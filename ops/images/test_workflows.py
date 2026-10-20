"""Exercise the read-only verified-pin handoff and its permission boundary."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml

from test_update_pins import manifest

WORKFLOWS = Path(__file__).resolve().parents[2] / ".github/workflows"


class WorkflowTests(unittest.TestCase):
    def test_publication_and_handoff_use_only_the_required_permissions(self):
        publish = yaml.safe_load((WORKFLOWS / "images.yml").read_text())
        handoff = yaml.safe_load((WORKFLOWS / "image-pins.yml").read_text())
        self.assertEqual(publish["permissions"], {"contents": "read"})
        self.assertEqual(publish["jobs"]["publish"]["permissions"], {
            "contents": "read", "packages": "write", "id-token": "write"})
        self.assertEqual(handoff["permissions"], {"contents": "read"})
        self.assertEqual(handoff["jobs"]["pins"]["permissions"], {
            "contents": "read", "actions": "read"})

    def test_export_writes_both_verified_digests_without_repository_commands(self):
        handoff = yaml.safe_load((WORKFLOWS / "image-pins.yml").read_text())
        steps = handoff["jobs"]["pins"]["steps"]
        export = next((step for step in steps if step.get("name") == "Export verified digests for a person-created PR"), None)
        self.assertIsNotNone(export, "missing read-only digest export")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "publication").mkdir()
            (root / "verified-image-pins").mkdir()
            data = manifest()
            original = json.dumps(data) + "\n"
            (root / "publication/images.json").write_text(original)
            refs = [image["repository"] + "@" + image["digest"] for image in data["images"].values()]
            (root / "image-refs.txt").write_text("\n".join(refs) + "\n")
            commands = root / "bin"
            commands.mkdir()
            # Avoid ambient GitHub credentials if a repository command regresses
            # into this step. Assertions exercise the real file/summary output.
            for name in ["git", "gh"]:
                command = commands / name
                command.write_text("#!/bin/sh\necho 'unexpected repository command' >&2\nexit 99\n")
                command.chmod(0o700)
            summary = root / "summary.md"
            environment = dict(os.environ, RUNNER_TEMP=str(root), GITHUB_STEP_SUMMARY=str(summary), SOURCE="a" * 40, PUBLISH_RUN_ID="1234", PATH=str(commands) + os.pathsep + os.environ["PATH"])
            result = subprocess.run(["bash", "-euo", "pipefail", "-c", export["run"]], env=environment, cwd=root, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((root / "verified-image-pins/images.json").read_text(), original)
            self.assertEqual((root / "publication/images.json").read_text(), original)
            for ref in refs:
                self.assertIn(ref, summary.read_text())
            self.assertIn("1234", summary.read_text())
            self.assertEqual(sorted(p.name for p in (root / "verified-image-pins").iterdir()), ["images.json"])


if __name__ == "__main__":
    unittest.main()
