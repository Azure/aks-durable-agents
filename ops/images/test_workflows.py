"""Exercise the read-only verified-pin handoff and its permission boundary."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import yaml

from test_update_pins import manifest

WORKFLOWS = Path(__file__).resolve().parents[2] / ".github/workflows"


class WorkflowTests(unittest.TestCase):
    def test_packaged_fixture_smoke_checks_actor_entrypoint_and_port80(self):
        smoke = (Path(__file__).resolve().parents[2] / "ops/images/smoke.sh").read_text()
        self.assertIn("actor-harness --check", smoke)
        self.assertIn("/session-fixture actor-harness", smoke)
        self.assertIn("127.0.0.1:80 --expect allowed", smoke)

    def test_publication_and_handoff_use_only_the_required_permissions(self):
        publish = yaml.safe_load((WORKFLOWS / "images.yml").read_text())
        handoff = yaml.safe_load((WORKFLOWS / "image-pins.yml").read_text())
        self.assertEqual(publish["permissions"], {"contents": "read"})
        self.assertEqual(publish["jobs"]["publish"]["permissions"], {
            "contents": "read", "packages": "write", "id-token": "write"})
        self.assertEqual(handoff["permissions"], {"contents": "read"})
        self.assertEqual(handoff["jobs"]["pins"]["permissions"], {
            "contents": "read", "actions": "read"})

    def test_helper_publication_reuses_pinned_build_and_attestation_contract(self):
        workflow = yaml.safe_load((WORKFLOWS / "images.yml").read_text())
        jobs = workflow["jobs"]
        self.assertNotIn("permissions", jobs["validate"])
        # PR validation must exercise the helper through the same local smoke.
        self.assertIn("bash ops/images/smoke.sh", [s.get("run") for s in jobs["validate"]["steps"]])
        steps = jobs["publish"]["steps"]
        host = next(s for s in steps if s.get("id") == "host")
        helper = next((s for s in steps if s.get("id") == "backup-helper"), None)
        self.assertIsNotNone(helper, "backup helper publication is missing")
        self.assertEqual(helper["uses"], host["uses"])
        self.assertEqual(helper["with"]["context"], "ops/backup")
        self.assertEqual(helper["with"]["file"], "ops/backup/Dockerfile")
        self.assertIn("HOST_IMAGE=ghcr.io/azure/aks-durable-agents/host@${{ steps.host.outputs.digest }}",
                      helper["with"]["build-args"])
        for field in ["platforms", "network", "outputs", "provenance", "attests"]:
            self.assertEqual(helper["with"][field], host["with"][field])
        smoke = next(s for s in steps if s.get("name") == "Smoke-test the pushed image contents before signing")
        self.assertEqual(smoke["env"]["HELPER_DIGEST"], "${{ steps.backup-helper.outputs.digest }}")

    def test_signing_records_separate_helper_receipt_and_keeps_two_image_manifest(self):
        workflow = yaml.safe_load((WORKFLOWS / "images.yml").read_text())
        sign = next(s for s in workflow["jobs"]["publish"]["steps"] if s.get("name") == "Sign digests and record SBOMs")
        self.assertEqual(sign["env"].get("HELPER_DIGEST"), "${{ steps.backup-helper.outputs.digest }}")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scripts = root / "ops/images"
            scripts.mkdir(parents=True)
            for name in ["update_pins.py", "backup_helper.py"]:
                shutil.copyfile(WORKFLOWS.parents[1] / "ops/images" / name, scripts / name)
            commands = root / "bin"
            commands.mkdir()
            cosign = commands / "cosign"
            cosign.write_text(f"#!{sys.executable}\nimport json,os,sys\nwith open(os.environ['COMMAND_LOG'], 'a') as f: f.write(json.dumps(sys.argv[1:]) + '\\n')\nprint('{{}}')\n")
            docker = commands / "docker"
            docker.write_text("#!/bin/sh\nprintf '%s\\n' '{\"SPDXID\":\"SPDXRef-DOCUMENT\",\"packages\":[{\"name\":\"test\"}]}'\n")
            for command in [cosign, docker]:
                command.chmod(0o700)
            log = root / "commands.jsonl"
            environment = dict(os.environ, PATH=str(commands) + os.pathsep + os.environ["PATH"],
                               COMMAND_LOG=str(log), GITHUB_SHA="a" * 40,
                               GITHUB_REPOSITORY="Azure/aks-durable-agents", GITHUB_REF="refs/heads/main",
                               GITHUB_STEP_SUMMARY=str(root / "summary.md"), HOST_DIGEST="sha256:" + "b" * 64,
                               FIXTURE_DIGEST="sha256:" + "c" * 64, HELPER_DIGEST="sha256:" + "d" * 64)
            result = subprocess.run(["bash", "-euo", "pipefail", "-c", sign["run"]], env=environment,
                                    cwd=root, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            publication = root / ".build/publication"
            data = json.loads((publication / "images.json").read_text())
            self.assertEqual(data, {"version": 1, "sourceCommit": "a" * 40, "images": {
                "host": {"repository": "ghcr.io/azure/aks-durable-agents/host", "digest": "sha256:" + "b" * 64},
                "harness": {"repository": "ghcr.io/azure/aks-durable-agents/session-fixture", "digest": "sha256:" + "c" * 64}}})
            helper_ref = "ghcr.io/azure/aks-durable-agents/backup-helper@sha256:" + "d" * 64
            self.assertEqual(json.loads((publication / "backup-helper.json").read_text()), {
                "version": 1, "sourceCommit": "a" * 40, "hostDigest": "sha256:" + "b" * 64, "image": helper_ref})
            calls = [json.loads(line) for line in log.read_text().splitlines()]
            refs = [image["repository"] + "@" + image["digest"] for image in data["images"].values()] + [helper_ref]
            for ref in refs:
                self.assertIn(["sign", "--yes", ref], calls)
                verification = next(call for call in calls if call[0] == "verify" and call[-1] == ref)
                self.assertIn("https://github.com/Azure/aks-durable-agents/.github/workflows/images.yml@refs/heads/main", verification)
                self.assertIn(ref, (root / "summary.md").read_text())
            self.assertTrue((publication / "backup-helper-sbom.json").is_file())
            self.assertTrue((publication / "backup-helper-signature.json").is_file())

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
            # A separate helper receipt must never be exported as chart pins.
            (root / "publication/backup-helper.json").write_text('{"separate": true}\n')
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
