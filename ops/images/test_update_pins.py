"""Catch forged manifests, unrelated values edits and untrusted publication runs."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("update_pins.py")
VALUES = '''# Operator inputs remain required.
image:
  host:
    repository: ""
    digest: ""
    # Profile-specific probe.
    includesHealthProbe: false
  harness:
    repository: ""
    digest: ""

workloads:
  enabled: false
'''


def manifest():
    return {"version": 1, "sourceCommit": "a" * 40, "images": {
        "host": {"repository": "ghcr.io/azure/aks-durable-agents/host", "digest": "sha256:" + "1" * 64},
        "harness": {"repository": "ghcr.io/azure/aks-durable-agents/session-fixture", "digest": "sha256:" + "2" * 64}}}


class PinTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.values = self.root / "values.yaml"
        self.values.write_text(VALUES)
        self.input = self.root / "images.json"
        self.input.write_text(json.dumps(manifest()))

    def run_update(self):
        return subprocess.run([sys.executable, str(SCRIPT), "update", "--manifest", str(self.input), "--values", str(self.values)], capture_output=True, text=True)

    def test_updates_only_five_fields_and_is_idempotent(self):
        result = self.run_update()
        self.assertEqual(result.returncode, 0, result.stderr)
        expected = VALUES.replace('repository: ""', 'repository: "ghcr.io/azure/aks-durable-agents/host"', 1)
        expected = expected.replace('repository: ""', 'repository: "ghcr.io/azure/aks-durable-agents/session-fixture"', 1)
        expected = expected.replace('digest: ""', 'digest: "sha256:' + "1" * 64 + '"', 1)
        expected = expected.replace('digest: ""', 'digest: "sha256:' + "2" * 64 + '"', 1)
        expected = expected.replace("includesHealthProbe: false", "includesHealthProbe: true")
        self.assertEqual(self.values.read_text(), expected)
        self.assertEqual(self.run_update().returncode, 0)
        self.assertEqual(self.values.read_text(), expected)

    def test_bad_manifest_never_changes_values(self):
        changes = [("version", True), ("sourceCommit", "main; evil"), ("extra", "no"), ("images", {})]
        for key, value in changes:
            with self.subTest(key=key):
                data = manifest()
                data[key] = value
                self.input.write_text(json.dumps(data))
                self.assertNotEqual(self.run_update().returncode, 0)
                self.assertEqual(self.values.read_text(), VALUES)
        for field, value in [("digest", "sha256:abc"), ("digest", "sha256:" + "F" * 64), ("repository", "ghcr.io/attacker/host"), ("extra", "no")]:
            with self.subTest(field=field, value=value):
                data = manifest()
                data["images"]["host"][field] = value
                self.input.write_text(json.dumps(data))
                self.assertNotEqual(self.run_update().returncode, 0)
                self.assertEqual(self.values.read_text(), VALUES)
        self.input.write_text('{"version":1,"version":1}')
        self.assertNotEqual(self.run_update().returncode, 0)
        self.assertEqual(self.values.read_text(), VALUES)

    def test_missing_or_ambiguous_fields_never_partially_write(self):
        for text in [VALUES.replace('    digest: ""\n', '', 1), VALUES + VALUES, VALUES.replace('    includesHealthProbe: false', '    includesHealthProbe: false\n    includesHealthProbe: true')]:
            with self.subTest(text=text):
                self.values.write_text(text)
                self.assertNotEqual(self.run_update().returncode, 0)
                self.assertEqual(self.values.read_text(), text)

    def test_symlink_target_refused(self):
        actual = self.root / "actual.yaml"
        self.values.rename(actual)
        self.values.symlink_to(actual)
        self.assertNotEqual(self.run_update().returncode, 0)
        self.assertEqual(actual.read_text(), VALUES)
        self.assertTrue(self.values.is_symlink())

    def test_only_trusted_successful_main_run_matches_manifest(self):
        run = {"repository": {"full_name": "Azure/aks-durable-agents"}, "path": ".github/workflows/images.yml", "event": "push", "head_branch": "main", "head_sha": "a" * 40, "conclusion": "success"}
        metadata = self.root / "run.json"
        def validate(data):
            metadata.write_text(json.dumps(data))
            return subprocess.run([sys.executable, str(SCRIPT), "validate-run", "--manifest", str(self.input), "--run", str(metadata)], capture_output=True, text=True)
        self.assertEqual(validate(run).returncode, 0)
        for key, value in [("event", "pull_request"), ("head_branch", "v1.0"), ("head_sha", "b" * 40), ("conclusion", "failure"), ("path", ".github/workflows/evil.yml"), ("repository", {"full_name": "attacker/fork"})]:
            with self.subTest(key=key):
                changed = copy.deepcopy(run)
                changed[key] = value
                self.assertNotEqual(validate(changed).returncode, 0)


if __name__ == "__main__":
    unittest.main()
