"""Contracts for read-only source builds and the separate Substrate pin handoff."""
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
ROLES = {"ateapi", "atecontroller", "atelet", "atenet", "ateom-gvisor", "objectstore-plugin",
         "podcertcontroller", "counter", "envoy-dataplane", "pause"}


class SubstrateWorkflowTests(unittest.TestCase):
    def test_source_builds_separate_pr_validation_from_main_publication(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/images.yml").read_text())
        jobs = workflow["jobs"]
        self.assertIn("substrate-validate", jobs)
        self.assertIn("substrate-publish", jobs)
        validate, publish = jobs["substrate-validate"], jobs["substrate-publish"]
        self.assertEqual(validate.get("permissions", workflow["permissions"]), {"contents": "read"})
        self.assertEqual(publish["permissions"], {"contents": "read", "packages": "write", "id-token": "write"})
        self.assertEqual(validate["if"], "github.event_name == 'pull_request'")
        self.assertEqual(publish["if"], "github.repository == 'Azure/aks-durable-agents' && github.event_name == 'push' && github.ref == 'refs/heads/main'")
        for job, enabled in ((validate, "false"), (publish, "true")):
            self.assertEqual(set(job["strategy"]["matrix"]["role"]), ROLES)
            self.assertFalse(job["strategy"]["fail-fast"])
            self.assertEqual(job["strategy"]["max-parallel"], 3)
            action = next(s for s in job["steps"] if s.get("uses") == "./.github/actions/substrate-image")
            self.assertEqual(action["with"]["publish"], enabled)
            self.assertEqual(action["with"].get("registry-token", ""), "${{ secrets.GITHUB_TOKEN }}" if enabled == "true" else "")
        collect = jobs["substrate-collect"]
        self.assertEqual(collect["needs"], "substrate-publish")
        self.assertEqual(collect.get("permissions", workflow["permissions"]), {"contents": "read"})
        self.assertIn("python3 -m pip install -r charts/aks-durable-agents/tests/requirements.txt", [s.get("run") for s in collect["steps"]])

    def test_source_action_reuses_host_attestation_tools_without_pr_signing(self):
        path = ROOT / ".github/actions/substrate-image/action.yml"
        self.assertTrue(path.is_file(), "source image action is missing")
        action = yaml.safe_load(path.read_text())
        host = yaml.safe_load((ROOT / ".github/workflows/images.yml").read_text())["jobs"]["publish"]["steps"]
        steps = action["runs"]["steps"]
        for prefix in ("docker/setup-buildx-action@", "docker/build-push-action@", "sigstore/cosign-installer@"):
            original = next(s for s in host if s.get("uses", "").startswith(prefix))
            actual = next(s for s in steps if s.get("uses", "").startswith(prefix))
            self.assertEqual(actual["uses"], original["uses"])
        build = next(s for s in steps if s.get("id") == "build")
        self.assertEqual(build["with"]["platforms"], "linux/amd64")
        self.assertEqual(build["with"]["network"], "${{ inputs.role == 'envoy-dataplane' && 'default' || 'none' }}")
        for step in steps:
            if step.get("uses", "").startswith(("docker/login-action@", "sigstore/cosign-installer@")) or step.get("id") == "record":
                self.assertEqual(step["if"], "inputs.publish == 'true'")
            if step.get("uses", "").startswith("actions/checkout@"):
                self.assertFalse(step["with"]["persist-credentials"])
        self.assertEqual(action["inputs"]["registry-token"]["default"], "")
        self.assertIn("python3 -m pip install -r charts/aks-durable-agents/tests/requirements.txt", [s.get("run") for s in steps])

    def test_verified_substrate_export_stays_separate_and_does_not_write_repository(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/image-pins.yml").read_text())
        self.assertIn("substrate-pins", workflow["jobs"])
        job = workflow["jobs"]["substrate-pins"]
        self.assertEqual(job["permissions"], {"contents": "read", "actions": "read"})
        self.assertIn("python3 -m pip install -r charts/aks-durable-agents/tests/requirements.txt", [s.get("run") for s in job["steps"]])
        export = next(s for s in job["steps"] if s.get("name") == "Export verified Substrate map")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            publication = root / "substrate-publication"
            publication.mkdir()
            data = {"sourceCommit": "e" * 40, "images": {"probe": "registry.example/probe@sha256:" + "a" * 64}}
            text = json.dumps(data) + "\n"
            (publication / "substrate-images.json").write_text(text)
            (publication / "substrate-publication.json").write_text('{"receipt":true}\n')
            (root / "verified-substrate-images").mkdir()
            (root / "substrate-refs.txt").write_text("counter\tregistry.example/counter@sha256:" + "b" * 64 + "\n")
            commands = root / "bin"
            commands.mkdir()
            for name in ("git", "gh"):
                path = commands / name
                path.write_text("#!/bin/sh\necho unexpected repository write >&2\nexit 99\n")
                path.chmod(0o700)
            summary = root / "summary.md"
            environment = dict(os.environ, RUNNER_TEMP=str(root), SOURCE="c" * 40, PUBLISH_RUN_ID="1234",
                               GITHUB_STEP_SUMMARY=str(summary), PATH=str(commands) + os.pathsep + os.environ["PATH"])
            result = subprocess.run(["bash", "-euo", "pipefail", "-c", export["run"]], env=environment,
                                    cwd=root, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            output = root / "verified-substrate-images"
            self.assertEqual((output / "substrate-images.json").read_text(), text)
            self.assertTrue((output / "substrate-publication.json").is_file())
            self.assertFalse((output / "images.json").exists())
            self.assertIn("1234", summary.read_text())
            self.assertIn("--image-map", summary.read_text())


if __name__ == "__main__":
    unittest.main()
