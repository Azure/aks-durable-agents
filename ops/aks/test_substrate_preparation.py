"""Exercise the pre-paid executable graph and artifact, not a live publication/run."""
import datetime
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import lifecycle
import substrate_inputs as inputs
import test_lifecycle
import tool_audit

ROOT = Path(__file__).resolve().parents[2]
original_path = sys.path[:]
try:
    sys.path.append(str(ROOT / "ops/images"))
    from ops.images import substrate_images
finally:
    sys.path[:] = original_path


class PreparationTests(unittest.TestCase):
    def exercise(self, *, old_actor=False, mismatched_map=False, bad_signature=False, bad_integrity=False):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        source, goroot = root / "source", root / "go"
        source.mkdir()
        (source / ".git").mkdir()
        (source / ".git/config").write_text("public source repository")
        (goroot / "bin").mkdir(parents=True)
        (goroot / "bin/go").write_text("synthetic compiler")
        runner_tools = root / "aks-nightly-tools"
        runner_tools.mkdir()
        (runner_tools / "demo-client").write_text("synthetic client")
        helm = root / "helm"
        helm.write_text("synthetic helm")
        output, calls = root / "prepared", []
        pub = {"version": 1, "workflowCommit": "a" * 40, "substrateCommit": substrate_images.SUBSTRATE_COMMIT, "pauseCommit": substrate_images.PAUSE_COMMIT, "images": {role: substrate_images.PREFIX + role + "@sha256:" + "b" * 64 for role in substrate_images.ROLES}}
        mapping = substrate_images.installer_map(pub)
        def command(argv, **kwargs):
            argv = [str(v) for v in argv]
            calls.append(argv)
            raw = b""
            if argv[:2] == ["gh", "api"]:
                verify = argv[-1].endswith("456")
                value = {"id": 456 if verify else 123, "path": ".github/workflows/image-pins.yml" if verify else ".github/workflows/images.yml", "head_sha": "a" * 40, "event": "workflow_run" if verify else "push", "head_branch": "main", "status": "completed", "conclusion": "success", "repository": {"full_name": inputs.REPO}, "head_repository": {"full_name": inputs.REPO}}
                raw = json.dumps(value).encode()
            elif argv[:3] == ["gh", "run", "download"]:
                directory = Path(argv[-1])
                directory.mkdir()
                value = dict(mapping, version=99) if mismatched_map and directory.name == "verified" else mapping
                (directory / "substrate-images.json").write_text(json.dumps(value))
                (directory / "substrate-publication.json").write_text(json.dumps(pub))
            elif argv[:3] == ["docker", "buildx", "imagetools"]:
                raw = json.dumps({"SPDXID": "SPDXRef-DOCUMENT", "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "name": "image", "documentNamespace": "https://example.invalid/sbom", "creationInfo": {"creators": ["Tool: syft"], "created": "2026-10-22T00:00:00Z"}, "packages": [{"SPDXID": "SPDXRef-package", "name": "binary", "downloadLocation": "NOASSERTION"}]}).encode()
            elif argv[:2] == ["docker", "run"]:
                assert argv[argv.index("--entrypoint") + 1] == "/session-fixture" and argv[-2:] == ["actor-harness", "--check"] and "--network=none" in argv
                raw = json.dumps({"version": 0} if old_actor else {"version": 1, "mode": "actor-v2", "harness": "release-notes", "protocol": "harnesswire", "port": 80, "resumability": "STATELESS_REPLAY", "descriptor": "release-v2-real-model-" + "a" * 64, "readinessPort": 8081, "readinessPath": "/readyz"}).encode()
            elif argv[:2] == ["git", "-C"]:
                raw = (substrate_images.SUBSTRATE_COMMIT if argv[-1] == "HEAD" else "").encode()
            elif argv[:2] == ["go", "build"]:
                Path(argv[argv.index("-o") + 1]).write_text("synthetic native binary")
            elif argv[:3] == ["go", "version", "-m"]:
                raw = ("vcs.revision=" + substrate_images.SUBSTRATE_COMMIT + "\nvcs.modified=false").encode()
            elif argv[:3] == ["go", "env", "GOROOT"]:
                raw = str(goroot).encode()
            elif argv == ["which", "helm"]:
                raw = str(helm).encode()
            else:
                assert argv[:2] in (["docker", "pull"], ["cosign", "verify"]) or argv[0].endswith("govulncheck"), argv
            return SimpleNamespace(returncode=1 if bad_signature and argv[0] == "cosign" else 0, stdout=raw, stderr=b"private-diagnostic")
        env = test_lifecycle.environment()
        pins = lifecycle.rendered_images()
        env.update(RUNNER_TEMP=str(root), PRIVATE_SENTINEL="never-package-this", MODEL_PRICE_AS_OF=datetime.datetime.now(datetime.timezone.utc).date().isoformat())
        env["PUBLISHED_IMAGES"] = json.dumps({"version": 1, "sourceCommit": "d" * 40, "images": {role: dict(zip(("repository", "digest"), ref.split("@"))) for role, ref in pins.items()}})
        env["BACKUP_HELPER_RECEIPT"] = json.dumps(dict(test_lifecycle.RECEIPT, hostDigest=pins["host"].split("@")[1]))
        decisions = [{"tool": "kubectl", "status": "integrity-error", "findings": []}] if bad_integrity else []
        def execute():
            with patch.dict(os.environ, env, clear=True), patch.object(sys, "path", list(sys.path)), patch.object(subprocess, "run", side_effect=command), patch.object(tool_audit, "audit_tools", return_value=decisions):
                inputs.prepare(output, source, "123", "456")
        return output, calls, execute

    def test_verified_prepaid_graph_exports_only_source_tools_maps_and_closed_reports(self):
        output, calls, execute = self.exercise()
        execute()
        with tarfile.open(output / "prepared.tar.gz") as archive:
            roots = {member.name.split("/")[0] for member in archive.getmembers()}
            self.assertEqual(roots, {"source", "native-tools", "runner-tools", "go-toolchain", "tool-report", "verified"})
            self.assertIn("native-tools/kubectl-ate", archive.getnames())
            for member in archive.getmembers():
                if member.isfile():
                    stream = archive.extractfile(member)
                    assert stream is not None
                    self.assertNotIn(b"never-package-this", stream.read())
        check = next(i for i, c in enumerate(calls) if c[:2] == ["docker", "run"])
        build = next(i for i, c in enumerate(calls) if c[:2] == ["go", "build"])
        self.assertLess(check, build)
        self.assertEqual(sum(c[:2] == ["cosign", "verify"] for c in calls), 13)
        self.assertEqual(sum(c[:2] == ["docker", "pull"] for c in calls), 18)
        self.assertFalse(any(c[0] in ("az", "kubectl", "ate-setup", "kubectl-ate") for c in calls))

    def test_signature_failure_refuses_artifact_without_raw_diagnostics(self):
        output, calls, execute = self.exercise(bad_signature=True)
        with self.assertRaises(ValueError) as caught: execute()
        self.assertNotIn("private-diagnostic", str(caught.exception))
        self.assertFalse((output / "prepared.tar.gz").exists())
        self.assertFalse(any(c[:2] == ["go", "build"] for c in calls))

    def test_tool_integrity_failure_cannot_export_ready_inputs(self):
        output, _, execute = self.exercise(bad_integrity=True)
        with self.assertRaises(ValueError): execute()
        self.assertFalse((output / "prepared.tar.gz").exists())

    def test_old_application_digest_refuses_before_native_build_or_artifact(self):
        output, calls, execute = self.exercise(old_actor=True)
        with self.assertRaises(ValueError): execute()
        self.assertFalse((output / "prepared.tar.gz").exists())
        self.assertFalse(any(c[:2] == ["go", "build"] for c in calls))

    def test_verified_map_mismatch_refuses_before_any_image_pull(self):
        output, calls, execute = self.exercise(mismatched_map=True)
        with self.assertRaises(ValueError): execute()
        self.assertFalse((output / "prepared.tar.gz").exists())
        self.assertFalse(any(c[0] == "docker" for c in calls))


if __name__ == "__main__": unittest.main()
