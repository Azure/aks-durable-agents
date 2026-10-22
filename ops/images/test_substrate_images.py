"""Offline publication contracts; only executable boundaries are substituted."""
import contextlib
import copy
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import substrate_images as images

REV = "a" * 40
SOURCE = "e8d40c33f96f4b7a4984bfea7334a36ab5b45b7b"
PAUSE = "f54c212e3a2f75d674b717a9b29052b20b60aefc"
DIGEST = "sha256:" + "b" * 64
PREFIX = "ghcr.io/azure/aks-durable-agents/substrate-"
ROLES = ("ateapi", "atecontroller", "atelet", "atenet", "ateom-gvisor", "objectstore-plugin",
         "podcertcontroller", "counter", "envoy-dataplane", "pause")
ROOT = Path(__file__).resolve().parents[2]


def spdx(packages=True):
    doc = {"SPDXID": "SPDXRef-DOCUMENT", "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0",
           "name": "image", "documentNamespace": "https://example.org/sbom/unique-id",
           "creationInfo": {"creators": ["Tool: syft-1.0"], "created": "2026-10-20T00:00:00Z"}}
    if packages:
        doc["packages"] = [{"SPDXID": "SPDXRef-package", "name": "binary", "downloadLocation": "NOASSERTION"}]
    return doc


def receipt(role):
    return {"version": 1, "workflowCommit": REV, "substrateCommit": SOURCE, "pauseCommit": PAUSE,
            "role": role, "image": PREFIX + role + "@" + DIGEST}


class Executables:
    """Record argv and model subprocess results/files, never security helpers."""
    def __init__(self, *, role="ateapi", fail=None, sbom=None, dirty=False, metadata=None):
        self.calls = []
        self.role, self.fail, self.dirty = role, fail, dirty
        self.sbom = spdx() if sbom is None else sbom
        self.metadata = metadata

    def __call__(self, argv, *, timeout, cwd=None, env=None):
        self.calls.append((argv, timeout, cwd, env))
        if self.fail and self.fail(argv):
            raise subprocess.CalledProcessError(1, argv, stderr="failure")
        if argv[0] == "git":
            if argv[-1] == "HEAD" and "rev-parse" in argv:
                return PAUSE if self.role == "pause" else SOURCE
            if "status" in argv:
                return " M tracked.go" if self.dirty else ""
            return "1792012331"
        if argv[:2] == ["go", "build"]:
            Path(argv[argv.index("-o") + 1]).write_bytes(b"synthetic not a Go binary")
        if argv[:2] == ["docker", "cp"]:
            Path(argv[-1]).write_bytes(b"synthetic packaged bytes")
        if argv[:3] == ["go", "version", "-m"]:
            package = "demos/counter" if self.role == "counter" else "cmd/" + self.role
            return self.metadata if self.metadata is not None else (
                "binary: go1.27.3\n\tpath\tgithub.com/agent-substrate/substrate/" + package +
                "\n\tbuild\tvcs.revision=" + SOURCE + "\n\tbuild\tvcs.modified=false\n")
        if argv[:2] == ["docker", "inspect"]:
            return "0"
        if argv[:3] == ["docker", "start", "--attach"]:
            return "pause.c v3.10.2-" + PAUSE if self.role == "pause" else "usage/version"
        if argv[:3] == ["docker", "buildx", "imagetools"]:
            return json.dumps({"linux/amd64": self.sbom})
        return "[]"


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write(self, path, data):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data))
        return path

    def collect(self):
        receipts = self.root / "receipts"
        for role in ROLES:
            self.write(receipts / (role + ".receipt.json"), receipt(role))
        output = self.root / "aggregate"
        images.collect(receipts, REV, output)
        return receipts, output

    def canonical(self):
        return {"GITHUB_EVENT_NAME": "push", "GITHUB_REPOSITORY": "Azure/aks-durable-agents",
                "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": REV, "SECRET_TOKEN": "never-an-argument"}

    def source(self):
        source = self.root / "source"
        source.mkdir()
        (source / ".ko.yaml").write_text(
            "defaultBaseImage: gcr.io/distroless/static-debian13:latest@sha256:f2ea2709ac8db56323cbd7d014277f32cb572d9ea124b0076f7aafe5980678fe\n"
            "baseImageOverrides:\n  github.com/agent-substrate/substrate/cmd/atelet: gcr.io/distroless/base-debian13:latest@sha256:389cad21f73e4c37b94ffe5b13736d5a92bd5bd3c6c6b38c2be1c881e14ba2bd\n")
        kodata = source / "cmd/ateom-gvisor/kodata"
        kodata.mkdir(parents=True)
        (kodata / "internal_flags.json").write_text('{"global":["--debug"]}')
        return source

    def test_collect_exports_complete_installer_compatible_map_and_source_identity(self):
        _, output = self.collect()
        publication = json.loads((output / "substrate-publication.json").read_text())
        mapping = json.loads((output / "substrate-images.json").read_text())
        self.assertEqual(set(publication), {"version", "workflowCommit", "substrateCommit", "pauseCommit", "images"})
        self.assertEqual(publication["workflowCommit"], REV)
        self.assertEqual(set(publication["images"]), set(ROLES))
        self.assertEqual(mapping["sourceCommit"], SOURCE)
        self.assertEqual(len(mapping["images"]), 15)
        self.assertEqual(mapping["images"]["ko://github.com/agent-substrate/substrate/demos/counter"], PREFIX + "counter@" + DIGEST)
        self.assertEqual(mapping["images"]["${ENVOY_DATAPLANE_IMAGE}"], PREFIX + "envoy-dataplane@" + DIGEST)
        self.assertEqual(mapping["images"]["probe"], "docker.io/library/python@sha256:79e7a9b9ff1cbceff819f856fb374477792a5967759d94df266de7b7b4120e6f")
        saved_path = sys.path[:]
        sys.path[:0] = [str(ROOT), str(ROOT / "ops/aks")]
        try:
            from ops.aks import substrate
            self.assertEqual(substrate.image_map(mapping), mapping["images"])
        finally:
            sys.path[:] = saved_path
        self.assertEqual(len(list(images.refs(publication, mapping))), 15)
        self.assertEqual(sum(role.startswith("upstream-") for role, _ in images.refs(publication, mapping)), 5)

    def test_collect_refuses_missing_unknown_duplicate_mixed_and_foreign_receipts(self):
        cases = [("workflowCommit", "c" * 40), ("substrateCommit", REV), ("pauseCommit", REV),
                 ("role", "counter"), ("image", PREFIX + "counter@" + DIGEST),
                 ("image", "evil.example/ateapi@" + DIGEST), ("image", PREFIX + "ateapi:latest"),
                 ("image", PREFIX + "ateapi@sha256:bad"), ("version", True), ("extra", "bad")]
        for key, value in cases:
            with self.subTest(key=key, value=value):
                receipts, _ = self.collect()
                bad = receipt("ateapi")
                bad[key] = value
                self.write(receipts / "ateapi.receipt.json", bad)
                destination = self.root / "refused"
                with self.assertRaises(ValueError):
                    images.collect(receipts, REV, destination)
                self.assertFalse(destination.exists())
        receipts, _ = self.collect()
        (receipts / "ateapi.receipt.json").unlink()
        with self.assertRaises(ValueError):
            images.collect(receipts, REV, self.root / "missing")
        self.write(receipts / "unknown.receipt.json", receipt("ateapi"))
        with self.assertRaises(ValueError):
            images.collect(receipts, REV, self.root / "unknown")
        (receipts / "unknown.receipt.json").rename(receipts / "ateapi.receipt.json")
        path = receipts / "ateapi.receipt.json"
        path.write_text(path.read_text().replace('"version": 1', '"version": 1, "version": 1'))
        with self.assertRaises(ValueError):
            images.collect(receipts, REV, self.root / "duplicate")

    def test_map_and_successful_run_use_workflow_not_upstream_sha(self):
        _, output = self.collect()
        pub = images.load_json(output / "substrate-publication.json")
        mapping = images.load_json(output / "substrate-images.json")
        run = {"path": ".github/workflows/images.yml", "event": "push", "head_branch": "main",
               "head_sha": REV, "conclusion": "success", "repository": {"full_name": "Azure/aks-durable-agents"}}
        images.validate_run(pub, mapping, run)
        for field, value in [("head_sha", SOURCE), ("event", "pull_request"), ("conclusion", "failure")]:
            bad = dict(run, **{field: value})
            with self.assertRaises(ValueError):
                images.validate_run(pub, mapping, bad)
        badmap = copy.deepcopy(mapping)
        badmap["images"]["probe"] = PREFIX + "pause@" + DIGEST
        with self.assertRaises(ValueError):
            list(images.refs(pub, badmap))
        runfile = self.write(self.root / "run.json", run)
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            images.main(["validate-run", "--publication", str(output / "substrate-publication.json"),
                         "--map", str(output / "substrate-images.json"), "--run", str(runfile)])
        self.assertEqual(stdout.getvalue(), REV + "\n")

    def test_sbom_empty_inventory_exception_requires_valid_pause_document(self):
        for role in ROLES:
            for inventory in ([], None):
                doc = spdx(False)
                if inventory == []:
                    doc["packages"] = []
                path = self.write(self.root / "sbom.json", doc)
                if role == "pause":
                    images.verify_sbom(role, doc)
                    images.main(["verify-sbom", "--role", role, "--input", str(path)])
                else:
                    with self.assertRaises(ValueError):
                        images.verify_sbom(role, doc)
                    with self.assertRaises(SystemExit) as result, contextlib.redirect_stderr(io.StringIO()):
                        images.main(["verify-sbom", "--role", role, "--input", str(path)])
                    self.assertEqual(result.exception.code, 1)
        for key in spdx(False):
            doc = spdx(False)
            del doc[key]
            with self.assertRaises(ValueError):
                images.verify_sbom("pause", doc)
        for inventory in ({}, [None], [{}], "not-packages"):
            with self.assertRaises(ValueError):
                images.verify_sbom("pause", dict(spdx(False), packages=inventory))

    def test_public_verifier_accepts_the_same_single_platform_sbom_as_record(self):
        doc = spdx()
        attached = {"linux/amd64": doc}
        self.assertEqual(images.verify_sbom("ateapi", attached), doc)
        path = self.write(self.root / "attached-sbom.json", attached)
        images.main(["verify-sbom", "--role", "ateapi", "--input", str(path)])
        for invalid in ({"linux/arm64": doc}, {"linux/amd64": doc, "linux/arm64": doc}):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                images.verify_sbom("ateapi", invalid)

    def test_prepare_preserves_kodata_literal_entrypoint_and_pinned_build_flags(self):
        source = self.source()
        for role in ("ateom-gvisor", "atelet", "counter"):
            run = Executables(role=role)
            outputs = images.prepare(role, source, self.root / "unused", self.root / "contexts", REV, run=run)
            context = Path(outputs["context"])
            dockerfile = Path(outputs["file"]).read_text()
            self.assertEqual(outputs["epoch"], "1792012331")
            self.assertEqual(outputs["image"], PREFIX + role + ":sha-" + REV)
            self.assertIn('ENTRYPOINT ["/ko-app/' + role + '"]', dockerfile)
            self.assertIn("USER 0", dockerfile)
            self.assertIn("ENV KO_DATA_PATH=/var/run/ko", dockerfile)
            self.assertIn("base-debian13" if role == "atelet" else "static-debian13", dockerfile)
            argv, timeout, cwd, env = next(call for call in run.calls if call[0][:2] == ["go", "build"])
            self.assertEqual(cwd, source.resolve())
            self.assertTrue({"-mod=vendor", "-trimpath", "-buildvcs=true"}.issubset(argv))
            self.assertIn("internal/version.Commit=" + SOURCE, argv[argv.index("-ldflags") + 1])
            self.assertNotIn("-s -w", " ".join(argv))
            self.assertEqual({k: env[k] for k in ("CGO_ENABLED", "GOOS", "GOARCH", "GOTOOLCHAIN")},
                             {"CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "amd64", "GOTOOLCHAIN": "go1.27.3"})
            self.assertGreater(timeout, 0)
            if role == "ateom-gvisor":
                self.assertEqual((context / "kodata/internal_flags.json").read_text(), '{"global":["--debug"]}')
            with self.assertRaises(FileExistsError):
                images.prepare(role, source, self.root / "unused", self.root / "contexts", REV, run=run)
        with self.assertRaises(ValueError):
            images.prepare("ateapi", source, source, self.root / "dirty", REV, run=Executables(dirty=True))
        self.assertFalse((self.root / "dirty").exists())

    def test_pause_and_envoy_keep_source_build_inputs_and_only_applicable_checkout(self):
        pause = self.root / "pause-source/build/pause"
        pause.mkdir(parents=True)
        (pause / "linux").mkdir()
        (pause / "linux/pause.c").write_text("/* exact source */")
        (pause / "Makefile").write_text("TAG ?= 3.10.2\n")
        run = Executables(role="pause")
        outputs = images.prepare("pause", self.root / "nonexistent", pause.parents[1], self.root / "contexts", REV, run=run)
        text = Path(outputs["file"]).read_text()
        self.assertIn("gcc:14.3.0@sha256:ccf38976f2c7d682841165bf5da334c6e48c89550f7ebf2ac8b8c06f307f4f79", text)
        self.assertIn("gcc -Os -Wall -Werror -static -s -DVERSION=v3.10.2-" + PAUSE, text)
        self.assertIn("FROM scratch", text)
        self.assertIn("USER 65535:65535\n", text)
        self.assertEqual((Path(outputs["context"]) / "pause.c").read_text(), "/* exact source */")
        source = self.source()
        envoy = source / "cmd/dataplane/envoy"
        envoy.mkdir(parents=True)
        (envoy / "Dockerfile").write_text("FROM pinned\nCOPY dynamic-modules .\n")
        (envoy / "dynamic-modules").mkdir()
        (envoy / "dynamic-modules/Cargo.lock").write_text("lock")
        outputs = images.prepare("envoy-dataplane", source, self.root / "unused", self.root / "contexts", REV, run=Executables())
        self.assertEqual(Path(outputs["file"]).read_bytes(), (envoy / "Dockerfile").read_bytes())
        self.assertEqual((Path(outputs["context"]) / "dynamic-modules/Cargo.lock").read_text(), "lock")

    def test_smoke_closed_refs_scan_packaged_binary_and_cleanup_on_failure(self):
        for role in ROLES:
            run = Executables(role=role)
            images.smoke(role, PREFIX + role + "@" + DIGEST, run=run)
            commands = [c[0] for c in run.calls]
            self.assertEqual(commands[0], ["docker", "pull", PREFIX + role + "@" + DIGEST])
            create = next(c for c in commands if c[:2] == ["docker", "create"])
            self.assertIn("none", create)
            self.assertNotIn("--entrypoint", create)
            self.assertEqual(create[-2:] if role == "objectstore-plugin" else create[-1:],
                             ["node", "--help"] if role == "objectstore-plugin" else ["-v" if role == "pause" else "--version" if role == "envoy-dataplane" else "--help"])
            name = create[create.index("--name") + 1]
            self.assertEqual(commands[-1], ["docker", "rm", "-f", name])
            if role in ROLES[:8]:
                scan = next(c for c in commands if c[0] == "govulncheck")
                self.assertEqual(scan[1], "-mode=binary")
                self.assertTrue(any(c[:2] == ["docker", "cp"] and ":/ko-app/" + role in c[2] for c in commands))
        for ref in ("evil.example/image@" + DIGEST, PREFIX + "counter@" + DIGEST, PREFIX + "ateapi:latest", "--help"):
            run = Executables()
            with self.assertRaises(ValueError):
                images.smoke("ateapi", ref, run=run)
            self.assertEqual(run.calls, [])
        for failure in (lambda a: a[0] == "govulncheck", lambda a: a[:2] == ["docker", "cp"]):
            run = Executables(fail=failure)
            with self.assertRaises(subprocess.CalledProcessError):
                images.smoke("ateapi", PREFIX + "ateapi:sha-" + REV, run=run)
            self.assertEqual(run.calls[-1][0][:3], ["docker", "rm", "-f"])
            self.assertFalse(any(c[0][:2] == ["docker", "pull"] for c in run.calls))
        run = Executables(metadata="build vcs.revision=" + SOURCE + "\nbuild vcs.modified=true")
        with self.assertRaises(ValueError):
            images.smoke("ateapi", PREFIX + "ateapi@" + DIGEST, run=run)
        self.assertEqual(run.calls[-1][0][:3], ["docker", "rm", "-f"])

    def test_record_canonical_boundary_and_failures_never_emit_receipt(self):
        for field, bad in [("GITHUB_EVENT_NAME", "pull_request"), ("GITHUB_REPOSITORY", "fork/repo"),
                           ("GITHUB_REF", "refs/tags/v1"), ("GITHUB_SHA", SOURCE)]:
            run = Executables()
            with self.assertRaises(ValueError):
                images.record("ateapi", DIGEST, REV, self.root / "denied", env=dict(self.canonical(), **{field: bad}), run=run)
            self.assertEqual(run.calls, [])
            self.assertFalse((self.root / "denied").exists())
        for stage in ("pull", "start", "govulncheck", "sign", "verify", "imagetools"):
            run = Executables(fail=lambda a, stage=stage: stage in a)
            output = self.root / stage
            with self.assertRaises(subprocess.CalledProcessError):
                images.record("ateapi", DIGEST, REV, output, env=self.canonical(), run=run)
            self.assertFalse((output / "ateapi.receipt.json").exists())
            if stage in ("pull", "start", "govulncheck"):
                self.assertFalse(any(call[0][0] == "cosign" for call in run.calls))
        for role in ("ateapi", "pause"):
            output = self.root / (role + "-record")
            run = Executables(role=role, sbom=spdx(False))
            if role != "pause":
                with self.assertRaises(ValueError):
                    images.record(role, DIGEST, REV, output, env=self.canonical(), run=run)
                self.assertFalse(output.exists())
            else:
                images.record(role, DIGEST, REV, output, env=self.canonical(), run=run)
                self.assertEqual(images.load_json(output / "pause.receipt.json"), receipt("pause"))
                self.assertEqual(images.load_json(output / "pause-sbom.json"), spdx(False))
                verification = next(c[0] for c in run.calls if c[0][:2] == ["cosign", "verify"])
                self.assertIn("https://github.com/Azure/aks-durable-agents/.github/workflows/images.yml@refs/heads/main", verification)
                self.assertIn("https://token.actions.githubusercontent.com", verification)
                for argv, timeout, _, _ in run.calls:
                    self.assertNotIn("never-an-argument", " ".join(argv))
                    self.assertTrue(0 < timeout <= 900)

    def test_nonzero_container_exit_refuses_signing_and_still_cleans_exact_container(self):
        external = Executables()

        def run(argv, **kwargs):
            if argv[:2] == ["docker", "inspect"]:
                external.calls.append((argv, kwargs["timeout"], None, None))
                return "2"
            return external(argv, **kwargs)

        with self.assertRaises(ValueError):
            images.record("ateapi", DIGEST, REV, self.root / "nonzero", env=self.canonical(), run=run)
        self.assertFalse((self.root / "nonzero").exists())
        self.assertEqual(external.calls[-1][0][:3], ["docker", "rm", "-f"])
        self.assertFalse(any(c[0][0] == "cosign" for c in external.calls))

    def test_source_provenance_and_output_path_boundaries_fail_before_context_effects(self):
        source = self.source()
        external = Executables()

        def wrong_head(argv, **kwargs):
            return REV if "rev-parse" in argv else external(argv, **kwargs)

        with self.assertRaises(ValueError):
            images.prepare("ateapi", source, source, self.root / "wrong-head", REV, run=wrong_head)
        self.assertFalse((self.root / "wrong-head").exists())
        (source / ".ko.yaml").write_text("defaultBaseImage: evil.example/mutable\n")
        with self.assertRaises(ValueError):
            images.prepare("ateapi", source, source, self.root / "bad-base", REV, run=external)
        self.assertFalse((self.root / "bad-base").exists())
        for role, revision in (("../../outside", REV), ("ateapi", "bad")):
            with self.assertRaises(ValueError):
                images.prepare(role, source, source, self.root / "bad", revision, run=external)
        self.assertFalse((self.root / "bad").exists())

    def test_json_outputs_replace_instead_of_following_existing_symlinks(self):
        protected = self.root / "protected.json"
        protected.write_text("unchanged")
        output = self.root / "receipt.json"
        output.symlink_to(protected)
        images.write_json(output, {"validated": True})
        self.assertEqual(protected.read_text(), "unchanged")
        self.assertFalse(output.is_symlink())
        self.assertEqual(images.load_json(output), {"validated": True})

    def test_prepare_cli_emits_exact_github_output_contract(self):
        source = self.source()
        github_output = self.root / "github-output"
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            images.main(["prepare", "--role", "ateapi", "--source", str(source),
                         "--pause-source", str(self.root / "unused"), "--output", str(self.root / "contexts"),
                         "--revision", REV, "--github-output", str(github_output)], run=Executables())
        self.assertEqual(stdout.getvalue(), "")
        values = dict(line.split("=", 1) for line in github_output.read_text().splitlines())
        self.assertEqual(set(values), {"context", "file", "image", "epoch"})
        self.assertEqual(values["image"], PREFIX + "ateapi:sha-" + REV)
        self.assertTrue(Path(values["file"]).is_file())

    def test_executable_boundary_enforces_timeout_and_does_not_log_token_environment(self):
        result = images.command([sys.executable, "-c", "import os; print(os.environ['TOKEN'])"],
                                env={"TOKEN": "synthetic-token"}, timeout=5)
        self.assertEqual(result.strip(), "synthetic-token")
        with self.assertRaises(subprocess.TimeoutExpired):
            images.command([sys.executable, "-c", "import time; time.sleep(2)"], timeout=0.01)


if __name__ == "__main__":
    unittest.main()
