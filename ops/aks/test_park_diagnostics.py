"""Park producers through real failure publication/collection; no cluster calls."""
import contextlib
import io
import json
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock, patch

import nightly as n
import substrate_session as s

SECRET = "PRIVATE-credential-model-output-pod-argv"
BOUNDARIES = (("host", "park-host-discovery"), ("forward", "park-rpc"),
              ("rpc", "park-rpc"), ("forward-exit", "park-rpc"),
              ("evidence-pod", "park-evidence-discovery"),
              ("evidence-exec", "park-evidence-exec"))


def inventory(calls):
    return {"realModelCalls": calls, "fakeModelCalls": 0, "realLedgerDigest": "a" * 64,
            "realAttempts": [], "publicationCount": 0, "receiptCount": 0, "artifacts": []}


class ParkDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.collector = n.local_module("park_collector", n.ROOT / "ops/demo/e2e.py")

    def scenario(self, variant, boundary=None, cleanup_failed=False):
        cls = s.SubstrateScenario if variant == "aks-substrate" else n.Scenario
        api: Any = object.__new__(cls)
        api.phase_name, api.operation = "preflight", "phase"
        api.phase_started = api.started = time.monotonic()
        api.phases, api.diagnostics, api.cleanup_status = {}, None, "not-run"
        api.state = self.root / str(len(list(self.root.iterdir()))) / SECRET
        api.state.mkdir(parents=True, mode=0o700)
        parked = {"session": SECRET}
        (api.state / "park.json").write_text(json.dumps(parked))
        api.prefix = ["kubectl", "--kubeconfig", "/" + SECRET, "--context", n.CONTEXT, "--namespace", n.NAMESPACE]
        api.client = Path("/" + SECRET + "/demo-client")
        api.labels = {role: {"app.kubernetes.io/name": "aks-durable-agents",
                            "app.kubernetes.io/instance": "kaimahi", "app.kubernetes.io/component": role}
                      for role in ("host", "harness")}
        api.owned, api.deployments = True, {"host": "host", "harness": "harness"}
        api.deadlines = SimpleNamespace(remaining=lambda cleanup=False: 120)
        api.preflight = api.install = api.enable = lambda: None
        api.network = lambda phase: []
        calls = []

        class External:
            parked = False

            def fail(self, point):
                if api.phase_name == "park" and boundary == point:
                    raise n.SafeFailure("command-failed", SECRET)

            @contextlib.contextmanager
            def forward(self, prefix, pod):
                calls.append("forward")
                self.fail("forward")
                yield 12345
                calls.append("forward-exit")
                self.fail("forward-exit")

            def run(self, args, **kwargs):
                if args[0] == str(api.client):
                    calls.append("rpc")
                    self.fail("rpc")
                    self.parked = True
                    return json.dumps(parked).encode()
                command = args[7:]
                if command[:1] == ["scale"]:
                    calls.append("cleanup-scale")
                    if cleanup_failed:
                        raise n.SafeFailure("command-failed", SECRET)
                    return b""
                if command[:1] == ["wait"]:
                    return b""
                if command[:2] == ["get", "pods"]:
                    point = "evidence-pod" if self.parked or api.phase_name != "park" else "host"
                    calls.append(point)
                    self.fail(point)
                    role = command[3].split("=")[-1]
                    return json.dumps({"items": [{"metadata": {"name": SECRET, "labels": api.labels[role]},
                        "status": {"conditions": [{"type": "Ready", "status": "True"}]}}]}).encode()
                if command[:1] == ["exec"]:
                    calls.append("evidence-exec")
                    self.fail("evidence-exec")
                    expected = "daemon" if variant == "aks-substrate" else "fixture-harness"
                    if command[2:4] != ["-c", expected]:
                        raise AssertionError("wrong evidence container")
                    return json.dumps(inventory(int(self.parked))).encode()
                raise AssertionError("unexpected external command")

        api.executor = External()
        if variant == "aks-substrate":
            # Native placement/checkpoint boundaries are not changed by these labels.
            # Keep their validation real, with fixed external response fixtures.
            api.first = {"actor": "session", "actorUID": "actor-uid"}
            api.read_placement = lambda: api.first
            api.checkpoint_rpc = lambda: {"version": 1, "actor": "session", "uri": "s3://held", "memory": False}
            api.actor = lambda: {"metadata": {"atespace": s.APP, "name": "session", "uid": "actor-uid"},
                "actorTemplate": {"atespace": s.APP, "name": "release-notes"},
                "status": {"state": "ACTOR_STATE_SUSPENDED", "snapshots": [{"generation": 1,
                    "fidelity": "SNAPSHOT_FIDELITY_VOLUMES", "durableSnapshot": {
                        "status": "SNAPSHOT_STORAGE_STATUS_COMPLETED", "object": {"snapshotUri": "s3://held"}}}]}}
            api.space_attempted = api.app_attempted = api.native_passed = api.native_cleanup_passed = False
            api.native_evidence = Mock()
        return api, calls

    def test_each_park_failure_survives_cleanup_and_real_collection_in_both_variants(self):
        for variant in ("aks", "aks-substrate"):
            for boundary, operation in BOUNDARIES:
                for cleanup_failed in (False, True):
                    with self.subTest(variant=variant, boundary=boundary, cleanup_failed=cleanup_failed):
                        api, calls = self.scenario(variant, boundary, cleanup_failed)
                        public = api.state.parent / "public"
                        public.mkdir(mode=0o700)
                        argv = ["--workdir", str(api.state), "--public-dir", str(public), "--client", str(api.client)]
                        if variant == "aks-substrate":
                            argv += ["--variant", "substrate-gvisor", "--substrate-source", "/source",
                                     "--substrate-image-map", "/map", "--substrate-tools", "/tools"]
                        original_load = n.local_module
                        def load(name, path, original_load=original_load):
                            return s if path.name == "substrate_session.py" else original_load(name, path)
                        stderr = io.StringIO()
                        with patch.object(n, "Scenario", return_value=api), \
                                patch.object(s, "SubstrateScenario", return_value=api), \
                                patch.object(n, "local_module", side_effect=load), contextlib.redirect_stderr(stderr):
                            self.assertEqual(n.main(argv), 1)
                        expected = {"version": 1, "phase": "park", "operation": operation,
                                    "reason": "command-failed", "cleanup": "failed" if cleanup_failed else "succeeded"}
                        self.assertEqual(json.loads((public / "diagnostics.json").read_text()), expected)
                        self.assertEqual(calls.count(boundary), 2 if boundary in ("evidence-pod", "evidence-exec") else 1)
                        self.assertEqual(calls.count("cleanup-scale"), 2)
                        (public / "command-0001.stderr").write_text(SECRET)
                        dest, summary = api.state.parent / "collected", api.state.parent / "summary.md"
                        self.assertEqual(self.collector.collect_aks(public, dest, summary, "failure",
                            "https://github.com/Azure/aks-durable-agents/actions/runs/12", "a" * 40, "scenario", variant), 0)
                        self.assertEqual(json.loads((dest / "diagnostics.json").read_text()), expected)
                        self.assertIn("Operation: " + operation, summary.read_text())
                        self.assertIn("Underlying cause: not determined", summary.read_text())
                        self.assertEqual({p.name for p in dest.iterdir()}, {"diagnostics.json", "status.json", "summary.md"})
                        for output in [stderr.getvalue(), summary.read_text(), *(p.read_text() for p in dest.iterdir())]:
                            self.assertNotIn(SECRET, output)

    def test_success_restores_previous_operation_and_other_phases_keep_their_context(self):
        for variant in ("aks", "aks-substrate"):
            for phase in ("park", "network-live", "restart"):
                with self.subTest(variant=variant, phase=phase):
                    api, _ = self.scenario(variant)
                    api.phase(phase)
                    api.operation = "profile-verify"
                    self.assertEqual(api.rpc("park"), {"session": SECRET})
                    self.assertEqual(api.operation, "profile-verify")
                    self.assertEqual(api.evidence(), inventory(1))
                    self.assertEqual(api.operation, "profile-verify")
                    if phase != "park":
                        # A failure outside park must not inherit any park label.
                        api.executor.run = Mock(side_effect=n.SafeFailure("command-failed", SECRET))
                        with self.assertRaises(n.SafeFailure):
                            api.evidence()
                        self.assertEqual(api.operation, "profile-verify")

    def test_other_rpcs_in_park_do_not_acquire_park_labels(self):
        for variant in ("aks", "aks-substrate"):
            with self.subTest(variant=variant):
                api, _ = self.scenario(variant)
                api.phase("park")
                api.executor.run = Mock(side_effect=n.SafeFailure("command-failed", SECRET))
                with self.assertRaises(n.SafeFailure):
                    api.rpc("check-parked")
                self.assertEqual(api.operation, "phase")

    def test_substrate_post_rpc_checks_do_not_inherit_the_shared_rpc_label(self):
        api, _ = self.scenario("aks-substrate")
        api.phase("park")
        api.read_placement = Mock(side_effect=n.SafeFailure("command-failed", SECRET))
        with self.assertRaises(n.SafeFailure):
            api.rpc("park")
        self.assertEqual(api.operation, "phase")


if __name__ == "__main__":
    unittest.main()
