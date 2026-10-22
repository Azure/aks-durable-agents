"""Actor variant boundaries. All external execution is synthetic here."""
import contextlib
import copy
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock, patch

import substrate_session as s

P = {"atespace": s.APP, "actor": "session-test", "actorUID": "actor-uid", "templateAtespace": s.APP, "template": "release-notes", "worker": "worker", "namespace": s.APP, "pool": s.APP, "pod": "worker-pod", "podUID": "pod-uid", "node": "node-a", "runtime": "gvisor", "runtimeSchema": "v1", "runtimeDigest": "a" * 64}
POD = {"metadata": {"uid": "pod-uid", "labels": {"ate.dev/worker-pool": s.APP}}, "spec": {"nodeName": "node-a"}}
CHECKPOINT = {"version": 1, "actor": "session-test", "uri": "s3://snapshots/held", "memory": False}
ACTOR: dict[str, Any] = {"metadata": {"atespace": s.APP, "name": "session-test", "uid": "actor-uid"}, "actorTemplate": {"atespace": s.APP, "name": "release-notes"}, "status": {"state": "ACTOR_STATE_SUSPENDED", "snapshots": [{"generation": 1, "fidelity": "SNAPSHOT_FIDELITY_VOLUMES", "durableSnapshot": {"status": "SNAPSHOT_STORAGE_STATUS_COMPLETED", "object": {"snapshotUri": "s3://snapshots/held"}}}]}}


class NativeBindingTests(unittest.TestCase):
    def test_first_and_latest_bound_to_controlled_actor_and_worker(self):
        doc: dict[str, Any] = {"version": 1, "first": P, "latest": P}
        self.assertEqual(s.placement(doc, "session-test", {"node-a"}, POD), P)
        for key, value in (("actor", "other"), ("runtime", "runc"), ("actorUID", ""), ("node", "other"), ("namespace", "agents"), ("pool", "other"), ("podUID", "other"), ("template", "counter")):
            changed = copy.deepcopy(doc)
            changed["latest"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                s.placement(changed, "session-test", {"node-a"}, POD)
        changed = copy.deepcopy(doc)
        changed["token"] = "must-not-pass"
        with self.assertRaises(ValueError):
            s.placement(changed, "session-test", {"node-a"}, POD)

    def test_checkpoint_requires_exact_newest_completed_external_volumes(self):
        s.held_checkpoint(ACTOR, CHECKPOINT, P)
        for change in ("pending", "memory", "uri", "uid", "state", "newest"):
            a = copy.deepcopy(ACTOR)
            if change == "pending": a["status"]["snapshots"][0]["durableSnapshot"]["status"] = "PENDING"
            elif change == "memory": a["status"]["snapshots"][0]["fidelity"] = "SNAPSHOT_FIDELITY_MEMORY"
            elif change == "uri": a["status"]["snapshots"][0]["durableSnapshot"]["object"]["snapshotUri"] = "s3://wrong"
            elif change == "uid": a["metadata"]["uid"] = "replacement"
            elif change == "state": a["status"]["state"] = "ACTOR_STATE_RUNNING"
            else: a["status"]["snapshots"].append({"generation": 2, "fidelity": "SNAPSHOT_FIDELITY_VOLUMES"})
            with self.subTest(change=change), self.assertRaises(ValueError):
                s.held_checkpoint(a, CHECKPOINT, P)

    def test_application_uses_actor_digest_and_no_host_state(self):
        bundle = {"manifests": [{"kind": "WorkerPool", "metadata": {"name": "smoke", "namespace": "smoke", "labels": {"workload": "smoke"}}, "spec": {"replicas": 1}}], "actorTemplate": {"metadata": {}, "workerSelector": {}, "containers": [], "resources": {}, "snapshotConfig": {}, "sandboxConfig": {"sandboxClass": "gvisor"}, "volumes": [{"name": "data", "durableDir": {}}]}}
        image = "registry.example/fixture@sha256:" + "a" * 64
        pool, template = s.application_bundle(bundle, image)
        self.assertEqual(pool["metadata"]["namespace"], s.APP)
        self.assertEqual(template["containers"], [{"name": "harness", "image": image, "command": ["/session-fixture", "actor-harness"], "volumeMounts": [{"name": "data", "mountPath": "/durable"}]}])
        self.assertEqual(template["snapshotConfig"]["goldenSnapshotConfig"]["mode"], "GOLDEN_SNAPSHOT_MODE_DISABLED")
        self.assertNotIn("/data", str(template))
        with self.assertRaises(ValueError): s.application_bundle(bundle, "fixture:latest")

    def test_runtime_cilium_policy_cannot_bypass_owned_router_inventory(self):
        api: Any = object.__new__(s.SubstrateScenario)
        api.runtime_policies, api.runtime_policy_uids = {}, {}
        api.kube = Mock(return_value=b"ciliumnetworkpolicies.cilium.io\n")
        api.get = Mock(side_effect=lambda kind, **kwargs: {"items": [] if kind == "networkpolicies" else [{"metadata": {"name": "extra"}}]})
        with patch.object(s.nightly.Scenario, "check_policies"), self.assertRaises(ValueError):
            api.check_policies()

    def test_continue_rejects_changed_held_uri_before_any_resume(self):
        api: Any = object.__new__(s.SubstrateScenario)
        api.first, api.checkpoint, api.parked_placement = P, CHECKPOINT, P
        api.read_placement = Mock(return_value=P)
        changed = copy.deepcopy(ACTOR)
        changed["status"]["snapshots"][0]["durableSnapshot"]["object"]["snapshotUri"] = "s3://other"
        api.actor = Mock(return_value=changed)
        with patch.object(s.nightly.Scenario, "rpc") as rpc, self.assertRaises(ValueError):
            api.rpc("continue")
        rpc.assert_not_called()

    def test_continue_saves_native_proof_before_cleanup_not_overall_success(self):
        api: Any = object.__new__(s.SubstrateScenario)
        api.first, api.checkpoint, api.parked_placement = P, CHECKPOINT, P
        api.read_placement = Mock(return_value=P)
        running = copy.deepcopy(ACTOR)
        running["status"] = {"state": "ACTOR_STATE_RUNNING", "workerAssignment": {"workerPodUid": P["podUID"], "nodeName": P["node"], "sandboxRuntime": {"sandboxClass": "gvisor"}}}
        api.actor = Mock(side_effect=[ACTOR, running])
        api.native_evidence = Mock()
        api.native_passed = False
        with patch.object(s.nightly.Scenario, "rpc", return_value={"completed": True}):
            self.assertEqual(api.rpc("continue"), {"completed": True})
        api.native_evidence.write_json.assert_called_once()
        self.assertEqual(api.native_evidence.write_json.call_args.args[1]["status"], "nativePassed")
        self.assertTrue(api.native_passed)

    def test_executor_peer_identity_is_not_a_remote_harness_or_wi_recipient(self):
        api: Any = object.__new__(s.SubstrateScenario)
        peer = {"metadata": {"uid": "executor", "labels": {"app.kubernetes.io/component": "executor"}}, "spec": {"nodeName": "node-a", "automountServiceAccountToken": False, "containers": [{"name": "executor"}]}}
        host = {"spec": {"nodeName": "node-a"}}
        api.component = Mock(side_effect=lambda role: host if role == "host" else peer)
        self.assertEqual(api.marker(), {"podUID": "executor", "nodeName": "node-a"})
        peer["metadata"]["labels"]["azure.workload.identity/use"] = "true"
        with self.assertRaises(ValueError): api.marker()

    def test_run_refuses_partial_native_or_cleanup_proof(self):
        for native, cleaned in ((False, True), (True, False)):
            api = SimpleNamespace(native_passed=native, native_cleanup_passed=cleaned, native_evidence=Mock(), cleanup_status="succeeded", diagnostics=None)
            with self.subTest(native=native, cleaned=cleaned), patch.object(s.nightly, "run_scenario", return_value=({}, [])), self.assertRaises(ValueError):
                s.run(api)
            api.native_evidence.close.assert_called_once()

    def test_result_write_or_close_error_does_not_mask_primary(self):
        primary = RuntimeError("original")
        evidence = Mock()
        evidence.write_json.side_effect = OSError("full disk")
        evidence.close.side_effect = OSError("close")
        api = SimpleNamespace(native_passed=False, native_cleanup_passed=False, native_evidence=evidence, cleanup_status="failed", diagnostics=None)
        with patch.object(s.nightly, "run_scenario", side_effect=primary), self.assertRaises(RuntimeError) as caught:
            s.run(api)
        self.assertIs(caught.exception, primary)
        evidence.write_json.assert_called_once()

    def test_run_keeps_primary_failure_and_marks_cleanup_failure(self):
        primary = RuntimeError("original")
        api = SimpleNamespace(native_passed=False, native_cleanup_passed=False, native_evidence=Mock(), cleanup_status="succeeded", diagnostics={"cleanup": "succeeded"})
        with patch.object(s.nightly, "run_scenario", side_effect=primary), self.assertRaises(RuntimeError) as caught:
            s.run(api)
        self.assertIs(caught.exception, primary)
        self.assertEqual(api.cleanup_status, "failed")
        self.assertEqual(api.diagnostics["cleanup"], "failed")

    def test_network_probes_use_positive_controls_and_no_credentials(self):
        labels = {"host": {"app.kubernetes.io/component": "host"}, "harness": {"app.kubernetes.io/component": "executor"}}
        jobs = s.network_jobs("live", labels, "fixture@sha256:" + "a" * 64, "10.0.0.1:8080", "10.0.0.2:443", "10.0.0.3:9000", "20.0.0.1:443")
        self.assertEqual(set(jobs), {"untrusted-router", "untrusted-control", "executor-router", "executor-control", "executor-model", "host-egress"})
        for case, (namespace, job) in jobs.items():
            spec = job["spec"]["template"]["spec"]
            self.assertFalse(spec["automountServiceAccountToken"])
            self.assertNotIn("volumes", spec)
            self.assertNotIn("serviceAccountName", spec)
            if case.startswith("untrusted"):
                self.assertEqual(namespace, s.PROBES)
            else:
                self.assertEqual(namespace, "agents")
            if case.startswith("executor"):
                self.assertEqual(spec["initContainers"][0]["restartPolicy"], "Always")
                self.assertEqual(spec["initContainers"][1]["command"][-3:], ["127.0.0.1:9000", "--expect", "allowed"])
            self.assertEqual(spec["containers"][0]["command"][-1], "denied")

    def test_native_command_reuses_original_work_and_cleanup_deadline(self):
        api: Any = object.__new__(s.SubstrateScenario)
        api.source, api.tools, api.kubeconfig = Path("/source"), Path("/tools"), Path("/private/kubeconfig")
        api.deadlines = SimpleNamespace(remaining=Mock(side_effect=[17, 23]))
        api.native_evidence = SimpleNamespace(command=Mock(return_value=b"{}"))
        with patch.object(s.substrate, "setup_environment", return_value=contextlib.nullcontext()):
            api.native("get", "actor", "session")
            api.native("delete", "actor", "session", cleanup=True)
        self.assertEqual(api.deadlines.remaining.call_args_list[0].kwargs, {"cleanup": False})
        self.assertEqual(api.deadlines.remaining.call_args_list[1].kwargs, {"cleanup": True})
        self.assertEqual([c.kwargs["timeout"] for c in api.native_evidence.command.call_args_list], [17, 23])
        self.assertTrue(all("--context" in c.args[0] and str(api.kubeconfig) in c.args[0] for c in api.native_evidence.command.call_args_list))

    def test_publication_binding_uses_explicit_executor_not_harness_fallback(self):
        pins = {"host": "host@sha256:x", "harness": "fixture@sha256:y"}
        publication = {"sourceCommit": "same", "images": {k: {"repository": v.split("@")[0], "digest": v.split("@")[1]} for k, v in pins.items()}}
        rendered: list[dict[str, Any]] = [{"kind": "Deployment", "metadata": {"labels": {"app.kubernetes.io/component": role}}, "spec": {"template": {"spec": {"containers": [{"image": pins[image]}]}}}} for role, image in (("host", "host"), ("executor", "harness"))]
        with patch.object(s.nightly.update_pins, "validate_manifest", return_value=publication), patch.object(s.nightly.backup_helper, "validate_receipt"), patch.object(s.nightly.backup_helper, "validate_host", return_value="helper"):
            s.nightly.verify_bindings(pins, rendered, publication, {"sourceCommit": "same"}, "helper", peer_role="executor")
            rendered[1]["metadata"]["labels"]["app.kubernetes.io/component"] = "harness"
            with self.assertRaises(ValueError):
                s.nightly.verify_bindings(pins, rendered, publication, {"sourceCommit": "same"}, "helper", peer_role="executor")

    def test_cleanup_preserves_primary_attempts_all_and_fails_without_primary(self):
        events = []
        def failure():
            events.append("failed")
            raise OSError("private detail")
        actions = [("first", failure), ("second", lambda: events.append("second"))]
        evidence = Mock()
        primary = RuntimeError("original")
        self.assertFalse(s.cleanup_actions(actions, evidence, primary))
        self.assertEqual(events, ["failed", "second"])
        with self.assertRaises(ValueError): s.cleanup_actions(actions, evidence, None)
        interrupted = [("first", lambda: (_ for _ in ()).throw(KeyboardInterrupt())), ("second", lambda: self.fail("continued after cancellation"))]
        with self.assertRaises(KeyboardInterrupt): s.cleanup_actions(interrupted, evidence, None)


if __name__ == "__main__": unittest.main()
