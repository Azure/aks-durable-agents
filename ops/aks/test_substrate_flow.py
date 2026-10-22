"""Real adapter orchestration with real Helm, file proofs and synthetic external APIs.

No Azure, model, Kubernetes or native runtime calls. The released host/adapter/
harnesswire lifecycle itself is exercised separately by the Go assembly test.
"""
import contextlib
import copy
import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

import substrate_proof
import substrate_session as s
import test_nightly as fixtures
from test_substrate_session import ACTOR, CHECKPOINT, P

# The standalone admission helper sets its own CLI search path. Do not leak it
# into unittest discovery (both images and AKS have test_workflows modules).
original_path = sys.path[:]
try:
    import check_substrate_manifests
finally:
    sys.path[:] = original_path


def encoded(value):
    return json.dumps(value).encode()


class External:
    def __init__(self):
        self.calls, self.objects, self.rendered = [], {}, []
        self.replicas, self.host_generation = {}, 1
        self.calls_model, self.effects = 0, 0
        self.native_calls = []
        self.template: Any = None
        self.bad_checkpoint, self.bad_template, self.fail_actor_delete = False, False, False
        self.api: Any = None

    def object(self, namespace, kind, name):
        return self.objects[namespace, kind.lower(), name]

    def put(self, obj, namespace):
        obj = copy.deepcopy(obj)
        obj["metadata"].setdefault("uid", obj["metadata"]["name"] + "-uid")
        self.objects[namespace, obj["kind"].lower(), obj["metadata"]["name"]] = obj

    def native(self, argv, *, timeout, input=None):
        assert timeout > 0
        args = argv[5:]
        self.native_calls.append(args)
        if args[:2] == ["create", "actor-template"]:
            assert input is not None
            self.template = json.loads(input)
        elif args[:2] == ["get", "actor-template"]:
            value = copy.deepcopy(self.template)
            if self.bad_template:
                value["containers"][0]["image"] = "untrusted:latest"
            return encoded(value)
        elif args[:2] == ["get", "actor"]:
            value: Any = copy.deepcopy(ACTOR)
            if self.effects:
                value["status"] = {"state": "ACTOR_STATE_RUNNING", "workerAssignment": {"workerPodUid": P["podUID"], "nodeName": "n1", "sandboxRuntime": {"sandboxClass": "gvisor"}}}
            if args[2] == "-a":
                return encoded({"actors": [value] if self.calls_model else []})
            if self.bad_checkpoint:
                value["status"]["snapshots"][0]["durableSnapshot"]["object"]["snapshotUri"] = "s3://wrong"
            return encoded(value)
        elif args[:2] == ["delete", "actor"] and self.fail_actor_delete:
            raise ValueError("synthetic native cleanup error")
        return b"{}"

    @contextlib.contextmanager
    def forward(self, prefix, name):
        self.calls.append(["forward", name])
        yield 12345

    def run(self, argv, **kwargs):
        self.calls.append(argv)
        api = self.api
        if argv[0] == "helm":
            if "template" in argv:
                raw = subprocess.check_output(argv)
                self.rendered = [x for x in s.nightly.yaml.safe_load_all(raw) if x]
                return raw
            if "install" in argv:
                for obj in self.rendered:
                    self.put(obj, "agents")
                    if obj["kind"] == "Deployment":
                        self.replicas[obj["metadata"]["name"]] = 0
                return b""
            raise AssertionError(argv)
        if Path(argv[0]).resolve() == Path(sys.executable).resolve():
            if "ops/backup/backup.py" in argv[2]:
                command = argv[3]
                assert all(v == 0 for v in self.replicas.values())
                if command == "backup":
                    assert argv[-2:] == ["--output", str(api.archive)] and "--runtime" in argv
                    api.archive.write_bytes(b"synthetic archive transport")
                    return encoded({"backup": str(api.archive), "sha256": hashlib.sha256(api.archive.read_bytes()).hexdigest(), "source": {"replicas": self.replicas}})
                assert command == "restore" and "--runtime" not in argv
                completed = api.snapshot("completed.json")
                recovery = argv[argv.index("--namespace") + 1]
                return b"\n".join(encoded(v) for v in [
                    {"restore": "verified", "namespace": recovery, "pvc": s.nightly.PVC, "session": "session-test", "workloads_started": False},
                    {"socket_denial": "verified"}, {"socket_denial": "verified"},
                    {"restored_hashes": "unchanged", "replay": {"completed": True, "provider_calls": 0, "executor_calls": 0, "session_uid": "session-test", "head_seq": completed["headSeq"], "head_hash": completed["headHash"], "expected_execution_ids": ["execution-test"], "covered_execution_ids": ["execution-test"]}}])
            command = argv[1]
            parked = fixtures.state()
            if command == "park":
                self.calls_model = 1
                s.nightly.write_json(api.state / "park.json", parked)
                return encoded(parked)
            if command == "checkpoint":
                return encoded(CHECKPOINT)
            if command == "check-parked":
                assert self.host_generation == 2 and self.effects == 0
                return encoded({"session": "session-test", "parked": True})
            if command == "approve":
                assert self.effects == 0
                return encoded({"session": "session-test", "approved": True})
            if command == "continue":
                self.effects = 1
                completed = dict(parked, headSeq=8, approvalSeq=4, artifact="b" * 64 + ".json")
                s.nightly.write_json(api.state / "completed.json", completed)
                return encoded({"session": "session-test", "completed": True, "artifact": completed["artifact"]})
            raise AssertionError(argv)
        assert argv[0] == "kubectl", argv
        namespace, command = argv[6], argv[7:]
        verb = command[0]
        if verb == "create":
            obj = json.loads(kwargs["data"])
            self.put(obj, namespace)
            return b"{}"
        if verb == "get":
            kind = command[1]
            if kind == "namespace":
                return b""
            if kind == "nodes":
                return encoded({"items": [{"metadata": {"name": node, "labels": {"kubernetes.io/os": "linux", "kubernetes.io/arch": "amd64"}}, "status": {"conditions": [{"type": "Ready", "status": "True"}]}} for node in ("n1", "n2")]})
            if kind == "daemonsets":
                return encoded({"items": [{"status": {"desiredNumberScheduled": 2, "numberReady": 2}}]})
            if kind == "pods":
                selector = command[command.index("-l") + 1] if "-l" in command else ""
                if namespace in ("kube-system", "node-profile") or "nightly-profile" in selector:
                    return encoded({"items": [fixtures.pod("cilium-" + node, node) for node in ("n1", "n2")]})
                if namespace == "ate-system":
                    p = fixtures.pod(selector.removeprefix("app="), "n1")
                    p["status"]["podIP"] = "10.0.1.2" if "router" in selector else "10.0.1.3"
                    return encoded({"items": [p]})
                pods = []
                for name, replicas in self.replicas.items():
                    obj = self.object("agents", "deployment", name)
                    template = obj["spec"]["template"]
                    wanted = {key: value for key, _, value in (part.partition("=") for part in selector.split(",") if part)}
                    if namespace == "agents" and replicas and all(template["metadata"]["labels"].get(k) == v for k, v in wanted.items()):
                        role = template["metadata"]["labels"]["app.kubernetes.io/component"]
                        uid = "host-" + str(self.host_generation) if role == "host" else "executor-stable"
                        pod = fixtures.pod(uid, "n1")
                        pod["metadata"]["labels"] = template["metadata"]["labels"]
                        pod["spec"].update(template["spec"])
                        pods.append(pod)
                return encoded({"items": pods})
            if kind == "deployments":
                return b'{"items":[]}'
            if kind.startswith("deployment/"):
                name = kind.split("/", 1)[1]
                return encoded({"spec": {"replicas": self.replicas[name]}})
            if kind == "networkpolicies":
                return encoded({"items": [v for (ns, k, _), v in self.objects.items() if ns == namespace and k == "networkpolicy"]})
            if kind == "hpa":
                return b'{"items":[]}'
            if kind == "pod/nightly-credential":
                return encoded({"spec": {"containers": [{"env": [{"name": "AZURE_CLIENT_ID", "value": api.env["MODEL_CLIENT_ID"]}, {"name": "AZURE_FEDERATED_TOKEN_FILE", "value": "/projected/token"}]}]}})
            if kind == "pod/actor-peer":
                return encoded({"status": {"podIP": "10.0.2.1"}})
            if kind == "pod/worker-pod":
                return encoded({"metadata": {"uid": P["podUID"], "labels": {"ate.dev/worker-pool": s.APP}}, "spec": {"nodeName": "n1"}})
            raise AssertionError(argv)
        if verb == "exec":
            if "placement-evidence" in command:
                p = dict(P, node="n1")
                return encoded({"version": 1, "first": p, "latest": p})
            if "evidence" in command:
                assert command[3] == "daemon"
                return encoded(fixtures.evidence(self.calls_model, self.effects))
            return b""
        if verb == "logs":
            if command[1] == "pod/nightly-evidence":
                return encoded(fixtures.evidence(1, 1))
            job = self.object(namespace, "job", command[1].split("/", 1)[1])
            spec = job["spec"]["template"]["spec"]
            stage = command[command.index("-c") + 1]
            container = next(c for c in spec["initContainers"] + spec["containers"] if c["name"] == stage)
            address, expect = container["command"][-3], container["command"][-1]
            return encoded({"address": address, "allowed": expect == "allowed", "expect": expect, "tcpOnly": True})
        if verb == "api-resources":
            return b""
        if verb == "scale":
            self.replicas[command[1].split("/", 1)[1]] = int(command[2].split("=")[1])
            return b""
        if verb == "delete":
            if command[1] == "pod/host-1":
                self.host_generation += 1
            for resource in command[1:]:
                if "/" in resource and not resource.startswith("--"):
                    kind, name = resource.split("/", 1)
                    self.objects.pop((namespace, kind, name), None)
            return b""
        if verb in ("wait", "rollout", "label"):
            return b""
        raise AssertionError(argv)


class ActorFlowTests(unittest.TestCase):
    def exercise(self, *, bad_checkpoint=False, bad_template=False, fail_actor_delete=False):
        fixture = fixtures.DiagnosticTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        boundary = External()
        boundary.bad_checkpoint, boundary.bad_template, boundary.fail_actor_delete = bad_checkpoint, bad_template, fail_actor_delete
        mapping = fixture.root / "mapping.json"
        mapping.write_bytes(encoded(check_substrate_manifests.test_images()))
        bundle = {"manifests": [{"kind": "WorkerPool", "metadata": {"name": "counter", "namespace": "counter"}, "spec": {"workerImage": "example/worker@sha256:" + "a" * 64}}], "actorTemplate": {"volumes": [{"name": "data", "durableDir": {}}]}}
        env = dict(fixture.env, AKS_SUBSTRATE_ENABLED="true")
        api = s.SubstrateScenario(fixture.work, Path(sys.executable).resolve(), fixtures.ROOT / "charts/aks-durable-agents", env, fixture.root, mapping, fixture.root, boundary)
        boundary.api = api
        def installer(*args, clock, **kwargs):
            self.assertLessEqual(clock.remaining(), float(env["WORK_DEADLINE_EPOCH"]) - clock.now() + .1)
        def execute():
            with patch.object(s.substrate, "render", return_value=bundle), patch.object(s.substrate, "install", side_effect=installer), patch.object(s.substrate, "setup_environment", return_value=contextlib.nullcontext()), patch.object(api.native_evidence, "command", side_effect=boundary.native), patch.object(s.socket, "gethostbyname", return_value="20.0.0.1"):
                return s.run(api)
        return api, boundary, execute

    def test_real_python_flow_binds_park_restart_continue_archive_replay_and_cleanup(self):
        api, boundary, execute = self.exercise()
        proof, network = execute()
        self.assertEqual(substrate_proof.validate(proof)["profile"], "aks-substrate")
        self.assertEqual(len(substrate_proof.validate_network(network)), 24)
        self.assertEqual((boundary.calls_model, boundary.effects, boundary.host_generation), (1, 1, 2))
        native = json.loads((api.workdir / "actor-evidence/native-proof.json").read_bytes())
        self.assertEqual(native["status"], "nativePassed")
        self.assertEqual(native["harnessImage"], api.pins["harness"])
        result = json.loads((api.workdir / "actor-evidence/scenario-result.json").read_bytes())
        self.assertEqual(result, {"status": "passed", "native": "nativePassed", "cleanup": "succeeded"})
        self.assertEqual(boundary.native_calls[-3:][0][:2], ["delete", "actor"])
        self.assertFalse(any("fixture-harness" in call or "nightly-marker" in call for call in boundary.calls))

    def test_corrupt_native_checkpoint_fails_before_continue_and_still_cleans(self):
        api, boundary, execute = self.exercise(bad_checkpoint=True)
        with self.assertRaises(ValueError): execute()
        self.assertEqual(boundary.effects, 0)
        self.assertFalse((api.workdir / "actor-evidence/native-proof.json").exists())
        self.assertIn(["delete", "atespace", s.APP], boundary.native_calls)

    def test_template_drift_fails_before_first_model_attempt(self):
        _, boundary, execute = self.exercise(bad_template=True)
        with self.assertRaises(ValueError): execute()
        self.assertEqual(boundary.calls_model, 0)
        self.assertIn(["delete", "atespace", s.APP], boundary.native_calls)

    def test_native_proof_survives_cleanup_failure_without_overall_success(self):
        api, _, execute = self.exercise(fail_actor_delete=True)
        with self.assertRaises(ValueError): execute()
        self.assertTrue((api.workdir / "actor-evidence/native-proof.json").exists())
        result = json.loads((api.workdir / "actor-evidence/scenario-result.json").read_bytes())
        self.assertEqual(result, {"status": "failed", "native": "nativePassed", "cleanup": "failed"})


if __name__ == "__main__": unittest.main()
