"""Offline invariant and orchestration tests. No cloud/model/Kubernetes calls."""
import contextlib
import copy
import datetime
import importlib.util
import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent

def module():
    spec = importlib.util.spec_from_file_location("aks_nightly", HERE / "nightly.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def evidence(calls=1, effects=0):
    return {"fakeModelCalls": 0, "realModelCalls": calls, "realLedgerDigest": "a" * 64,
            "realAttempts": [{"attemptId": 1, "time": "2026-10-21T00:00:00Z", "finishedAt": "2026-10-21T00:00:01Z",
                              "outcome": "succeeded", "inputTokens": 250, "outputTokens": 84, "reasoningTokens": 12}] if calls else [],
            "publicationCount": effects, "receiptCount": effects,
            "artifacts": [{"name": "b" * 64 + ".json", "digest": "c" * 64}] if effects else []}


def state():
    return {"session": "session-test", "pending": {"executionID": "execution-test", "toolCallID": "execution-test/publish_release_notes", "requestSeq": 3},
            "headSeq": 3, "headHash": "d" * 64, "draft": "private fictional draft"}


def pod(uid, node="n1"):
    return {"metadata": {"uid": uid, "name": uid}, "spec": {"nodeName": node}, "status": {"conditions": [{"type": "Ready", "status": "True"}]}}


class InvariantTests(unittest.TestCase):
    def setUp(self):
        self.n = module()

    def test_networkpolicy_api_empty_lists_are_normalized_without_weakening_rules(self):
        rendered = {"podSelector": {}, "policyTypes": ["Ingress", "Egress"], "ingress": [], "egress": []}
        observed = {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}
        self.assertEqual(self.n.policy_spec(rendered), self.n.policy_spec(observed))
        self.assertEqual(observed, {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]})
        permitted = dict(observed, egress=[{}])
        self.assertNotEqual(self.n.policy_spec(rendered), self.n.policy_spec(permitted))

    def test_absent_cilium_policy_api_is_discovered_not_assumed(self):
        api = self.n.Scenario.__new__(self.n.Scenario)
        api.rendered_policies = {"deny": self.n.policy_spec({"podSelector": {}, "ingress": [], "egress": []})}
        def get(kind, *args, **kwargs):
            if kind == "networkpolicies":
                return {"items": [{"metadata": {"name": "deny", "uid": "same"}, "spec": {"podSelector": {}}}]}
            if kind == "hpa":
                return {"items": []}
            self.fail("unsupported Cilium API must not be queried")
        api.get = get
        api.kube = lambda *args, **kwargs: b"ciliumnodes.cilium.io\n"
        api.check_policies(initial=True)
        api.check_policies()

    def test_real_ledger_requires_one_known_bounded_success_and_zero_fake(self):
        self.n.check_evidence(evidence(0), 0, 0)
        self.n.check_evidence(evidence(), 1, 0)
        self.n.check_evidence(evidence(1, 1), 1, 1)
        for field, value in [("outcome", "unknown"), ("outcome", "failed"), ("inputTokens", None), ("outputTokens", None),
                             ("inputTokens", 8193), ("outputTokens", 4097), ("reasoningTokens", None), ("reasoningTokens", 85),
                             ("attemptId", 2), ("finishedAt", None)]:
            bad = evidence()
            bad["realAttempts"][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.n.check_evidence(bad, 1, 0)
        for field, value in [("fakeModelCalls", 1), ("realModelCalls", None), ("realModelCalls", True),
                             ("realLedgerDigest", ""), ("publicationCount", 1), ("realAttempts", evidence()["realAttempts"] * 2)]:
            bad = evidence()
            bad[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.n.check_evidence(bad, 1, 0)

    def test_ledger_digest_and_attempts_cannot_change_after_park(self):
        self.n.same_ledger(evidence(), evidence(1, 1))
        for field in ("realLedgerDigest", "realAttempts"):
            bad = evidence(1, 1)
            bad[field] = "changed"
            with self.assertRaises(ValueError):
                self.n.same_ledger(evidence(), bad)

    def test_restart_requires_uid_change_unchanged_harness_same_node_exact_marker(self):
        old, new, harness = pod("old"), pod("new"), pod("harness")
        marker = {"podUID": "harness", "nodeName": "n1"}
        self.n.check_restart(old, new, harness, harness, marker)
        for replacement, peer, mark in [(old, harness, marker), (pod("new", "n2"), harness, marker),
                                         (new, pod("different"), marker), (new, harness, {"podUID": "old", "nodeName": "n1"})]:
            with self.assertRaises(ValueError):
                self.n.check_restart(old, replacement, harness, peer, mark)

    def test_strict_replay_binds_completed_head_and_coverage_not_just_zero_calls(self):
        completed = dict(state(), headSeq=8, approvalSeq=4, artifact="b" * 64 + ".json")
        raw = {"replay": {"completed": True, "provider_calls": 0, "executor_calls": 0, "session_uid": completed["session"],
                           "head_seq": 8, "head_hash": completed["headHash"], "expected_execution_ids": ["execution-test"],
                           "covered_execution_ids": ["execution-test"], "error": ""}, "restored_hashes": "unchanged"}
        self.n.check_replay(raw, completed)
        for field, value in [("completed", False), ("provider_calls", 1), ("executor_calls", 1), ("head_seq", 7),
                             ("head_hash", "e" * 64), ("covered_execution_ids", []), ("expected_execution_ids", []),
                             ("error", "unfinished")]:
            bad = copy.deepcopy(raw)
            bad["replay"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.n.check_replay(bad, completed)

    def test_fresh_fixture_init_before_any_tmp_directories(self):
        obj = self.n.prepare_manifest("nightly-12-1", "fixture@sha256:" + "a" * 64)
        spec = obj["spec"]
        stages = spec["initContainers"] + spec["containers"]
        self.assertEqual([c["name"] for c in stages], ["ownership", "fixture", "tmpdirs"])
        self.assertIn("test ! -e", stages[0]["command"][-1])
        self.assertIn("chown 65532:65532", stages[0]["command"][-1])
        self.assertNotIn("tmp-", stages[0]["command"][-1])
        self.assertEqual(stages[1]["command"], ["/session-fixture", "init", "--scenario", "v2", "--data", "/volume/nightly-12-1", "--socket", "/data/publish.sock"])
        self.assertEqual(stages[1]["securityContext"]["runAsUser"], 65532)
        self.assertIn("tmp-daemon", stages[2]["command"][-1])
        self.assertFalse(spec["automountServiceAccountToken"])

    def test_rpc_builder_exact_allowlist(self):
        for command in ("park", "check-parked", "approve", "continue"):
            args = self.n.rpc_command(Path("/private/client"), command, Path("/private/state"), 42345)
            self.assertEqual(args, ["/private/client", command, "--data", "/private/state", "--server", "127.0.0.1:42345"])
        for forbidden in ("seal", "verify", "counter", "prepare", "resume"):
            with self.assertRaises(ValueError):
                self.n.rpc_command(Path("/private/client"), forbidden, Path("/private/state"), 42345)

    def test_network_builders_no_additive_policy_two_independent_controls(self):
        labels = {"host": {"app.kubernetes.io/name": "aks-durable-agents", "app.kubernetes.io/instance": "kaimahi", "app.kubernetes.io/component": "host"},
                  "harness": {"app.kubernetes.io/name": "aks-durable-agents", "app.kubernetes.io/instance": "kaimahi", "app.kubernetes.io/component": "harness"}}
        objs = self.n.network_probes("dormant", labels, "fixture@sha256:" + "a" * 64, "10.1.1.2:9000", "10.1.1.3:9000")
        self.assertEqual(len(objs), 2)
        self.assertTrue(all(o["kind"] != "NetworkPolicy" for o in objs))
        hosts = [o for o in objs if o["spec"]["template"]["metadata"]["labels"] == labels["host"]]
        self.assertEqual(len(hosts), 1)
        untrusted = [o for o in objs if o not in hosts][0]
        self.assertFalse(set(labels["host"]) & set(untrusted["spec"]["template"]["metadata"]["labels"]))
        # Each source must prove a permitted path BEFORE its expected denial.
        # Two host-only controls cannot establish that an untrusted source works.
        for obj, control, denied in ((untrusted, "10.1.1.3:9000", "10.1.1.2:9000"),
                                     (hosts[0], "10.1.1.2:9000", "10.1.1.3:9000")):
            spec = obj["spec"]["template"]["spec"]
            self.assertFalse(spec["automountServiceAccountToken"])
            self.assertEqual(len(spec["initContainers"]), 1)
            self.assertEqual(spec["initContainers"][0]["command"][-3:], [control, "--expect", "allowed"])
            self.assertEqual(spec["containers"][0]["command"][-3:], [denied, "--expect", "denied"])

    def test_rendered_pins_bind_both_images_and_helper_same_source(self):
        import yaml
        pins = self.n.chart_images(ROOT)
        publication = {"version": 1, "sourceCommit": "a" * 40, "images": {role: dict(zip(("repository", "digest"), ref.split("@"))) for role, ref in pins.items()}}
        receipt = {"version": 1, "sourceCommit": "a" * 40, "hostDigest": pins["host"].split("@")[1],
                   "image": "ghcr.io/azure/aks-durable-agents/backup-helper@sha256:" + "b" * 64}
        rendered = [{"kind": "Deployment", "metadata": {"labels": {"app.kubernetes.io/component": role}},
                     "spec": {"template": {"spec": {"containers": [{"image": ref}]}}}} for role, ref in pins.items()]
        self.n.verify_bindings(pins, rendered, publication, receipt, receipt["image"])
        bad = copy.deepcopy(rendered)
        bad[1]["spec"]["template"]["spec"]["containers"][0]["image"] = "wrong"
        with self.assertRaises(ValueError):
            self.n.verify_bindings(pins, bad, publication, receipt, receipt["image"])
        receipt["sourceCommit"] = "c" * 40
        with self.assertRaises(ValueError):
            self.n.verify_bindings(pins, rendered, publication, receipt, receipt["image"])

    def test_credential_probe_only_exchanges_federated_token_and_never_prints_it(self):
        import io
        import urllib.request
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temp:
            token = Path(temp) / "token"
            token.write_text("private-assertion")
            requests = []
            class Response:
                def __enter__(self): return self
                def __exit__(self, *args): pass
                def read(self, size): return b'{"access_token":"private-access-token","expires_in":3600,"token_type":"Bearer"}'
            def exchange(request, timeout):
                requests.append(request)
                return Response()
            environ = {"AZURE_CLIENT_ID": "55555555-5555-5555-5555-555555555555", "AZURE_TENANT_ID": "44444444-4444-4444-4444-444444444444",
                       "AZURE_AUTHORITY_HOST": "https://login.microsoftonline.com/", "AZURE_FEDERATED_TOKEN_FILE": str(token)}
            out, err = io.StringIO(), io.StringIO()
            with patch.dict(os.environ, environ, clear=True), patch.object(urllib.request, "urlopen", exchange), patch("sys.stdout", out), patch("sys.stderr", err):
                exec(self.n.credential_probe_script(), {})
            self.assertEqual(out.getvalue(), "")
            self.assertEqual(err.getvalue(), "")
            self.assertEqual(len(requests), 1)
            self.assertIn("/oauth2/v2.0/token", requests[0].full_url)
            self.assertIn(b"client_assertion=private-assertion", requests[0].data)
            self.assertNotIn("openai", requests[0].full_url)

    def test_readonly_marker_builder_uses_real_file_not_nonexistent_fixture_cli(self):
        obj = self.n.marker_manifest("nightly-12-1", "helper@sha256:" + "a" * 64, "n1")
        spec = obj["spec"]
        c = spec["containers"][0]
        self.assertEqual(c["command"][:2], ["python3", "-c"])
        self.assertIn("fixture-node.json", c["command"][-1])
        self.assertEqual(spec["nodeName"], "n1")
        self.assertEqual(c["securityContext"]["seccompProfile"]["type"], "Localhost")
        self.assertTrue(c["volumeMounts"][0]["readOnly"])
        self.assertFalse(spec["automountServiceAccountToken"])

    def test_fence_rejects_even_pending_consumers(self):
        deployments = [{"spec": {"replicas": 0}}] * 2
        self.n.check_fence(deployments, [])
        pending = {"metadata": {"name": "pending"}, "spec": {"volumes": [{"persistentVolumeClaim": {"claimName": "nightly-data"}}]}, "status": {"phase": "Pending"}}
        with self.assertRaises(ValueError):
            self.n.check_fence(deployments, [pending])
        with self.assertRaises(ValueError):
            self.n.check_fence([{"spec": {"replicas": 1}}] * 2, [])

    def test_real_helm_render_accepts_conservative_values_and_preserves_budget(self):
        import datetime
        import shutil

        import yaml
        if not shutil.which("helm"):
            self.skipTest("Helm unavailable")
        env = {"AKS_SCENARIO_ENABLED": "true", "AKS_BUDGET_CONFIRMED": "true", "MODEL_ENDPOINT": "https://example.invalid/openai/v1/",
               "MODEL_DEPLOYMENT": "reviewed-model", "MODEL_CLIENT_ID": "55555555-5555-5555-5555-555555555555", "MODEL_PRICE_INPUT": "225000",
               "MODEL_PRICE_OUTPUT": "500000", "MODEL_PRICE_EXTRA": "0", "MODEL_PRICE_SOURCE": "https://example.invalid/prices",
               "MODEL_PRICE_AS_OF": datetime.date.today().isoformat()}
        values = self.n.values_from_env(env, "nightly-12-1")
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "values.json"
            path.write_text(json.dumps(values))
            result = subprocess.run(["helm", "template", "kaimahi", str(ROOT / "charts/aks-durable-agents"), "--namespace", "agents",
                                     "--kube-version", "1.37.0", "-f", str(path)], capture_output=True, check=True)
        objects = [x for x in yaml.safe_load_all(result.stdout) if x]
        deployments = [o for o in objects if o["kind"] == "Deployment"]
        self.assertEqual(len(deployments), 2)
        self.assertTrue(all(d["spec"]["replicas"] == 0 for d in deployments))
        host = next(d for d in deployments if d["metadata"]["labels"]["app.kubernetes.io/component"] == "host")
        self.assertEqual(host["spec"]["template"]["spec"]["containers"][0]["command"], ["/host"])
        self.assertIn("-auth-mode=off", host["spec"]["template"]["spec"]["containers"][0]["args"])
        policy = next(o for o in objects if o["kind"] == "ConfigMap" and "model-policy.json" in o.get("data", {}))
        policy = json.loads(policy["data"]["model-policy.json"])
        self.assertEqual(policy["version"], 1)
        self.assertEqual(policy["runID"], "nightly-12-1")
        for field, wrong in (("AKS_SCENARIO_ENABLED", "false"), ("AKS_BUDGET_CONFIRMED", "false"), ("MODEL_PRICE_EXTRA", "1"), ("MODEL_PRICE_AS_OF", "2020-01-01")):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.n.values_from_env(dict(env, **{field: wrong}), "nightly-12-1")

    def test_backup_uses_real_fence_and_fresh_archive_without_stop(self):
        import hashlib
        n = self.n
        with tempfile.TemporaryDirectory() as temp:
            scenario = n.Scenario.__new__(n.Scenario)
            scenario.archive = Path(temp) / "source.tar.gz"
            scenario.deployments = {"host": "host-deployment", "harness": "harness-deployment"}
            scenario.kubeconfig = Path(temp) / "kubeconfig"
            scenario.subpath, scenario.helper = "nightly-12-1", "helper@sha256:" + "a" * 64
            scenario.get = lambda kind: {"items": []} if kind == "pods" else {"spec": {"replicas": 0}}
            class External:
                def run(self, args):
                    self.arguments = args
                    scenario.archive.write_bytes(b"archive-test-bytes")
                    return b'pod/copy condition met\n' + json.dumps({"backup": str(scenario.archive), "sha256": hashlib.sha256(b"archive-test-bytes").hexdigest(),
                        "source": {"replicas": {"host-deployment": 0, "harness-deployment": 0}}}).encode()
            scenario.executor = External()
            scenario.backup()
            self.assertEqual(scenario.archive.read_bytes(), b"archive-test-bytes")
            self.assertNotIn("--stop", scenario.executor.arguments)
            self.assertEqual(scenario.executor.arguments[3], "backup")
            with self.assertRaises(ValueError): scenario.backup()
            scenario.archive.unlink()
            scenario.get = lambda kind: {"items": []} if kind == "pods" else {"spec": {"replicas": 1}}
            with self.assertRaises(ValueError): scenario.backup()
            self.assertFalse(scenario.archive.exists())

    def test_backup_json_records_allow_kubectl_progress_but_require_exact_proof(self):
        raw = b'pod/journal-copy-test condition met\n{"socket_denial":"verified"}\npod "journal-copy-test" deleted\n{"restore":"verified"}\n'
        self.assertEqual(self.n.json_records(raw), [{"socket_denial": "verified"}, {"restore": "verified"}])
        with self.assertRaises(ValueError):
            self.n.json_records(b'{malformed}\n')
        with self.assertRaises(ValueError):
            self.n.json_records(b'no JSON proof\n')

    def test_work_deadline_immutable_and_cleanup_uses_only_reserve(self):
        clock = lambda: 200
        d = self.n.Deadlines(190, 300, clock)
        with self.assertRaises(ValueError):
            d.remaining()
        self.assertAlmostEqual(d.remaining(cleanup=True), 100, places=2)
        with self.assertRaises(ValueError):
            self.n.Deadlines(300, 299, clock)

    def test_process_group_kills_descendants_on_timeout_and_logs_private(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            os.chmod(root, 0o700)
            d = self.n.Deadlines(time.time() + .3, time.time() + 5)
            executor = self.n.Executor(root, dict(os.environ), d)
            pidfile = root / "child.pid"
            script = "import subprocess,time,pathlib,sys; p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); pathlib.Path(sys.argv[1]).write_text(str(p.pid)); print('private-id',flush=True); time.sleep(60)"
            with self.assertRaises(ValueError):
                executor.run([sys.executable, "-c", script, str(pidfile)])
            pid = int(pidfile.read_text())
            for _ in range(30):
                proc = Path(f"/proc/{pid}/stat")
                try:
                    status = proc.read_text().split()[2]
                except FileNotFoundError:
                    break
                if status == "Z":
                    break
                time.sleep(.02)
            else:
                self.fail("subprocess descendant survived timeout")
            self.assertTrue(list(root.glob("command-*.stdout")))
            self.assertEqual(next(root.glob("command-*.stdout")).stat().st_mode & 0o777, 0o600)


class InstallObservationTests(unittest.TestCase):
    """Hand-authored apps/batch/ate API shapes; every dynamic name and message is a canary."""
    SECRET = "PRIVATE-CANARY-message"
    FIELDS = ("eventReasons", "containerReasons", "containerStates", "exitCodes", "rolloutStatus")

    def setUp(self):
        self.n = module()

    def shapes(self, kind, name):
        def ref(api, owner_kind, owner_name, uid):
            return {"apiVersion": api, "kind": owner_kind, "name": owner_name, "uid": uid, "controller": True}
        labels = {"Job": {"job-name": name}, "WorkerPool": {"ate.dev/worker-pool": name}}.get(kind, {"app": name})
        api = {"Job": "batch/v1", "WorkerPool": "ate.dev/v1alpha1"}.get(kind, "apps/v1")
        controller = {"apiVersion": api, "kind": kind, "metadata": {"name": name, "uid": "controller-uid", "generation": 3},
                      "spec": {"replicas": 1, "selector": {"matchLabels": labels}}, "status": {"observedGeneration": 3}}
        deployment_like = {"apiVersion": "apps/v1", "kind": kind, "metadata": dict(controller["metadata"]), "spec": controller["spec"],
                           "status": {"observedGeneration": 3, "replicas": 1, "readyReplicas": 0}}
        if kind == "DaemonSet":
            controller["status"] = {"observedGeneration": 3, "desiredNumberScheduled": 2, "numberReady": 1}
        elif kind in ("Deployment", "StatefulSet"):
            controller["status"] = deployment_like["status"]
        elif kind == "Job":
            controller["status"] = {"conditions": [{"type": "Failed", "status": "True", "message": self.SECRET}]}
        responses, owner, owners = {kind.lower() + "/" + name: controller}, ref(api, kind, name, "controller-uid"), {"controller-uid"}
        if kind in ("Deployment", "WorkerPool"):
            if kind == "WorkerPool":
                deployment = {"apiVersion": "apps/v1", "kind": "Deployment", "spec": controller["spec"],
                              "metadata": {"name": name, "uid": "deployment-uid", "generation": 2, "ownerReferences": [owner]},
                              "status": {"observedGeneration": 2, "replicas": 1, "updatedReplicas": 1, "readyReplicas": 1, "availableReplicas": 1}}
                responses["deployment/" + name] = deployment
                owner, owners = ref("apps/v1", "Deployment", name, "deployment-uid"), owners | {"deployment-uid"}
            responses["replicasets"] = {"apiVersion": "apps/v1", "kind": "ReplicaSetList", "items": [
                {"apiVersion": "apps/v1", "kind": "ReplicaSet", "metadata": {"name": self.SECRET + "-rs", "uid": "rs-uid", "ownerReferences": [owner]}},
                {"apiVersion": "apps/v1", "kind": "ReplicaSet", "metadata": {"name": "foreign", "uid": "foreign-rs", "ownerReferences": [ref("apps/v1", "Deployment", name, "other")]}}]}
            owner, owners = ref("apps/v1", "ReplicaSet", self.SECRET + "-rs", "rs-uid"), owners | {"rs-uid"}
        def pod(uid, owner, **extra):
            return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": self.SECRET + uid, "uid": uid, "labels": labels, "ownerReferences": [owner], **extra},
                    "status": {"containerStatuses": [{"state": {"waiting": {"reason": "ImagePullBackOff", "message": self.SECRET}}, "lastState": {}}],
                               "initContainerStatuses": [{"state": {"terminated": {"reason": "OOMKilled", "exitCode": 137}},
                                                          "lastState": {"terminated": {"reason": self.SECRET, "exitCode": 1}}}]}}
        responses["pods"] = {"apiVersion": "v1", "kind": "PodList", "items": [
            pod("pod-uid", owner), pod("foreign-owner", dict(owner, uid="other")), pod("deleted", owner, deletionTimestamp="now"),
            {**pod("foreign-state", dict(owner, apiVersion="v2")), "status": {"containerStatuses": [{"state": {"terminated": {"exitCode": 99}}}]}}]}
        def event(uid, reason, kind="Warning"):
            return {"type": kind, "reason": reason, "message": self.SECRET, "involvedObject": {"uid": uid, "name": self.SECRET}}
        responses["events"] = {"apiVersion": "v1", "kind": "EventList", "items": [
            event("pod-uid", "BackOff"), event("controller-uid", "FailedScheduling"), event("pod-uid", self.SECRET),
            event("pod-uid", "Pulled", "Normal"), event("foreign-owner", "Evicted"), event("unrelated", "FailedMount")]}
        return responses

    def reader(self, responses, calls=None):
        def read(resource, *args, namespace=None):
            if calls is not None:
                calls.append((resource, args, namespace))
            return copy.deepcopy(responses[resource])
        return read

    def test_resource_matrix_projects_only_owned_structured_enums(self):
        for kind, name, namespace, rollout in (
                ("Deployment", "ate-api-server", "ate-system", "incomplete"), ("StatefulSet", "postgres", "ate-system", "incomplete"),
                ("DaemonSet", "atelet", "ate-system", "incomplete"), ("Job", "rustfs-bucket-init", "ate-system", "failed"),
                ("WorkerPool", "substrate-smoke", "substrate-smoke", "complete")):
            with self.subTest(kind=kind):
                calls = []
                result = self.n.install_observations(kind, name, self.reader(self.shapes(kind, name), calls))
                self.assertEqual(result, {"eventReasons": ["BackOff", "FailedScheduling", "other"], "containerReasons": ["ImagePullBackOff", "OOMKilled", "other"],
                                          "containerStates": ["terminated", "waiting"], "exitCodes": [1, 137], "rolloutStatus": rollout})
                self.assertNotIn(self.SECRET, json.dumps(result))
                self.assertEqual({namespace_ for _, _, namespace_ in calls}, {namespace})
                self.assertEqual([c[0] for c in calls][0], kind.lower() + "/" + name)
                self.assertEqual("deployment/" + name in [c[0] for c in calls], kind in ("Deployment", "WorkerPool"))
                self.assertEqual("replicasets" in [c[0] for c in calls], kind in ("Deployment", "WorkerPool"))
                selector = next(c[1] for c in calls if c[0] == "pods")
                self.assertEqual(selector[0], "-l")
                self.assertEqual(selector[1], {"Job": "job-name=" + name, "WorkerPool": "ate.dev/worker-pool=" + name}.get(kind, "app=" + name))

    def test_identity_and_ownership_are_strict_and_malformed_shapes_raise(self):
        base = self.shapes("Deployment", "ate-api-server")
        for label, change in (
                ("controller-name", lambda r: r["deployment/ate-api-server"]["metadata"].update(name="other")),
                ("controller-kind", lambda r: r["deployment/ate-api-server"].update(kind="StatefulSet")),
                ("controller-api", lambda r: r["deployment/ate-api-server"].update(apiVersion="v1")),
                ("selector", lambda r: r["deployment/ate-api-server"]["spec"].update(selector={"matchLabels": {"app": "x"}})),
                ("pods", lambda r: r.update(pods={"apiVersion": "v1", "kind": "Secret", "items": []})),
                ("events", lambda r: r.update(events={"apiVersion": "v1", "kind": "EventList", "items": {}})),
                ("event-item", lambda r: r["events"]["items"].append("SECRET")),
                ("exit-list", lambda r: r["pods"]["items"][0]["status"].update(containerStatuses={})),
                ("rs", lambda r: r["replicasets"].update(items=None))):
            responses = copy.deepcopy(base)
            change(responses)
            with self.subTest(label), self.assertRaises((self.n.SafeFailure, KeyError, TypeError, AttributeError)):
                self.n.install_observations("Deployment", "ate-api-server", self.reader(responses))
        responses = self.shapes("Job", "rustfs-bucket-init")
        responses["pods"]["items"][0]["metadata"]["ownerReferences"][0]["apiVersion"] = "apps/v1"
        self.assertEqual(self.n.install_observations("Job", "rustfs-bucket-init", self.reader(responses))["containerStates"], [])
        responses = self.shapes("WorkerPool", "substrate-smoke")
        responses["deployment/substrate-smoke"]["metadata"]["ownerReferences"][0]["uid"] = "other"
        with self.assertRaises(self.n.SafeFailure):
            self.n.install_observations("WorkerPool", "substrate-smoke", self.reader(responses))

    def test_rollout_enum_requires_current_generation_and_integer_status(self):
        def deployment(**status):
            return {"metadata": {"generation": 3}, "spec": {"replicas": 2}, "status": status}
        state = self.n.rollout_state
        current = dict(observedGeneration=3, replicas=2, updatedReplicas=2, readyReplicas=2, availableReplicas=2)
        self.assertEqual(state("Deployment", deployment(**current)), "complete")
        # Ready/available counts can still describe old pods during a rollout or scale-down.
        for stale in ({"replicas": 3}, {"updatedReplicas": 1}, {"readyReplicas": 1}, {"availableReplicas": 1}, {"availableReplicas": 3}):
            self.assertEqual(state("Deployment", deployment(**{**current, **stale})), "incomplete", stale)
        self.assertEqual(state("Deployment", deployment(observedGeneration=3, readyReplicas=2)), "incomplete")
        self.assertEqual(state("Deployment", deployment(observedGeneration=3, conditions=[
            {"type": "Progressing", "status": "False", "reason": "ProgressDeadlineExceeded"}])), "failed")
        for status in ({"readyReplicas": 2}, {"observedGeneration": 2, "readyReplicas": 2}, {"observedGeneration": True, "readyReplicas": 2},
                       {"observedGeneration": 3, "readyReplicas": True}, {"observedGeneration": 3, "readyReplicas": "2"}, None, []):
            with self.subTest(status=status):
                self.assertEqual(state("Deployment", {**deployment(), "status": status}), "unknown")
        self.assertEqual(state("Deployment", {"metadata": {}, "spec": {"replicas": 2}, "status": {"observedGeneration": 3, "readyReplicas": 2}}), "unknown")
        daemon = {"observedGeneration": 1, "desiredNumberScheduled": 2, "numberReady": 2, "updatedNumberScheduled": 2, "numberAvailable": 2}
        self.assertEqual(state("DaemonSet", {"metadata": {"generation": 1}, "status": daemon}), "complete")
        for stale in ({"updatedNumberScheduled": 1}, {"numberAvailable": 1}, {"numberReady": 1}):
            self.assertEqual(state("DaemonSet", {"metadata": {"generation": 1}, "status": {**daemon, **stale}}), "incomplete", stale)
        stateful = {"observedGeneration": 1, "replicas": 1, "updatedReplicas": 1, "readyReplicas": 1, "currentRevision": "a", "updateRevision": "a"}
        self.assertEqual(state("StatefulSet", {"metadata": {"generation": 1}, "spec": {"replicas": 1}, "status": stateful}), "complete")
        for stale in ({"updateRevision": "b"}, {"updateRevision": None, "currentRevision": None}, {"updatedReplicas": 0}):
            self.assertEqual(state("StatefulSet", {"metadata": {"generation": 1}, "spec": {"replicas": 1}, "status": {**stateful, **stale}}), "incomplete", stale)
        self.assertEqual(state("Job", {"status": {"conditions": [{"type": "Complete", "status": "True"}]}}), "complete")
        self.assertEqual(state("Job", {"status": {}}), "incomplete")
        self.assertEqual(state("Job", {"status": "SECRET"}), "unknown")
        self.assertEqual(state("Job", {}), "unknown")

    def record(self, status, step="workload-rollout", kind="Deployment", name="ate-api-server", error=None, responses=None, remaining=None, **kw):
        calls = []
        responses = responses if responses is not None else self.shapes("Deployment", "ate-api-server")
        def run(args, namespace, limit):
            calls.append((args, namespace, limit))
            return json.dumps(responses[args[1]]).encode() if isinstance(responses[args[1]], dict) else responses[args[1]]
        self.n.record_install_failure(status, step, kind, name, error or ValueError(self.SECRET), run, remaining or (lambda: 100), **kw)
        return calls

    def test_first_failure_wins_and_falls_back_without_reads_or_raw_values(self):
        status = {}
        calls = self.record(status)
        self.assertEqual({k: v for k, v in status.items() if k in self.FIELDS}, {
            "eventReasons": ["BackOff", "FailedScheduling", "other"], "containerReasons": ["ImagePullBackOff", "OOMKilled", "other"],
            "containerStates": ["terminated", "waiting"], "exitCodes": [1, 137], "rolloutStatus": "incomplete"})
        self.assertEqual([c[0][:2] for c in calls], [["get", "deployment/ate-api-server"], ["get", "replicasets"], ["get", "pods"], ["get", "events"]])
        for args, namespace, limit in calls:
            self.assertEqual((args[-3], args[-2], namespace), ("-o", "json", "ate-system"))
            self.assertTrue(0 < limit <= 5 and args[-1].startswith("--request-timeout="))
        before = copy.deepcopy(status)
        self.assertEqual(self.record(status, step="cleanup", kind="other", name="other"), [])
        self.assertEqual(status, before)
        fallback = {"version": 1, "failedStep": "other", "resourceKind": "other", "resourceName": "other", "eventReasons": [],
                    "containerReasons": [], "containerStates": [], "exitCodes": [], "rolloutStatus": "unknown"}
        for label, kwargs in (("unknown-step", {"step": self.SECRET, "kind": "other", "name": "other"}),
                              ("unsupported-resource", {"kind": "Deployment", "name": self.SECRET}),
                              ("interrupt", {"error": KeyboardInterrupt()}), ("system-exit", {"error": SystemExit()}),
                              ("exhausted", {"remaining": lambda: (_ for _ in ()).throw(self.n.SafeFailure("deadline-exhausted"))}),
                              ("malformed", {"responses": {"deployment/ate-api-server": b"not-json"}}),
                              ("oversize", {"responses": {"deployment/ate-api-server": b" " * (16 * 1024 * 1024 + 1)}}),
                              ("wrong-shape", {"responses": {"deployment/ate-api-server": {"kind": "Deployment"}}})):
            status = {}
            calls = self.record(status, **kwargs)
            expected = dict(fallback, **({"failedStep": "workload-rollout", "resourceKind": "Deployment", "resourceName": "ate-api-server"}
                                         if label not in ("unknown-step", "unsupported-resource") else {}))
            if label == "unsupported-resource":
                expected["failedStep"] = "workload-rollout"
            self.assertEqual(status, expected, label)
            self.assertEqual(len(calls), {"malformed": 1, "oversize": 1, "wrong-shape": 1}.get(label, 0), label)
            self.assertNotIn(self.SECRET, json.dumps(status))

    def test_reads_share_one_five_second_budget_and_leave_no_partial_status(self):
        clock = [100.0]
        responses = self.shapes("Deployment", "ate-api-server")
        for expire_after, reads in ((1, 1), (4, 4)):
            status, calls = {}, []
            def run(args, namespace, limit, calls=calls):
                calls.append(limit)
                if len(calls) == expire_after:
                    clock[0] += 6
                return json.dumps(responses[args[1]]).encode()
            with patch.object(self.n.time, "monotonic", lambda: clock[0]):
                self.n.record_install_failure(status, "workload-rollout", "Deployment", "ate-api-server", ValueError(), run, lambda: 100)
            self.assertEqual(len(calls), reads)
            self.assertTrue(all(0 < limit <= 5 for limit in calls))
            self.assertEqual((status["containerStates"], status["rolloutStatus"]), ([], "unknown"))
            clock[0] = 100.0


class DiagnosticTests(unittest.TestCase):
    SECRET = "PRIVATE-CREDENTIAL-path-ID-command-timeout"

    def setUp(self):
        self.n = module()
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.work = self.root / "private"
        self.public = self.root / "public"
        self.work.mkdir(mode=0o700)
        self.public.mkdir(mode=0o700)
        kubeconfig = self.root / "kubeconfig"
        kubeconfig.write_text(self.SECRET)
        kubeconfig.chmod(0o600)
        pins = self.n.chart_images(ROOT)
        helper = "ghcr.io/azure/aks-durable-agents/backup-helper@sha256:" + "b" * 64
        started = time.time()
        self.env = {
            "AKS_SCENARIO_ENABLED": "true", "AKS_BUDGET_CONFIRMED": "true", "GITHUB_RUN_ID": "12", "GITHUB_RUN_ATTEMPT": "1",
            "MODEL_ENDPOINT": "https://example.invalid/openai/v1/", "MODEL_DEPLOYMENT": self.SECRET,
            "MODEL_CLIENT_ID": "55555555-5555-5555-5555-555555555555", "MODEL_PRICE_INPUT": "225000",
            "MODEL_PRICE_OUTPUT": "500000", "MODEL_PRICE_EXTRA": "0", "MODEL_PRICE_SOURCE": "https://example.invalid/prices",
            "MODEL_PRICE_AS_OF": datetime.datetime.now(datetime.timezone.utc).date().isoformat(),
            "AKS_STARTED_EPOCH": str(started), "WORK_DEADLINE_EPOCH": str(started + 1800),
            "HARD_DEADLINE_EPOCH": str(started + 2700), "KUBECONFIG": str(kubeconfig), "BACKUP_HELPER_IMAGE": helper,
            "BACKUP_HELPER_RECEIPT": json.dumps({"version": 1, "sourceCommit": "a" * 40, "hostDigest": pins["host"].split("@")[1], "image": helper}),
            "PUBLISHED_IMAGES": json.dumps({"version": 1, "sourceCommit": "a" * 40,
                "images": {role: dict(zip(("repository", "digest"), ref.split("@"))) for role, ref in pins.items()}}),
        }
        self.argv = ["--workdir", str(self.work), "--public-dir", str(self.public), "--client", str(Path(sys.executable).resolve())]

    def external(self, operation, error=None, fail_when=None, capture=None):
        # The real Scenario, install/profile, and command builders run. Only the
        # external executor is fake; no cloud, Kubernetes, Helm or model call.
        n = self.n
        pins = n.chart_images(ROOT)
        policies = [{"kind": "NetworkPolicy", "metadata": {"name": "policy-" + str(i), "uid": "uid-" + str(i)},
                     "spec": {"podSelector": {}}} for i in range(3)]
        def labels(role):
            return {"app.kubernetes.io/name": "aks-durable-agents", "app.kubernetes.io/instance": "kaimahi", "app.kubernetes.io/component": role}
        rendered = policies + [{"kind": "Deployment", "metadata": {"name": "kaimahi-aks-durable-agents-" + role, "labels": {"app.kubernetes.io/component": role}},
            "spec": {"replicas": 0, "selector": {"matchLabels": labels(role)}, "template": {"metadata": {"labels": labels(role)},
                "spec": {"containers": [{"image": image}], "serviceAccountName": "host"}}}} for role, image in pins.items()]
        nodes = [{"metadata": {"name": name, "labels": {"kubernetes.io/os": "linux", "kubernetes.io/arch": "amd64"}},
                  "status": {"conditions": [{"type": "Ready", "status": "True"}]}} for name in ("n1", "n2")]
        calls = []
        class External:
            def __init__(self, *args): pass
            def run(self, args, **kwargs):
                calls.append((args, kwargs))
                if fail_when is not None and fail_when(args, kwargs, calls):
                    raise error if error is not None else ValueError(DiagnosticTests.SECRET)
                if args[0] == "helm":
                    if "template" in args:
                        return "\n---\n".join(json.dumps(obj) for obj in rendered).encode()
                    return b""
                command = args[7:]
                if command[:1] == ["get"] and any(arg.startswith("--request-timeout=") for arg in command):
                    value = capture(command, kwargs) if callable(capture) else (capture or {}).get(command[1], {})
                    if isinstance(value, BaseException):
                        raise value
                    return value if isinstance(value, bytes) else json.dumps(value).encode()
                if command[:2] == ["get", "pod/nightly-credential"]:
                    return json.dumps({"spec": {"containers": [{"env": [
                        {"name": "AZURE_CLIENT_ID", "value": "55555555-5555-5555-5555-555555555555"},
                        {"name": "AZURE_FEDERATED_TOKEN_FILE", "value": "PRIVATE-token"}]}]}}).encode()
                if ((operation in ("host", "harness") and command[:3] == [
                        "rollout", "status", "deployment/kaimahi-aks-durable-agents-" + operation])
                        or (operation == "profile-rollout" and command[:1] == ["rollout"])
                        or (operation == "fixture-init-wait" and command[:1] == ["wait"] and "pod/nightly-prepare" in command)):
                    raise error if error is not None else ValueError(DiagnosticTests.SECRET)
                if command[:2] == ["get", "namespace"]:
                    return b""
                if command[:2] == ["get", "nodes"]:
                    return json.dumps({"items": nodes}).encode()
                if command[:2] == ["get", "daemonsets"]:
                    return b'{"items":[{"status":{"desiredNumberScheduled":2,"numberReady":2}}]}'
                if command[:2] == ["get", "pods"]:
                    return json.dumps({"items": [pod("p1", "n1"), pod("p2", "n2")]}).encode()
                if command[:2] == ["get", "networkpolicies"]:
                    return json.dumps({"items": policies}).encode()
                if command[:1] == ["get"]:
                    return b'{"items":[]}'
                return b""
        return External, calls

    def invoke(self, external):
        stderr = io.StringIO()
        with patch.dict(os.environ, self.env, clear=True), patch.object(self.n, "Executor", external), contextlib.redirect_stderr(stderr):
            result = self.n.main(self.argv)
        return result, stderr.getvalue()

    def rollout_shape(self, kind="DaemonSet", role="harness"):
        # Sanitized, hand-authored apps/v1 and core/v1 shapes, NOT historic W499 captures.
        labels = {"nightly-profile": "installer"} if kind == "DaemonSet" else {
            "app.kubernetes.io/name": "aks-durable-agents", "app.kubernetes.io/instance": "kaimahi",
            "app.kubernetes.io/component": role}
        name = "nightly-profile" if kind == "DaemonSet" else "kaimahi-aks-durable-agents-" + role
        def owner(kind, name, uid):
            return {"apiVersion": "apps/v1", "kind": kind, "name": name, "uid": uid, "controller": True}
        controller = {"apiVersion": "apps/v1", "kind": kind,
            "metadata": {"name": name, "uid": self.SECRET + "-controller"},
            "spec": {"selector": {"matchLabels": labels}},
            "status": {"numberReady": 0, "desiredNumberScheduled": 2}}
        responses = {kind.lower() + "/" + name: controller}
        pod_owner = owner(kind, name, controller["metadata"]["uid"])
        pod_labels = dict(labels)
        if kind == "Deployment":
            controller["status"] = {"replicas": 2, "updatedReplicas": 1, "readyReplicas": 0, "availableReplicas": 0,
                "conditions": [{"type": "Progressing", "status": "False", "reason": "ProgressDeadlineExceeded",
                                "message": self.SECRET}]}
            replicas = []
            for revision in ("old", "new"):
                rs_name, uid = self.SECRET + "-rs-" + revision, self.SECRET + "-rsuid-" + revision
                rs_labels = dict(labels, **{"pod-template-hash": self.SECRET + revision})
                replicas.append({"apiVersion": "apps/v1", "kind": "ReplicaSet",
                    "metadata": {"name": rs_name, "uid": uid, "labels": rs_labels, "ownerReferences": [pod_owner]},
                    "spec": {"selector": {"matchLabels": rs_labels}}})
            responses["replicasets"] = {"apiVersion": "apps/v1", "kind": "ReplicaSetList", "items": replicas}
            pod_owner = owner("ReplicaSet", replicas[0]["metadata"]["name"], replicas[0]["metadata"]["uid"])
            pod_labels["pod-template-hash"] = self.SECRET + "old"
        item = {"apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": self.SECRET + "-pod", "uid": self.SECRET + "-poduid", "labels": pod_labels,
                         "namespace": self.SECRET, "ownerReferences": [pod_owner]},
            "spec": {"nodeName": self.SECRET + "-node"},
            "status": {"phase": "Pending", "containerStatuses": [{"name": self.SECRET,
                "ready": False, "state": {"waiting": {"reason": "ImagePullBackOff", "message": self.SECRET}},
                "lastState": {}}]}}
        responses["pods"] = {"apiVersion": "v1", "kind": "PodList", "items": [item]}
        return responses, name

    def rollout_api(self, operation="profile-rollout", capture=None, error=None):
        external, calls = self.external(operation, error=error, capture=capture)
        api = self.n.Scenario(self.work, Path(sys.executable).resolve(), ROOT / "charts/aks-durable-agents",
                              self.env, executor=external())
        api.preflight()
        calls.clear()
        return api, calls

    def capture_calls(self, calls):
        return [(args, kw) for args, kw in calls if any(str(arg).startswith("--request-timeout=") for arg in args)]

    def test_real_rollout_producers_main_to_collector_and_no_private_canaries(self):
        collector = self.n.local_module("rollout_collector", ROOT / "ops/demo/e2e.py")
        for operation, kind, role in (("profile-rollout", "DaemonSet", "harness"),
                                      ("harness", "Deployment", "harness"), ("host", "Deployment", "host")):
            responses, name = self.rollout_shape(kind, role)
            if kind == "Deployment" and role == "host":
                responses["replicasets"].update(apiVersion="v1", kind="List")
            duplicate = copy.deepcopy(responses["pods"]["items"][0])
            duplicate["metadata"].update(name=self.SECRET + "-second-pod", uid=self.SECRET + "-second-uid")
            duplicate["spec"]["nodeName"] = self.SECRET + "-second-node"
            responses["pods"]["items"].append(duplicate)
            external, calls = self.external(operation, error=self.n.SafeFailure("command-failed", self.SECRET), capture=responses)
            with patch.object(self.n.Scenario, "network", return_value=[]):
                result, stderr = self.invoke(external)
            self.assertEqual(result, 1)
            report = {"version": 1, "controllerKind": kind, "controllerName": name,
                      "podReasons": ["ImagePullBackOff"], "readyNodes": 0 if kind == "DaemonSet" else None,
                      "desiredNodes": 2 if kind == "DaemonSet" else None}
            self.assertEqual(json.loads((self.public / "rollout-status.json").read_text()), report)
            diagnostics = json.loads((self.public / "diagnostics.json").read_text())
            self.assertEqual(diagnostics["operation"], "profile-rollout" if kind == "DaemonSet" else "deployment-rollout")
            self.assertEqual(diagnostics["reason"], "command-failed")
            dest = self.root / ("rollout-" + operation)
            summary = self.root / "summary.md"
            self.assertEqual(collector.collect_aks(self.public, dest, summary, "failure",
                "https://github.com/Azure/aks-durable-agents/actions/runs/123", "a" * 40, "teardown"), 0)
            self.assertEqual(json.loads((dest / "rollout-status.json").read_text()), report)
            public = stderr + summary.read_text() + "".join(p.read_text() for p in self.public.iterdir())
            public += "".join(p.read_text() for p in dest.iterdir())
            self.assertNotIn(self.SECRET, public)
            self.assertNotIn(str(self.work), public)
            gets = self.capture_calls(calls)
            self.assertEqual(len(gets), 2 if kind == "DaemonSet" else 3)
            for args, kw in gets:
                self.assertFalse(kw["cleanup"])
                self.assertTrue(0 < kw["limit"] <= 5)
                self.assertEqual(args[6], "nightly-profile" if kind == "DaemonSet" else "agents")
                if args[8] in ("pods", "replicasets"):
                    selector = args[args.index("-l") + 1]
                    self.assertNotIn(self.SECRET, selector)
                    self.assertNotIn("pod-template-hash", selector)
            rollout = next(args for args, _ in calls if args[7:10] == ["rollout", "status", kind.lower() + "/" + name])
            self.assertEqual(rollout[10:], ["--timeout=180s"])
            self.clear_work()

    def test_reason_projection_current_init_last_terminated_and_no_readiness_invention(self):
        cases = [
            ({field: [{"state": {"waiting": {"reason": reason}}}]}, [reason])
            for field in ("containerStatuses", "initContainerStatuses")
            for reason in ("ImagePullBackOff", "ErrImagePull", "CrashLoopBackOff", "CreateContainerConfigError",
                           "ContainerCreating", "FailedMount")]
        cases += [
            ({"initContainerStatuses": [{"state": {"terminated": {"reason": "OOMKilled", "message": self.SECRET}}}]}, ["OOMKilled"]),
            ({"containerStatuses": [{"state": {"waiting": {"reason": "CrashLoopBackOff"}},
                                     "lastState": {"terminated": {"reason": "OOMKilled"}}}]}, ["CrashLoopBackOff", "OOMKilled"]),
            ({"conditions": [{"type": "PodScheduled", "status": "False", "reason": "Unschedulable", "message": self.SECRET}]}, ["Unschedulable"]),
            ({"conditions": [{"type": "Ready", "status": "False", "reason": "ContainersNotReady"}],
              "containerStatuses": [{"ready": False, "state": {"running": {}}}]}, ["other"]),
            ({"containerStatuses": [{"state": {"waiting": {"reason": self.SECRET, "message": "readiness probe failing"}}}]}, ["other"]),
            ({"containerStatuses": [{"state": {"terminated": {"reason": "Error"}}}]}, ["other"]),
            ({}, ["other"]), ({"containerStatuses": "unknown-shape"}, ["other"])]
        for status, wanted in cases:
            with self.subTest(status=status):
                responses, name = self.rollout_shape()
                responses["pods"]["items"][0]["status"] = status
                api, _ = self.rollout_api(capture=responses, error=self.n.SafeFailure("command-failed"))
                with self.assertRaises(self.n.SafeFailure):
                    api.rollout("DaemonSet", name, namespace="nightly-profile")
                self.assertEqual(api.rollout_status["podReasons"], wanted)
                self.assertNotIn("readiness probe failing", api.rollout_status["podReasons"])
                self.clear_work()

    def test_capture_ownership_selector_counts_and_unknown_controller_are_conservative(self):
        mutations = [
            ("selector", lambda r: r["daemonset/nightly-profile"]["spec"]["selector"].update(matchExpressions=[{}])),
            ("controller", lambda r: r["daemonset/nightly-profile"].update(kind=self.SECRET)),
            ("controller-name", lambda r: r["daemonset/nightly-profile"]["metadata"].update(name=self.SECRET)),
            ("uid", lambda r: r["daemonset/nightly-profile"]["metadata"].pop("uid")),
            ("owner", lambda r: r["pods"]["items"][0]["metadata"]["ownerReferences"][0].update(controller=False)),
            ("api", lambda r: r["pods"]["items"][0]["metadata"]["ownerReferences"][0].update(apiVersion="v1")),
            ("foreign", lambda r: r["pods"]["items"][0]["metadata"]["ownerReferences"][0].update(uid="foreign")),
            ("labels", lambda r: r["pods"]["items"][0]["metadata"]["labels"].clear()),
            ("deleting", lambda r: r["pods"]["items"][0]["metadata"].update(deletionTimestamp="now"))]
        for label, mutate in mutations:
            responses, name = self.rollout_shape()
            mutate(responses)
            api, _ = self.rollout_api(capture=responses, error=self.n.SafeFailure("command-failed"))
            with self.assertRaises(self.n.SafeFailure):
                api.rollout("DaemonSet", name, namespace="nightly-profile")
            self.assertEqual(api.rollout_status["podReasons"], ["other"], label)
            if label in ("controller", "controller-name"):
                self.assertEqual((api.rollout_status["controllerKind"], api.rollout_status["controllerName"]), ("other", "other"))
                self.assertIsNone(api.rollout_status["readyNodes"])
            self.clear_work()
        for value in (None, True, -1, 2147483648, self.SECRET):
            responses, name = self.rollout_shape()
            responses["daemonset/" + name]["status"] = {"numberReady": value}
            api, _ = self.rollout_api(capture=responses, error=self.n.SafeFailure("command-failed"))
            with self.assertRaises(self.n.SafeFailure):
                api.rollout("DaemonSet", name, namespace="nightly-profile")
            self.assertIsNone(api.rollout_status["readyNodes"])
            self.assertIsNone(api.rollout_status["desiredNodes"])
            self.clear_work()
        api, calls = self.rollout_api(error=self.n.SafeFailure("command-failed"))
        with self.assertRaises(self.n.SafeFailure):
            api.rollout("DaemonSet", self.SECRET)
        self.assertEqual(api.rollout_status, {"version": 1, "controllerKind": "other", "controllerName": "other",
            "podReasons": ["other"], "readyNodes": None, "desiredNodes": None})
        self.assertEqual(self.capture_calls(calls), [])

    def test_deployment_all_owned_revisions_but_not_foreign_rs_or_pods(self):
        responses, name = self.rollout_shape("Deployment")
        pods = responses["pods"]["items"]
        newer = copy.deepcopy(pods[0])
        rs = responses["replicasets"]["items"][1]
        newer["metadata"]["ownerReferences"][0].update(name=rs["metadata"]["name"], uid=rs["metadata"]["uid"])
        newer["metadata"]["labels"]["pod-template-hash"] = self.SECRET + "new"
        newer["status"]["containerStatuses"][0]["state"]["waiting"]["reason"] = "CrashLoopBackOff"
        pods.append(newer)
        foreign = copy.deepcopy(newer)
        foreign["metadata"]["ownerReferences"][0]["uid"] = "not-owned"
        foreign["status"]["containerStatuses"][0]["state"]["waiting"]["reason"] = "ErrImagePull"
        pods.append(foreign)
        api, _ = self.rollout_api("harness", responses, self.n.SafeFailure("command-failed"))
        with self.assertRaises(self.n.SafeFailure):
            api.rollout("Deployment", name)
        self.assertEqual(api.rollout_status["podReasons"], ["CrashLoopBackOff", "ImagePullBackOff"])
        self.clear_work()
        responses, name = self.rollout_shape("Deployment")
        responses["replicasets"]["items"][0]["metadata"]["ownerReferences"][0]["uid"] = "not-deployment"
        api, _ = self.rollout_api("harness", responses, self.n.SafeFailure("command-failed"))
        with self.assertRaises(self.n.SafeFailure):
            api.rollout("Deployment", name)
        self.assertEqual(api.rollout_status["podReasons"], ["other"])
        self.clear_work()
        for api_version, list_kind, item_version, wanted in (
                ("v1", "List", "apps/v1", ["ImagePullBackOff"]),
                ("apps/v1", "List", "apps/v1", ["other"]),
                ("v1", "ReplicaSetList", "apps/v1", ["other"]),
                ("apps/v1", "ReplicaSetList", "apps/v2", ["other"])):
            responses, name = self.rollout_shape("Deployment")
            responses["replicasets"].update(apiVersion=api_version, kind=list_kind)
            responses["replicasets"]["items"][0]["apiVersion"] = item_version
            api, _ = self.rollout_api("harness", responses, self.n.SafeFailure("command-failed"))
            with self.assertRaises(self.n.SafeFailure):
                api.rollout("Deployment", name)
            self.assertEqual(api.rollout_status["podReasons"], wanted, (api_version, list_kind, item_version))
            self.clear_work()

    def test_only_original_command_failed_gets_capture_and_success_restores_operation(self):
        for error in (self.n.SafeFailure("command-timeout"), self.n.SafeFailure("interrupted"),
                      self.n.SafeFailure("deadline-exhausted"), self.n.SafeFailure("unknown"), KeyboardInterrupt(), OSError()):
            api, calls = self.rollout_api(error=error)
            with self.assertRaises(type(error)) as raised:
                api.rollout("DaemonSet", "nightly-profile", namespace="nightly-profile")
            self.assertIs(raised.exception, error)
            self.assertEqual(self.capture_calls(calls), [])
            self.assertEqual(api.rollout_status["podReasons"], ["other"])
            self.clear_work()
        api, calls = self.rollout_api(operation=None)
        api.operation = "phase"
        api.rollout("Deployment", "kaimahi-aks-durable-agents-harness")
        self.assertEqual(api.operation, "phase")
        self.assertIsNone(api.rollout_status)
        self.assertEqual(self.capture_calls(calls), [])

    def test_capture_failures_and_interrupts_discard_partial_counts_keep_primary_and_fence(self):
        for kind, operation, fail_at in (("DaemonSet", "profile-rollout", 1), ("DaemonSet", "profile-rollout", 2),
                                         ("Deployment", "harness", 1), ("Deployment", "harness", 2), ("Deployment", "harness", 3)):
            for secondary in (KeyboardInterrupt(self.SECRET), self.n.SafeFailure("interrupted"),
                              self.n.SafeFailure("command-timeout"), OSError(self.SECRET), b"{bad-json",
                              b" " * (16 * 1024 * 1024 + 1)):
                responses, name = self.rollout_shape(kind)
                seen = []
                def capture(command, kwargs):
                    seen.append(command)
                    return secondary if len(seen) == fail_at else responses[command[1]]
                primary = self.n.SafeFailure("command-failed", self.SECRET)
                api, calls = self.rollout_api(operation, capture, primary)
                api.owned = True
                api.preflight = lambda: api.rollout(kind, name, namespace="nightly-profile" if kind == "DaemonSet" else None)
                with self.assertRaises(self.n.SafeFailure) as raised:
                    self.n.run_scenario(api)
                self.assertIs(raised.exception, primary)
                self.assertEqual(raised.exception.reason, "command-failed")
                self.assertEqual(len(seen), fail_at)
                self.assertEqual(api.rollout_status, {"version": 1, "controllerKind": kind,
                    "controllerName": name, "podReasons": ["other"], "readyNodes": None, "desiredNodes": None})
                self.assertEqual(sum("scale" in args for args, _ in calls), 2)
                self.assertEqual(api.diagnostics["reason"], "command-failed")
                self.clear_work()

    def test_capture_budget_checked_before_and_after_reads_parse_and_projection(self):
        responses, name = self.rollout_shape("Deployment")
        clock = [100.0]
        def capture(command, kwargs):
            clock[0] += 1
            return responses[command[1]]
        api, calls = self.rollout_api("harness", capture, self.n.SafeFailure("command-failed"))
        api.deadlines.remaining = lambda cleanup=False: 20
        with patch.object(self.n.time, "monotonic", lambda: clock[0]), self.assertRaises(self.n.SafeFailure):
            api.rollout("Deployment", name)
        self.assertEqual([kw["limit"] for _, kw in self.capture_calls(calls)], [5, 4, 3])
        self.assertEqual(api.rollout_status["podReasons"], ["ImagePullBackOff"])
        self.clear_work()
        for expire in ("initial-work", "after-get", "after-parse", "after-project", "work-after-get"):
            responses, name = self.rollout_shape()
            primary = self.n.SafeFailure("command-failed")
            clock = [100.0]
            def capture(command, kwargs):
                if expire == "after-get":
                    clock[0] += 6
                if expire == "work-after-get":
                    api.deadlines.remaining = lambda cleanup=False: (_ for _ in ()).throw(self.n.SafeFailure("deadline-exhausted"))
                return responses[command[1]]
            api, calls = self.rollout_api(capture=capture, error=primary)
            api.deadlines.remaining = lambda cleanup=False: .25
            if expire == "initial-work":
                api.deadlines.remaining = lambda cleanup=False: (_ for _ in ()).throw(self.n.SafeFailure("deadline-exhausted"))
            parse = self.n.strict_json
            def slow_parse(raw):
                value = parse(raw)
                if expire == "after-parse":
                    clock[0] += 6
                return value
            validate = self.n.rollout_schema.validate_rollout_status
            def slow_validate(value):
                value = validate(value)
                if expire == "after-project":
                    clock[0] += 6
                return value
            with patch.object(self.n.time, "monotonic", lambda: clock[0]), patch.object(self.n, "strict_json", slow_parse), patch.object(self.n.rollout_schema, "validate_rollout_status", slow_validate):
                with self.assertRaises(self.n.SafeFailure) as raised:
                    api.rollout("DaemonSet", name, namespace="nightly-profile")
            self.assertIs(raised.exception, primary)
            gets = self.capture_calls(calls)
            self.assertEqual(len(gets), 0 if expire == "initial-work" else 2 if expire == "after-project" else 1)
            for args, kw in gets:
                self.assertTrue(0 < kw["limit"] <= .25)
                self.assertLessEqual(float(next(x for x in args if x.startswith("--request-timeout=")).split("=")[1][:-1]), .25)
                self.assertFalse(kw["cleanup"])
            self.assertEqual(api.rollout_status["podReasons"], ["other"])
            self.assertIsNone(api.rollout_status["readyNodes"])
            self.clear_work()

    def test_rollout_capture_primary_snapshot_survives_cleanup_failure_and_separate_writes(self):
        responses, _ = self.rollout_shape("Deployment")
        external, calls = self.external("harness", error=self.n.SafeFailure("command-failed"), capture=responses)
        run = external.run
        def fail_cleanup(executor, args, **kwargs):
            if "scale" in args and kwargs.get("cleanup"):
                calls.append((args, kwargs))
                raise self.n.SafeFailure("interrupted")
            return run(executor, args, **kwargs)
        external.run = fail_cleanup
        with patch.object(self.n.Scenario, "network", return_value=[]):
            self.assertEqual(self.invoke(external)[0], 1)
        self.assertEqual(sum("scale" in args and kw.get("cleanup", False) for args, kw in calls), 2)
        self.assertEqual(json.loads((self.public / "diagnostics.json").read_text())["reason"], "command-failed")
        self.assertEqual(json.loads((self.public / "diagnostics.json").read_text())["cleanup"], "failed")
        self.assertEqual(json.loads((self.public / "rollout-status.json").read_text())["podReasons"], ["ImagePullBackOff"])
        self.clear_work()
        for broken in ("diagnostics.json", "rollout-status.json"):
            external, _ = self.external("profile-rollout", error=self.n.SafeFailure("command-failed"), capture=self.rollout_shape()[0])
            original = self.n.write_json
            def write(path, value):
                if path.name == broken:
                    raise OSError(self.SECRET)
                return original(path, value)
            with patch.object(self.n, "write_json", write):
                self.assertEqual(self.invoke(external)[0], 1)
            other = "rollout-status.json" if broken == "diagnostics.json" else "diagnostics.json"
            self.assertTrue((self.public / other).exists())
            self.clear_work()

    def test_real_main_install_profile_failure_to_real_collector(self):
        collector = self.n.local_module("diagnostic_collector", ROOT / "ops/demo/e2e.py")
        for operation in ("profile-rollout", "fixture-init-wait"):
            with self.subTest(operation=operation):
                external, calls = self.external(operation)
                result, stderr = self.invoke(external)
                self.assertEqual(result, 1)
                self.assertEqual(stderr, "aks-nightly: failed stage=install\n")
                diagnostics = {"version": 1, "phase": "install", "operation": operation,
                               "reason": "unclassified-failure", "cleanup": "succeeded"}
                self.assertEqual(json.loads((self.public / "diagnostics.json").read_text()), diagnostics)
                dest = self.root / ("collected-" + operation)
                summary = self.root / "summary.md"
                self.assertEqual(collector.collect_aks(self.public, dest, summary, "failure",
                    "https://github.com/Azure/aks-durable-agents/actions/runs/123", "a" * 40, "teardown"), 0)
                self.assertEqual(json.loads((dest / "diagnostics.json").read_text()), diagnostics)
                public = stderr + summary.read_text() + "".join(path.read_text() for path in dest.iterdir())
                self.assertNotIn(self.SECRET, public)
                self.assertNotIn(str(self.work), public)
                self.assertIn("Underlying cause: not determined", public)
                self.assertTrue(all("port-forward" not in args for args, _ in calls))
                if operation == "fixture-init-wait":
                    self.assertEqual(sum("scale" in args for args, _ in calls), 2)
                self.clear_work()

    def test_real_main_publishes_only_validated_install_status_to_real_collector(self):
        from types import SimpleNamespace
        collector = self.n.local_module("install_collector", ROOT / "ops/demo/e2e.py")
        good = {"version": 1, "failedStep": "workload-rollout", "resourceKind": "Deployment", "resourceName": "ate-api-server",
                "eventReasons": ["BackOff"], "containerReasons": ["ImagePullBackOff"], "containerStates": ["waiting"],
                "exitCodes": [137], "rolloutStatus": "incomplete"}
        original, run_url = self.n.local_module, "https://github.com/Azure/aks-durable-agents/actions/runs/123"
        argv = self.argv + ["--variant", "substrate-gvisor", "--substrate-source", "/s", "--substrate-image-map", "/m", "--substrate-tools", "/t"]
        for label, status, accepted in (("valid", good, True), ("free-text-name", dict(good, resourceName=self.SECRET), False),
                                        ("extra-field", dict(good, message=self.SECRET), False), ("bool-exit", dict(good, exitCodes=[True]), False),
                                        ("unsorted", dict(good, eventReasons=["other", "BackOff"]), False), ("empty", {}, False), ("none", None, False)):
            with self.subTest(label):
                api = SimpleNamespace(phase_name="install", operation="phase", cleanup_status="succeeded", diagnostics=None,
                                      rollout_status=None, install_status=status)
                adapter = SimpleNamespace(SubstrateScenario=lambda *args: api, run=lambda _api: (_ for _ in ()).throw(ValueError(self.SECRET)))
                load = lambda name, path: adapter if path.name == "substrate_session.py" else original(name, path)
                with patch.dict(os.environ, self.env, clear=True), patch.object(self.n, "local_module", load), \
                        contextlib.redirect_stderr(io.StringIO()) as stderr:
                    self.assertEqual(self.n.main(argv), 1)
                self.assertEqual(json.loads((self.public / "diagnostics.json").read_text())["operation"], "phase")
                self.assertEqual((self.public / "install-status.json").exists(), accepted)
                dest, summary = self.root / ("collected-" + label), self.root / "summary.md"
                self.assertEqual(collector.collect_aks(self.public, dest, summary, "failure", run_url, "a" * 40, "scenario", "aks-substrate"), 0)
                text = summary.read_text()
                self.assertIn("- Install step: workload-rollout\n" if accepted else "- Install status: unavailable\n", text)
                if accepted:
                    self.assertEqual(json.loads((dest / "install-status.json").read_text()), good)
                    self.assertIn("- Exit codes: 137\n", text)
                self.assertNotIn(self.SECRET, stderr.getvalue() + text + "".join(path.read_text() for path in dest.iterdir()))
                self.clear_work()
        external, _ = self.external("profile-rollout")
        self.assertEqual(self.invoke(external)[0], 1)
        self.assertFalse((self.public / "install-status.json").exists())

    def clear_work(self):
        for path in self.work.iterdir():
            path.rmdir() if path.is_dir() else path.unlink()
        for path in self.public.iterdir():
            path.unlink()

    def test_install_checkpoints_cover_profile_verification_removal_and_final_nodes(self):
        def kube(args, prefix):
            return args[0] == "kubectl" and args[7:7 + len(prefix)] == prefix
        def created(args, kwargs, namespace, kind):
            return kube(args, ["create"]) and args[6] == namespace and json.loads(kwargs["data"])["kind"] == kind
        cases = [
            ("profile-create", lambda args, kw, calls: created(args, kw, "nightly-profile", "Namespace")),
            ("profile-verify", lambda args, kw, calls: kube(args, ["get", "pods"]) and args[6] == "nightly-profile"),
            ("profile-verify", lambda args, kw, calls: kube(args, ["exec"])),
            ("profile-remove", lambda args, kw, calls: kube(args, ["delete", "daemonset/nightly-profile"])),
            ("profile-remove", lambda args, kw, calls: kube(args, ["get", "namespace", "nightly-profile"])),
            ("profile-node-check", lambda args, kw, calls: kube(args, ["get", "nodes"]) and sum(kube(a, ["get", "nodes"]) for a, _ in calls) == 2),
            ("namespace-create", lambda args, kw, calls: created(args, kw, "agents", "Namespace")),
            ("volume-create", lambda args, kw, calls: created(args, kw, "agents", "PersistentVolumeClaim")),
            ("chart-install", lambda args, kw, calls: args[0] == "helm" and "install" in args),
            ("policy-check", lambda args, kw, calls: kube(args, ["get", "networkpolicies"])),
            ("fixture-init-create", lambda args, kw, calls: created(args, kw, "agents", "Pod")),
            ("fixture-init-remove", lambda args, kw, calls: kube(args, ["delete", "pod/nightly-prepare"])),
        ]
        for operation, fail_when in cases:
            with self.subTest(operation=operation):
                external, _ = self.external(None, fail_when=fail_when)
                result, stderr = self.invoke(external)
                self.assertEqual(result, 1)
                self.assertEqual(stderr, "aks-nightly: failed stage=install\n")
                self.assertEqual(json.loads((self.public / "diagnostics.json").read_text()),
                    {"version": 1, "phase": "install", "operation": operation, "reason": "unclassified-failure", "cleanup": "succeeded"})
                self.clear_work()

    def test_profile_pod_readiness_and_namespace_absence_invariants_have_correct_operation(self):
        for boundary, operation in (("pods", "profile-verify"), ("namespace", "profile-remove")):
            external, _ = self.external(None)
            original_run = external.run
            def run(executor, args, **kwargs):
                result = original_run(executor, args, **kwargs)
                if args[0] == "kubectl" and args[6] == "nightly-profile" and args[7:9] == ["get", "pods"] and boundary == "pods":
                    return b'{"items":[]}'
                if args[0] == "kubectl" and args[7:10] == ["get", "namespace", "nightly-profile"] and boundary == "namespace":
                    return b"namespace/nightly-profile"
                return result
            external.run = run
            result, _ = self.invoke(external)
            self.assertEqual(result, 1)
            self.assertEqual(json.loads((self.public / "diagnostics.json").read_text()),
                {"version": 1, "phase": "install", "operation": operation, "reason": "invariant-failed", "cleanup": "succeeded"})
            self.clear_work()

    def test_main_keeps_cleanup_stderr_stage_but_publishes_primary_snapshot(self):
        external, calls = self.external("fixture-init-wait")
        original_run = external.run
        def run(executor, args, **kwargs):
            if "scale" in args:
                calls.append((args, kwargs))
                raise OSError(self.SECRET)
            return original_run(executor, args, **kwargs)
        external.run = run
        result, stderr = self.invoke(external)
        self.assertEqual(result, 1)
        self.assertEqual(stderr, "aks-nightly: cleanup also failed after stage=install\naks-nightly: failed stage=cleanup\n")
        self.assertEqual(json.loads((self.public / "diagnostics.json").read_text()),
            {"version": 1, "phase": "install", "operation": "fixture-init-wait", "reason": "unclassified-failure", "cleanup": "failed"})
        self.assertEqual(sum("scale" in args for args, _ in calls), 2)

    def test_main_initialization_failure_reports_cleanup_not_run(self):
        self.env["AKS_SCENARIO_ENABLED"] = "false"
        external, calls = self.external("profile-rollout")
        result, stderr = self.invoke(external)
        self.assertEqual(result, 1)
        self.assertEqual(stderr, "aks-nightly: failed stage=preflight\n")
        self.assertEqual(calls, [])
        self.assertEqual(json.loads((self.public / "diagnostics.json").read_text()),
            {"version": 1, "phase": "preflight", "operation": "phase", "reason": "invariant-failed", "cleanup": "not-run"})

    def test_primary_snapshot_survives_cleanup_exception_precedence_and_identity(self):
        n = self.n
        for primary in (ValueError(self.SECRET), KeyboardInterrupt(self.SECRET)):
            for cleanup in (ValueError(self.SECRET), KeyboardInterrupt(self.SECRET), RuntimeError(self.SECRET)):
                api = n.Scenario.__new__(n.Scenario)
                api.phase_name, api.phase_started, api.phases = "preflight", time.monotonic(), {}
                def preflight():
                    api.operation = "profile-rollout"
                    raise primary
                api.preflight = preflight
                def fail_cleanup():
                    self.assertEqual(api.diagnostics, {"version": 1, "phase": "preflight", "operation": "profile-rollout",
                        "reason": "interrupted" if isinstance(primary, KeyboardInterrupt) else "unclassified-failure", "cleanup": "not-run"})
                    raise cleanup
                api.cleanup = fail_cleanup
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(type(cleanup)) as raised:
                    n.run_scenario(api)
                self.assertIs(raised.exception, cleanup)
                self.assertEqual(api.phase_name, "cleanup")
                self.assertEqual(api.operation, "phase")
                self.assertEqual(api.diagnostics["phase"], "preflight")
                self.assertEqual(api.diagnostics["operation"], "profile-rollout")
                self.assertEqual(api.diagnostics["cleanup"], "failed")

    def successful_api(self):
        api = self.n.Scenario.__new__(self.n.Scenario)
        api.phase_name, api.phase_started, api.phases = "preflight", time.monotonic(), {}
        api.started = time.monotonic()
        api.preflight = api.install = api.enable = api.cleanup = lambda: None
        api.network = lambda phase: []
        parked, completed = state(), dict(state(), headSeq=8, approvalSeq=4, artifact="b" * 64 + ".json")
        inventory = [evidence(0), evidence(), evidence(), evidence(), evidence(1, 1)]
        api.evidence = lambda: inventory.pop(0)
        api.rpc = lambda name: {"park": parked, "check-parked": {"session": parked["session"], "parked": True},
            "approve": {"session": parked["session"], "approved": True},
            "continue": {"session": parked["session"], "completed": True, "artifact": completed["artifact"]}}[name]
        api.snapshot = lambda name: parked if name == "park.json" else completed
        api.restart = api.fence = api.assert_fenced = api.backup = lambda: None
        api.replay = lambda *args: None
        return api

    def test_cleanup_only_failure_has_cleanup_phase_and_default_operation(self):
        api = self.successful_api()
        primary = OSError(self.SECRET)
        def cleanup(): raise primary
        api.cleanup = cleanup
        with self.assertRaises(OSError) as raised:
            self.n.run_scenario(api)
        self.assertIs(raised.exception, primary)
        self.assertEqual(api.diagnostics, {"version": 1, "phase": "cleanup", "operation": "phase", "reason": "io-failed", "cleanup": "failed"})

    def test_main_publication_failure_retains_successful_source_fence_status(self):
        api = self.successful_api()
        # Keep the actual orchestration and cleanup; only proof publication fails.
        api.network = lambda phase: [{"phase": phase, "case": case, "stage": stage, "passed": True}
            for case in ("untrusted-ingress", "host-egress") for stage in ("control", "denial")]
        original = self.n.write_json
        def write(path, value):
            if path.name == "proof.json":
                raise OSError(self.SECRET)
            return original(path, value)
        with patch.object(self.n, "Scenario", return_value=api), patch.object(self.n, "write_json", write), contextlib.redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(self.n.main(self.argv), 1)
        self.assertEqual(stderr.getvalue(), "aks-nightly: failed stage=cleanup\n")
        self.assertEqual(json.loads((self.public / "diagnostics.json").read_text()),
            {"version": 1, "phase": "cleanup", "operation": "phase", "reason": "io-failed", "cleanup": "succeeded"})

    def test_fixed_reason_mapping_never_parses_arbitrary_messages(self):
        n = self.n
        for error, expected in ((ValueError("deadline exhausted"), "unclassified-failure"),
                                (KeyError(self.SECRET), "unclassified-failure"),
                                (json.JSONDecodeError(self.SECRET, "", 0), "unclassified-failure"),
                                (OSError(self.SECRET), "io-failed"), (KeyboardInterrupt(self.SECRET), "interrupted")):
            self.assertEqual(n.failure_reason(error), expected)
        with self.assertRaises(ValueError) as raised:
            n.require(False, self.SECRET)
        self.assertIsInstance(raised.exception, n.SafeFailure)
        self.assertEqual(raised.exception.reason, "invariant-failed")
        with self.assertRaises(ValueError) as raised:
            n.Deadlines(190, 300, lambda: 200).remaining()
        self.assertEqual(n.failure_reason(raised.exception), "deadline-exhausted")

    def test_executor_timeout_nonzero_and_cancel_are_fixed_and_kill_group(self):
        n = self.n
        for error, reason in ((subprocess.TimeoutExpired(self.SECRET, 1), "command-timeout"),
                              (KeyboardInterrupt(self.SECRET), "interrupted"), (OSError(self.SECRET), "io-failed"),
                              (None, "command-failed")):
            process = unittest.mock.Mock(returncode=1)
            process.communicate.side_effect = error
            executor = n.Executor(self.work, {}, n.Deadlines(time.time() + 30, time.time() + 40))
            with patch.object(n.subprocess, "Popen", return_value=process), patch.object(executor, "kill") as kill:
                with self.assertRaises(ValueError) as raised:
                    executor.run([self.SECRET])
            self.assertIsInstance(raised.exception, n.SafeFailure)
            self.assertEqual(n.failure_reason(raised.exception), reason)
            self.assertEqual(kill.call_count, int(error is not None))
            for path in self.work.iterdir(): path.unlink()

    def test_executor_cancel_during_fence_still_attempts_both_scales(self):
        n = self.n
        api = n.Scenario.__new__(n.Scenario)
        api.owned, api.deployments = True, {"host": "host", "harness": "harness"}
        api.prefix = ["fake-kubectl"]
        api.deadlines = n.Deadlines(time.time() + 30, time.time() + 40)
        api.executor = n.Executor(self.work, {}, api.deadlines)
        process = unittest.mock.Mock()
        process.communicate.side_effect = KeyboardInterrupt(self.SECRET)
        with patch.object(n.subprocess, "Popen", return_value=process) as popen, patch.object(api.executor, "kill") as kill:
            with self.assertRaises(ValueError):
                api.fence(cleanup=True)
        self.assertEqual(popen.call_count, 2)
        self.assertEqual(kill.call_count, 2)
        self.assertEqual([call.args[0][2] for call in popen.call_args_list], ["deployment/host", "deployment/harness"])

    def test_main_diagnostic_write_errors_second_interrupt_and_validation_failure_are_best_effort(self):
        for error in (OSError(self.SECRET), KeyboardInterrupt(self.SECRET)):
            external, calls = self.external("fixture-init-wait")
            original = self.n.write_json
            attempts = []
            def write(path, value):
                if path.name == "diagnostics.json":
                    attempts.append(path)
                    self.assertEqual(stderr.getvalue(), "aks-nightly: failed stage=install\n")
                    raise error
                return original(path, value)
            stderr = io.StringIO()
            with patch.dict(os.environ, self.env, clear=True), patch.object(self.n, "Executor", external), patch.object(self.n, "write_json", write), contextlib.redirect_stderr(stderr):
                self.assertEqual(self.n.main(self.argv), 1)
            self.assertEqual(stderr.getvalue(), "aks-nightly: failed stage=install\n")
            self.assertEqual(attempts, [self.public / "diagnostics.json"])
            self.assertEqual(sum("scale" in args for args, _ in calls), 2)
            self.assertFalse((self.public / "diagnostics.json").exists())
            self.clear_work()
        external, _ = self.external("profile-rollout")
        with patch.object(self.n, "local_module", side_effect=ValueError(self.SECRET)):
            result, stderr = self.invoke(external)
        self.assertEqual(result, 1)
        self.assertEqual(stderr, "aks-nightly: failed stage=install\n")
        self.assertFalse((self.public / "diagnostics.json").exists())

    def test_invalid_public_directory_never_receives_diagnostics(self):
        external, _ = self.external("profile-rollout")
        original = self.public
        nested = self.work / "public"
        nested.mkdir(mode=0o700)
        linked = self.root / "link"
        linked.symlink_to(original, target_is_directory=True)
        wrong_mode = self.root / "wrong-mode"
        wrong_mode.mkdir(mode=0o755)
        wrong_mode.chmod(0o755)
        nonempty = self.root / "nonempty"
        nonempty.mkdir(mode=0o700)
        (nonempty / "keep").write_text(self.SECRET)
        for path in (nested, linked, wrong_mode, nonempty, self.work, self.root / "missing"):
            self.argv[3] = str(path)
            result, stderr = self.invoke(external)
            self.assertEqual(result, 1)
            self.assertEqual(stderr, "aks-nightly: failed stage=preflight\n")
            self.assertFalse((path / "diagnostics.json").exists())
        self.assertFalse((original / "diagnostics.json").exists())

    def test_phase_change_resets_operation(self):
        api = self.n.Scenario.__new__(self.n.Scenario)
        api.phase_name, api.phase_started, api.phases = "install", time.monotonic(), {}
        api.operation = "fixture-init-remove"
        api.phase("network-dormant")
        self.assertEqual(api.operation, "phase")


class SequenceTests(unittest.TestCase):
    def setUp(self):
        self.n = module()

    def test_cleanup_failure_retains_only_safe_original_stage_context(self):
        import contextlib
        import io
        class Boundary:
            def phase(self, name):
                self.phase_name = name
            def preflight(self):
                raise ValueError("private upstream error")
            def cleanup(self):
                raise ValueError("private cleanup error")
        api = Boundary()
        with contextlib.redirect_stderr(io.StringIO()) as output, self.assertRaises(ValueError):
            self.n.run_scenario(api)
        self.assertIn("stage=preflight", output.getvalue())
        self.assertNotIn("private", output.getvalue())
        self.assertEqual(api.phase_name, "cleanup")

    def test_real_sequence_with_fake_external_api_evidence_and_source_fence(self):
        n = self.n
        class Boundary:
            def __init__(self):
                self.inventory = evidence(0)
                self.fenced = False
                self.calls = []
            def phase(self, name):
                self.calls.append(name)
            def preflight(self): pass
            def install(self): pass
            def network(self, phase):
                return [{"phase": phase, "case": case, "stage": stage, "passed": True} for case in ("untrusted-ingress", "host-egress") for stage in ("control", "denial")]
            def enable(self): pass
            def evidence(self): return copy.deepcopy(self.inventory)
            def rpc(self, name):
                self.calls.append(name)
                if name == "park": self.inventory = evidence()
                if name == "continue": self.inventory = evidence(1, 1)
                return {"park": state(), "check-parked": {"session": "session-test", "parked": True},
                        "approve": {"session": "session-test", "approved": True}, "continue": {"session": "session-test", "completed": True, "artifact": "b" * 64 + ".json"}}[name]
            def restart(self): pass
            def snapshot(self, name): return dict(state(), headSeq=8, approvalSeq=4, artifact="b" * 64 + ".json") if name == "completed.json" else state()
            def fence(self): self.fenced = True; self.calls.append("fence")
            def assert_fenced(self):
                if not self.fenced: raise ValueError("writers resumed")
                self.calls.append("assert-fenced")
            def backup(self):
                if not self.fenced: raise ValueError("unfenced backup")
                self.calls.append("backup-external")
            def replay(self, completed, final):
                if not self.fenced: raise ValueError("unfenced replay")
                self.calls.append("replay-external")
            def cleanup(self): self.fence()
        api = Boundary()
        proof, network = n.run_scenario(api)
        self.assertEqual(proof["modelCalls"], 1)
        self.assertEqual(proof["replay"], {"completed": True, "providerCalls": 0, "executorCalls": 0, "coverageComplete": True, "unchanged": True})
        self.assertEqual(len(network), 8)
        self.assertLess(api.calls.index("network-dormant"), api.calls.index("park"))
        self.assertLess(api.calls.index("fence"), api.calls.index("backup-external"))
        self.assertGreater(api.calls.index("assert-fenced", api.calls.index("backup-external")), api.calls.index("backup-external"))
        self.assertFalse(set(api.calls) & {"seal", "verify", "counter"})
        api = Boundary()
        original = api.rpc
        def corrupt(name):
            result = original(name)
            if name == "check-parked": api.inventory["realLedgerDigest"] = "e" * 64
            return result
        api.rpc = corrupt
        with self.assertRaises(ValueError): n.run_scenario(api)
        self.assertNotIn("approve", api.calls)
        self.assertTrue(api.fenced)


if __name__ == "__main__":
    unittest.main()
