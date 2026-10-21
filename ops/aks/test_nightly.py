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

    def external(self, operation, error=None, fail_when=None):
        # The real Scenario, install/profile, and command builders run. Only the
        # external executor is fake; no cloud, Kubernetes, Helm or model call.
        n = self.n
        pins = n.chart_images(ROOT)
        policies = [{"kind": "NetworkPolicy", "metadata": {"name": "policy-" + str(i), "uid": "uid-" + str(i)},
                     "spec": {"podSelector": {}}} for i in range(3)]
        def labels(role):
            return {"app.kubernetes.io/name": "aks-durable-agents", "app.kubernetes.io/instance": "kaimahi", "app.kubernetes.io/component": role}
        rendered = policies + [{"kind": "Deployment", "metadata": {"name": role, "labels": {"app.kubernetes.io/component": role}},
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
                if ((operation == "profile-rollout" and command[:1] == ["rollout"])
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
