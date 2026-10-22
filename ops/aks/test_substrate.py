"""Offline contracts: external cloud, Kubernetes and executable boundaries are faked."""
import contextlib
import copy
import io
import json
import signal
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from typing import Any
from unittest.mock import patch

import substrate
import yaml

COMMIT = "e8d40c33f96f4b7a4984bfea7334a36ab5b45b7b"
PIN = "registry.example/substrate@sha256:" + "a" * 64
KO = "ko://github.com/agent-substrate/substrate/cmd/"


def fixture(root):
    base = root / "manifests/ate-install"
    base.mkdir(parents=True)
    objects: dict[str, list[dict[str, Any]]] = {
        "ate-system-namespace.yaml": [{"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "ate-system"}}],
        "sandboxconfig-gvisor.yaml": [{"apiVersion": "ate.dev/v1alpha1", "kind": "SandboxConfig", "metadata": {"name": "gvisor-default"}, "spec": {"sandboxClass": "gvisor", "versions": [{"pauseImage": "pause:upstream", "assets": {"amd64": {"gvisor": {"url": "gs://gvisor/pinned", "sha256": "b" * 64}}}}]}}],
        "sandboxconfig-validation.yaml": [],
        "ate-system-networkpolicies.yaml": [],
        "generated/role.yaml": [{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole", "metadata": {"name": "ate-manager-role"}}],
        "generated/ate.dev_workerpools.yaml": [{"apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinition", "metadata": {"name": "workerpools.ate.dev"}}],
    }
    for file, name, image, kind in [
        ("atelet.yaml", "atelet", KO + "atelet", "DaemonSet"),
        ("ate-api-server.yaml", "ate-api-server", KO + "ateapi", "Deployment"),
        ("ate-controller.yaml", "ate-controller", KO + "atecontroller", "Deployment"),
        ("atenet-router.yaml", "atenet-router", KO + "atenet", "Deployment"),
        ("atenet-egress.yaml", "atenet-egress", "${ENVOY_DATAPLANE_IMAGE}", "Deployment"),
        ("pod-certificate-controller.yaml", "podcertificate-controller", KO + "podcertcontroller", "Deployment"),
        ("postgres/postgres.yaml", "postgres", "postgres:upstream", "StatefulSet"),
        ("kind/rustfs.yaml", "rustfs", "rustfs:upstream", "Deployment"),
    ]:
        namespace = "podcertificate-controller-system" if name == "podcertificate-controller" else "ate-system"
        container: dict[str, Any] = {"name": name, "image": image}
        pod: dict[str, Any] = {"containers": [container], "volumes": []}
        if name in ("atelet", "ate-api-server"):
            pod["initContainers"] = [{"name": "objectstore-plugin", "image": KO + "objectstore-plugin", "env": [{"name": "ATE_STORAGE_BACKEND", "value": "gcs"}]}]
        if name == "atelet":
            pod["volumes"] = [{"name": "image-credential-provider-bin", "hostPath": {"path": "/home/kubernetes/bin"}}]
            container.update(args=["--image-credential-provider-bin-dir=/run/image-credential-provider/bin"], volumeMounts=[{"name": "image-credential-provider-bin", "mountPath": "/run/image-credential-provider/bin"}])
        if name == "rustfs":
            container["env"] = [{"name": "RUSTFS_ACCESS_KEY", "value": "rustfsadmin"}, {"name": "RUSTFS_SECRET_KEY", "value": "rustfsadmin"}, {"name": "RUSTFS_CONSOLE_ENABLE", "value": "true"}]
        spec = {"replicas": 4, "template": {"spec": pod}}
        if kind == "StatefulSet":
            spec["volumeClaimTemplates"] = [{"metadata": {"name": "data"}, "spec": {"resources": {"requests": {"storage": "500Gi"}}}}]
        objects[file] = [{"apiVersion": "apps/v1", "kind": kind, "metadata": {"name": name, "namespace": namespace}, "spec": spec}]
    for file, docs in objects.items():
        dest = base / file
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(yaml.safe_dump_all(docs))
    sql = root / "pkg/postgressetup/setup.sql"
    sql.parent.mkdir(parents=True)
    sql.write_text("SELECT 1;")
    refs = [KO + s for s in ("atelet", "ateapi", "atecontroller", "atenet", "podcertcontroller", "objectstore-plugin", "ateom-gvisor")]
    refs += ["ko://github.com/agent-substrate/substrate/demos/counter", "pause:upstream", "postgres:upstream", "rustfs:upstream", "${ENVOY_DATAPLANE_IMAGE}", "probe"]
    return {"sourceCommit": COMMIT, "images": {ref: PIN for ref in refs}}


class NodeScopeTests(unittest.TestCase):
    def test_each_approved_node_has_a_single_value_or_term(self):
        cases = [
            (["node-a"], [{"matchFields": [{"key": "metadata.name", "operator": "In", "values": ["node-a"]}]}]),
            (["node-b", "node-a"], [
                {"matchFields": [{"key": "metadata.name", "operator": "In", "values": ["node-a"]}]},
                {"matchFields": [{"key": "metadata.name", "operator": "In", "values": ["node-b"]}]},
            ]),
            (["node-c", "node-a", "node-b"], [
                {"matchFields": [{"key": "metadata.name", "operator": "In", "values": ["node-a"]}]},
                {"matchFields": [{"key": "metadata.name", "operator": "In", "values": ["node-b"]}]},
                {"matchFields": [{"key": "metadata.name", "operator": "In", "values": ["node-c"]}]},
            ]),
        ]
        for nodes, terms in cases:
            with self.subTest(nodes=nodes):
                self.assertEqual(substrate.node_scope(nodes), {
                    "requiredDuringSchedulingIgnoredDuringExecution": {"nodeSelectorTerms": terms}})


class RendererTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.images = fixture(self.root)

    def render(self, images=None):
        return substrate.render(self.root, images or self.images, ["node-b", "node-a"], verify=False)

    def test_secret_free_scoped_postgres_and_native_template(self):
        bundle = self.render()
        text = json.dumps(bundle)
        for forbidden in ("rustfsadmin", "/home/kubernetes", "image-credential-provider", "valkey", "agentsessions", "ko://"):
            self.assertNotIn(forbidden, text)
        self.assertEqual(bundle, self.render())
        byname = {d["metadata"]["name"]: d for d in bundle["manifests"]}
        scope = {"requiredDuringSchedulingIgnoredDuringExecution": {"nodeSelectorTerms": [
            {"matchFields": [{"key": "metadata.name", "operator": "In", "values": ["node-a"]}]},
            {"matchFields": [{"key": "metadata.name", "operator": "In", "values": ["node-b"]}]},
        ]}}
        for doc in bundle["manifests"]:
            spec = doc.get("spec", {})
            if doc["kind"] == "WorkerPool":
                self.assertEqual(spec["template"]["nodeAffinity"], scope)
            elif "template" in spec:
                self.assertEqual(spec["template"]["spec"]["affinity"]["nodeAffinity"], scope)
        pg = byname["postgres"]
        self.assertEqual(pg["spec"]["replicas"], 1)
        self.assertEqual(pg["spec"]["volumeClaimTemplates"][0]["spec"]["storageClassName"], "managed-csi")
        self.assertEqual(pg["spec"]["volumeClaimTemplates"][0]["spec"]["resources"]["requests"]["storage"], "4Gi")
        rust = byname["rustfs"]["spec"]["template"]["spec"]["containers"][0]
        env = {e["name"]: e for e in rust["env"]}
        self.assertEqual(env["RUSTFS_CONSOLE_ENABLE"]["value"], "false")
        self.assertEqual(env["RUSTFS_SECRET_KEY"]["valueFrom"]["secretKeyRef"], {"name": "substrate-s3", "key": "secret"})
        template = bundle["actorTemplate"]
        self.assertEqual(template["snapshotConfig"]["preferredFidelity"], "SNAPSHOT_FIDELITY_VOLUMES")
        self.assertEqual(template["snapshotConfig"]["goldenSnapshotConfig"]["mode"], "GOLDEN_SNAPSHOT_MODE_DISABLED")
        self.assertEqual(template["volumes"], [{"name": "data", "durableDir": {}}])
        pool = byname["substrate-smoke"]
        self.assertEqual(pool["spec"]["replicas"], 1)
        self.assertEqual(pool["metadata"]["labels"], template["workerSelector"]["matchLabels"])
        self.assertIn("gs://gvisor/pinned", text)

    def test_crd_image_schema_is_not_an_image_reference(self):
        path = self.root / "manifests/ate-install/generated/ate.dev_workerpools.yaml"
        docs = list(yaml.safe_load_all(path.read_text()))
        docs[0]["spec"] = {"versions": [{"schema": {"openAPIV3Schema": {"properties": {"spec": {"properties": {"workerImage": {"type": "string"}}}}}}}]}
        path.write_text(yaml.safe_dump_all(docs))
        result = self.render()
        crd = next(d for d in result["manifests"] if d["kind"] == "CustomResourceDefinition")
        self.assertEqual(crd["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["spec"]["properties"]["workerImage"], {"type": "string"})

    def test_embedded_unresolved_images_fail_without_rejecting_runtime_shell_variables(self):
        path = self.root / "manifests/ate-install/ate-controller.yaml"
        docs = list(yaml.safe_load_all(path.read_text()))
        embedded: dict[str, Any] = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "embedded", "namespace": "ate-system"},
                    "data": {"script": "echo ${CERT}"}}
        path.write_text(yaml.safe_dump_all([*docs, embedded]))
        self.assertIn("${CERT}", json.dumps(self.render()))
        for reference in ("ko://unresolved/embedded", "${ENVOY_DATAPLANE_IMAGE}"):
            embedded["data"]["script"] = reference
            path.write_text(yaml.safe_dump_all([*docs, embedded]))
            with self.subTest(reference=reference), self.assertRaisesRegex(ValueError, "unresolved image reference"):
                self.render()

    def test_invalid_images_and_nodes_fail_closed(self):
        for bad in ({}, {"sourceCommit": "f" * 40, "images": self.images["images"]}, {"sourceCommit": COMMIT, "images": {"probe": PIN}}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                substrate.render(self.root, bad, ["node-a"], verify=False)
        for value in ("registry.example/counter:latest", "ko://unresolved", "secret@sha256:bad"):
            bad = copy.deepcopy(self.images)
            bad["images"]["probe"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.render(bad)
        for nodes in ([], ["*"], ["node-a", "node-a"]):
            with self.subTest(nodes=nodes), self.assertRaises(ValueError):
                substrate.render(self.root, self.images, nodes, verify=False)

    def test_checkout_wrong_revision_or_dirty_refused(self):
        for head, dirty in (("f" * 40, b""), (COMMIT, b"?? untracked")):
            def run(args, *, head=head, dirty=dirty, **_):
                return head.encode() if "rev-parse" in args else dirty
            with self.subTest(head=head, dirty=dirty), self.assertRaises(ValueError):
                substrate.verify_source(self.root, run)


def environment():
    return {"AKS_BOOTSTRAP_ENABLED": "true", "AKS_BUDGET_CONFIRMED": "true", "AKS_SUBSTRATE_ENABLED": "true",
            "AZURE_CONFIG_DIR": "/isolated/azure", "AZURE_CLIENT_ID": "1" * 8 + "-1111-1111-1111-" + "1" * 12,
            "AZURE_TENANT_ID": "2" * 8 + "-2222-2222-2222-" + "2" * 12,
            "AZURE_SUBSCRIPTION_ID": "3" * 8 + "-3333-3333-3333-" + "3" * 12,
            "AKS_RESOURCE_GROUP": "owned-rg", "AKS_CLUSTER_NAME": "owned-aks", "AKS_NODE_RESOURCE_GROUP": "owned-nodes",
            "AKS_IDENTITY_RESOURCE_GROUP": "identity-rg", "AKS_MODEL_IDENTITY_NAME": "model",
            "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2", "AKS_STARTED_EPOCH": "1000"}


class Cloud:
    def __init__(self, env):
        self.env = env
        self.tags = {"ada-repository-id": "1426100286", "ada-purpose": "nightly-aks", "ada-run-id": "123", "ada-run-attempt": "2", "ada-expires-at": "2099-01-01T00:00:00Z"}
        self.item = {"id": "/subscriptions/" + env["AZURE_SUBSCRIPTION_ID"] + "/resourceGroups/owned-rg/providers/Microsoft.ContainerService/managedClusters/owned-aks",
                     "name": "owned-aks", "nodeResourceGroup": "owned-nodes", "tags": self.tags,
                     "issuer": "https://westus3.oic.prod-aks.azure.com/" + env["AZURE_TENANT_ID"] + "/11111111-1111-1111-1111-111111111111/", "provisioningState": "Succeeded"}

    def account(self):
        return {"id": self.env["AZURE_SUBSCRIPTION_ID"], "tenantId": self.env["AZURE_TENANT_ID"]}

    def group(self):
        return {"tags": self.tags}

    def cluster(self):
        return self.item

    def run(self, *args, **kwargs):
        if args[:2] == ("aks", "show"):
            return {"fqdn": "owned.example.test", "privateFqdn": None}
        raise AssertionError((args, kwargs))


class Boundary:
    """Strict fake of executable I/O, not the installer pipeline."""
    def __init__(self):
        self.calls = []
        self.server = "https://owned.example.test:443"
        self.collision = False
        self.certificates = True
        self.node_ready = True
        self.node_version = "v1.37.0"
        self.runtime = "gvisor"
        self.response = "hello from: 10.10.0.2 | preserved memory count: {n} | preserved file counter: {n} | preserved rootfs counter: {n}\n"
        self.request = 0
        self.fail = None
        self.trust_ready = False

    def __call__(self, args, *, timeout, input=None, stderr_sink=None):
        if stderr_sink:
            stderr_sink(b"")
        self.calls.append((args, input, timeout))
        if self.fail and self.fail(args):
            raise substrate.cleanup.CloudError("external boundary failure")
        if args[0] == "git":
            return COMMIT.encode() if "rev-parse" in args else b""
        if args[:3] == ["go", "version", "-m"]:
            return ("path\tgithub.com/agent-substrate/substrate/cmd/" + Path(args[3]).name + "\n\tbuild\tvcs.revision=" + COMMIT + "\n\tbuild\tvcs.modified=false\n").encode()
        if "--version" in args:
            return b"tool version v0.5.0"
        if Path(args[0]).name == "ate-setup":
            if "create" not in args or args[args.index("create") + 1] not in substrate.SETUP:
                raise AssertionError(args)
            if "podcertificate-controller-cas" in args:
                self.trust_ready = True
            return b""
        if Path(args[0]).name == "kubectl-ate":
            if "get" in args:
                return json.dumps({"metadata": {"name": "counter", "atespace": "substrate-smoke", "uid": "actor-uid"},
                                   "status": {"state": "ACTOR_STATE_RUNNING", "workerAssignment": {"worker": {"name": "worker"}, "workerNamespace": "substrate-smoke", "workerPool": "substrate-smoke", "workerPod": "worker-pod", "workerPodUid": "pod-uid", "workerPodIps": ["10.0.0.3"], "nodeName": "node-a", "sandboxRuntime": {"sandboxClass": self.runtime, "version": "v3"}}}}).encode()
            return b""
        if args[0] != "kubectl" or "--context" not in args or "--kubeconfig" not in args:
            raise AssertionError(args)
        if "config" in args:
            return json.dumps({"contexts": [{"name": "selected", "context": {"cluster": "cluster"}}], "clusters": [{"name": "cluster", "cluster": {"server": self.server}}]}).encode()
        if "--raw" in args:
            path = args[args.index("--raw") + 1]
            if path.endswith("certificates.k8s.io"):
                return b'{"versions":[{"version":"v1"}]}'
            resources = ["podcertificaterequests", "clustertrustbundles"] if self.certificates else []
            return json.dumps({"resources": [{"name": r} for r in resources]}).encode()
        if "get" in args:
            target = args[args.index("get") + 1]
            if target == "nodes":
                return json.dumps({"items": [{"metadata": {"name": "node-a", "labels": {"kubernetes.io/os": "linux", "kubernetes.io/arch": "amd64"}}, "spec": {}, "status": {"conditions": [{"type": "Ready", "status": "True" if self.node_ready else "False"}], "nodeInfo": {"kubeletVersion": self.node_version}}}]}).encode()
            if target == "storageclass/managed-csi":
                return b'{"provisioner":"disk.csi.azure.com"}'
            if target == "pod/worker-pod":
                return b'{"metadata":{"uid":"pod-uid","labels":{"ate.dev/worker-pool":"substrate-smoke"}},"spec":{"nodeName":"node-a"}}'
            if target == "clustertrustbundles":
                return json.dumps({"items": [{"metadata": {"name": s + ".podcert.ate.dev:identity:primary-bundle"}} for s in ("podidentity", "servicedns", "postgres")] if self.trust_ready else []}).encode()
            if target == "customresourcedefinitions":
                return json.dumps({"items": [{"metadata": {"name": "workerpools.ate.dev"}}] if self.collision else []}).encode()
            return b""
        if "exec" in args and "python3" in args:
            self.request += 1
            return self.response.format(n=self.request).encode()
        if any(op in args for op in ("create", "wait", "rollout", "exec", "delete")):
            return b""
        raise AssertionError(args)


class InstallerTests(RendererTests):
    def setUp(self):
        super().setUp()
        from argparse import Namespace
        self.env = environment()
        self.args = Namespace(source=self.root, nodes="node-a", kubeconfig=self.root / "kubeconfig", context="selected", ate_setup=self.root / "ate-setup", ate=self.root / "kubectl-ate", evidence_dir=self.root / "evidence")
        self.args.kubeconfig.write_text("private")
        self.args.kubeconfig.chmod(0o600)
        for tool in (self.args.ate_setup, self.args.ate):
            tool.write_text("prebuilt")
            tool.chmod(0o700)
        self.boundary = Boundary()
        self.cloud = Cloud(self.env)
        self.clock = substrate.lifecycle.Deadline(1000, now=lambda: 1001, monotonic=lambda: 1)

    def install(self, run=None):
        self.args.evidence_dir = self.root / ("evidence-" + uuid.uuid4().hex)
        return substrate.install(self.args, self.render(), self.images, self.env, run=run or self.boundary, cloud=self.cloud, clock=self.clock, sleep=lambda _: None)

    def evidence(self, name):
        return json.loads((self.args.evidence_dir / name).read_text())

    def test_probe_sigterm_exits_zero_and_only_probe_has_short_grace(self):
        probe = substrate.probe_pod({"probe": PIN}, ["node-a"])
        self.assertEqual(probe["spec"]["terminationGracePeriodSeconds"], 5)
        self.assertEqual(probe["spec"]["containers"][0]["resources"]["requests"], {"cpu": "10m", "memory": "32Mi"})
        command = probe["spec"]["containers"][0]["command"]
        p = subprocess.Popen([sys.executable, *command[1:]], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            until = time.monotonic() + 3
            while time.monotonic() < until:
                status = Path(f"/proc/{p.pid}/status").read_text()
                caught = next(line.split()[1] for line in status.splitlines() if line.startswith("SigCgt:"))
                if int(caught, 16) & (1 << (signal.SIGTERM - 1)):
                    break
                time.sleep(0.01)
            else:
                self.fail("production probe did not install a SIGTERM handler")
            p.terminate()
            p.communicate(timeout=2)
            self.assertEqual(p.returncode, 0)
        finally:
            if p.poll() is None:
                p.kill()
            p.communicate()
        self.assertNotIn("terminationGracePeriodSeconds", self.render()["manifests"][-1].get("spec", {}))

    def test_source_verification_stderr_is_kept_before_any_mutation(self):
        self.clock = substrate.lifecycle.Deadline(1000, now=lambda: 2795, monotonic=lambda: 1)
        def wrong_source(args, **kwargs):
            if args[0] == "git":
                self.assertLessEqual(kwargs["timeout"], 5)
                kwargs["stderr_sink"](b"source revision diagnostic")
                return b"wrong revision"
            return self.boundary(args, **kwargs)
        with self.assertRaisesRegex(ValueError, "source revision"):
            self.install(run=wrong_source)
        self.assertEqual((self.args.evidence_dir / "0001.stderr.txt").read_text(), "source revision diagnostic")
        self.assertEqual(self.evidence("steps.json")[0]["tool"], "git")
        self.assertEqual(self.mutations(), [])

    def test_apply_cli_defers_render_to_the_logged_installer(self):
        mapping = self.root / "images.json"
        mapping.write_text(json.dumps(self.images))
        with patch.object(substrate, "install", return_value={"status": "passed"}) as apply, \
                patch.object(substrate, "render") as render, contextlib.redirect_stdout(io.StringIO()):
            status = substrate.main(["--source", str(self.root), "--image-map", str(mapping), "--nodes", "node-a",
                                     "--apply", "--evidence-dir", str(self.args.evidence_dir)])
        self.assertEqual(status, 0)
        self.assertIsNone(apply.call_args.args[1])
        render.assert_not_called()

    def test_apply_renders_only_after_logged_source_verification(self):
        proof = substrate.install(self.args, None, self.images, self.env, run=self.boundary,
                                  cloud=self.cloud, clock=self.clock, sleep=lambda _: None)
        self.assertEqual(proof["status"], "passed")
        self.assertEqual([s["operation"] for s in self.evidence("steps.json")[:2]], ["rev-parse", "status"])

    def test_native_proof_is_complete_before_first_cleanup_command(self):
        boundary, observed = self.boundary, []
        def run(args, **kwargs):
            if "delete" in args and "pod/counter-probe" in args:
                proof = self.evidence("native-proof.json")
                self.assertEqual(proof["status"], "nativePassed")
                self.assertEqual(proof["memoryCounts"], [1, 2])
                self.assertEqual(proof["fileCounts"], [1, 2])
                self.assertTrue(proof["stableIdentity"])
                self.assertNotIn("smokeCleanup", proof)
                observed.append(True)
            return boundary(args, **kwargs)
        self.assertEqual(self.install(run=run)["status"], "passed")
        self.assertEqual(observed, [True])
        self.assertEqual(self.evidence("cleanup.json")["status"], "passed")

    def test_cleanup_failure_keeps_proof_and_separate_failed_cleanup(self):
        self.boundary.fail = lambda a: "delete" in a and "actor-template" in a
        with self.assertRaises(substrate.cleanup.CloudError):
            self.install()
        self.assertEqual(self.evidence("native-proof.json")["status"], "nativePassed")
        result = self.evidence("cleanup.json")
        self.assertEqual(result["status"], "failed")
        actions = {a["resource"]: a["status"] for a in result["actions"]}
        self.assertEqual(actions["actor-template"], "failed")
        self.assertEqual(actions["atespace"], "passed")
        self.assertEqual(actions["namespace"], "passed")
        self.assertEqual(self.evidence("install-result.json")["status"], "failed")

    def test_native_failure_is_not_masked_by_both_cleanup_failures(self):
        self.boundary.response = "bad counter"
        self.boundary.fail = lambda a: "delete" in a and any(x in a for x in ("pod/counter-probe", "namespace/substrate-smoke"))
        with self.assertRaisesRegex(ValueError, "counter response"):
            self.install()
        self.assertFalse((self.args.evidence_dir / "native-proof.json").exists())
        self.assertEqual(self.evidence("native-result.json"), {"status": "failed", "errorType": "ValueError"})
        self.assertEqual(self.evidence("cleanup.json")["status"], "failed")

    def test_native_proof_write_failure_still_attempts_every_cleanup(self):
        write = substrate.Evidence.write_json
        def fail_proof(evidence, name, data):
            if name == "native-proof.json":
                raise OSError("disk unavailable")
            return write(evidence, name, data)
        with patch.object(substrate.Evidence, "write_json", fail_proof), self.assertRaises(OSError):
            self.install()
        self.assertFalse((self.args.evidence_dir / "native-proof.json").exists())
        self.assertEqual(self.evidence("native-result.json"), {"status": "failed", "errorType": "OSError"})
        self.assertTrue(all(a["status"] == "passed" for a in self.evidence("cleanup.json")["actions"]))

    def test_stderr_write_failure_during_cleanup_does_not_skip_remaining_actions(self):
        command = substrate.Evidence.command
        def fail_recording(evidence, args, **kwargs):
            result = command(evidence, args, **kwargs)
            if "delete" in args:
                evidence.write_failed = True
            return result
        with patch.object(substrate.Evidence, "command", fail_recording), self.assertRaisesRegex(substrate.cleanup.CloudError, "evidence"):
            self.install()
        self.assertEqual(self.evidence("native-proof.json")["status"], "nativePassed")
        self.assertEqual(self.evidence("cleanup.json")["status"], "passed")
        self.assertTrue(all(a["status"] == "passed" for a in self.evidence("cleanup.json")["actions"]))
        self.assertEqual(self.evidence("install-result.json"), {"status": "failed", "errorType": "EvidenceWriteError"})

    def test_primary_interrupt_still_attempts_all_owned_cleanup(self):
        calls = 0
        def interrupt(args):
            nonlocal calls
            if "exec" in args and "pod/counter-probe" in args:
                calls += 1
                if calls == 2:
                    raise KeyboardInterrupt
            return False
        self.boundary.fail = interrupt
        with self.assertRaises(KeyboardInterrupt):
            self.install()
        self.assertEqual(self.evidence("native-result.json"), {"status": "failed", "errorType": "KeyboardInterrupt"})
        self.assertTrue(all(a["status"] == "passed" for a in self.evidence("cleanup.json")["actions"]))
        self.assertFalse((self.args.evidence_dir / "native-proof.json").exists())

    def test_interrupt_during_cleanup_marks_remaining_not_reached_and_stops(self):
        def interrupt(args):
            if "delete" in args and "pod/counter-probe" in args:
                raise KeyboardInterrupt
            return False
        self.boundary.fail = interrupt
        with self.assertRaises(KeyboardInterrupt):
            self.install()
        self.assertEqual(self.evidence("native-proof.json")["status"], "nativePassed")
        actions = {a["resource"]: a["status"] for a in self.evidence("cleanup.json")["actions"]}
        self.assertEqual(actions["probe"], "failed")
        self.assertTrue(all(actions[x] == "notReached" for x in ("actor", "actor-template", "atespace", "workerpool", "namespace")))
        self.assertFalse(any("delete" in a and "workerpool/substrate-smoke" in a for a, _, _ in self.boundary.calls))

    def test_missing_evidence_directory_refuses_before_commands(self):
        self.args.evidence_dir = None
        with self.assertRaisesRegex(ValueError, "evidence"):
            substrate.install(self.args, self.render(), self.images, self.env, run=self.boundary, cloud=self.cloud, clock=self.clock)
        self.assertEqual(self.boundary.calls, [])

    def test_failed_readiness_records_not_reached_proof_and_cleanup(self):
        self.boundary.fail = lambda a: "rollout" in a
        with self.assertRaises(substrate.cleanup.CloudError):
            self.install()
        self.assertFalse((self.args.evidence_dir / "native-proof.json").exists())
        self.assertEqual(self.evidence("native-result.json")["status"], "notReached")
        self.assertEqual(self.evidence("cleanup.json")["status"], "notReached")

    def mutations(self):
        return [a for a, _, _ in self.boundary.calls if any(x in a for x in ("create", "delete", "exec", "rollout"))]

    def test_install_real_native_actor_proof_and_exact_cleanup(self):
        proof = self.install()
        self.assertEqual(proof, {"status": "passed", "sourceCommit": COMMIT, "runtime": "gvisor", "requests": 2, "memoryCounts": [1, 2], "fileCounts": [1, 2], "smokeCleanup": "passed"})
        commands = [a for a, _, _ in self.boundary.calls]
        for command in commands:
            if command[0] == "kubectl" or Path(command[0]).name in ("ate-setup", "kubectl-ate") and "--version" not in command:
                self.assertIn("--kubeconfig", command)
                self.assertIn("--context", command)
        payloads = [json.loads(i) for a, i, _ in self.boundary.calls if "create" in a and i and i.startswith(b"{")]
        secrets = [p for p in payloads if p.get("kind") == "Secret"]
        self.assertEqual(len(secrets), 1)
        self.assertNotEqual(secrets[0]["stringData"]["access"], secrets[0]["stringData"]["secret"])
        self.assertNotIn(secrets[0]["stringData"]["secret"], json.dumps(proof))
        probe = next(p for p in payloads if p.get("kind") == "Pod" and p["metadata"]["name"] == "counter-probe")
        self.assertEqual(probe["spec"]["containers"][0]["image"], PIN)
        http = [a[-1] for a in commands if "exec" in a and "python3" in a]
        self.assertEqual(len(http), 2)
        self.assertTrue(all("ate-target-actor" in s and "substrate-smoke/counter" in s for s in http))
        self.assertTrue(any("delete" in a and "actor" in a and "--any-state" in a for a in commands))
        self.assertTrue(any("delete" in a and "actor-template" in a for a in commands))
        self.assertTrue(any("delete" in a and "atespace" in a for a in commands))
        self.assertFalse(any(a[0] == "az" for a in commands))
        self.assertTrue(all(t <= 1799 for _, _, t in self.boundary.calls))

    def test_preflight_guards_before_any_mutation(self):
        cases = [("server", "https://other.example.test"), ("collision", True), ("certificates", False), ("node_ready", False), ("node_version", "v1.33.0")]
        for key, value in cases:
            with self.subTest(key=key):
                b = Boundary()
                setattr(b, key, value)
                self.boundary = b
                with self.assertRaises(ValueError):
                    self.install()
                self.assertEqual(self.mutations(), [])
        self.boundary = Boundary()
        self.cloud.tags["ada-run-attempt"] = "1"
        with self.assertRaises(ValueError):
            self.install()
        self.assertEqual(self.mutations(), [])

    def test_install_does_not_require_model_identity_or_login_client(self):
        for key in ("AZURE_CLIENT_ID", "AKS_IDENTITY_RESOURCE_GROUP", "AKS_MODEL_IDENTITY_NAME"):
            self.env.pop(key)
        self.assertEqual(self.install()["status"], "passed")

    def test_owned_target_configuration_still_rejects_invalid_identifiers(self):
        for key, value in (("AZURE_TENANT_ID", "invalid"), ("AZURE_SUBSCRIPTION_ID", ""),
                           ("AKS_CLUSTER_NAME", "*"), ("AKS_NODE_RESOURCE_GROUP", "owned-rg")):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "invalid owned target identifiers"):
                substrate.apply_configuration({**self.env, key: value})
        with self.assertRaisesRegex(ValueError, "explicit owned target required"):
            substrate.apply_configuration({**self.env, "AKS_BOOTSTRAP_ENABLED": "false"})

    def test_explicit_apply_environment_and_deadline(self):
        for key in ("AZURE_CONFIG_DIR", "AKS_SUBSTRATE_ENABLED", "AKS_BUDGET_CONFIRMED", "AKS_STARTED_EPOCH"):
            saved = self.env.pop(key)
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.install()
            self.assertEqual(self.mutations(), [])
            self.env[key] = saved
        expired = substrate.lifecycle.Deadline(1000, now=lambda: 2801, monotonic=lambda: 1)
        with self.assertRaises(substrate.cleanup.CloudError):
            substrate.install(self.args, self.render(), self.images, self.env, run=self.boundary, cloud=self.cloud, clock=expired)
        self.assertEqual(self.mutations(), [])

    def test_wrong_runtime_bad_counter_and_cleanup_failure_stay_red(self):
        for key, value in (("runtime", "microvm"), ("response", "ready"), ("response", "hello from: 10.0.0.2 | preserved memory count: 1 | preserved file counter: 1 | preserved rootfs counter: 1\n")):
            with self.subTest(key=key, value=value):
                b = Boundary()
                setattr(b, key, value)
                self.boundary = b
                with self.assertRaises(ValueError):
                    self.install()
                self.assertTrue(any("delete" in a and "atespace" in a for a, _, _ in b.calls))
        self.boundary = Boundary()
        self.boundary.fail = lambda a: "delete" in a and "actor-template" in a
        with self.assertRaises(substrate.cleanup.CloudError):
            self.install()
        self.assertTrue(any("delete" in a and "atespace" in a for a, _, _ in self.boundary.calls))

    def test_dedicated_setup_scrubs_ambient_configuration_and_restores_it(self):
        import os
        ambient = {"ATE_CONFIG": "foreign", "ATE_NAMESPACE": "other", "ATE_API_POSTGRES_READ_WRITE_CONNECTION_STRING": "foreign", "PROJECT_ID": "foreign", "ACTOR_JWT_ISSUER": "foreign", "EXPECTED_JWT_ISSUER": "foreign", "ANTHROPIC_API_KEY": "foreign", "OPENAI_API_KEY": "foreign", "AWS_SESSION_TOKEN": "foreign", "AZURE_CLIENT_SECRET": "foreign"}
        with patch.dict(os.environ, {**ambient, "AZURE_CONFIG_DIR": "/isolated/test-tenant"}):
            with substrate.setup_environment(self.root):
                self.assertFalse(any(key in os.environ for key in ambient))
                self.assertEqual(os.environ.get("AZURE_CONFIG_DIR"), "/isolated/test-tenant")
                self.assertEqual(os.environ["NO_DEV_ENV"], "1")
            self.assertTrue(all(os.environ[key] == value for key, value in ambient.items()))

    def test_native_calls_scrub_client_overrides_and_restore_environment_on_success_or_failure(self):
        import os
        ambient = {"ATE_NAMESPACE": "other", "ATE_API_SERVICE_NAME": "foreign-api", "ATE_CLIENT_SERVICE_ACCOUNT": "foreign-client"}
        for fail_resume in (False, True):
            with self.subTest(fail_resume=fail_resume):
                boundary, observed = Boundary(), []
                if fail_resume:
                    boundary.fail = lambda args: Path(args[0]).name == "kubectl-ate" and "resume" in args

                def run(args, *, boundary=boundary, observed=observed, **kwargs):
                    if Path(args[0]).name == "kubectl-ate" and "--version" not in args:
                        observed.append((args, {key: os.environ[key] for key in ambient if key in os.environ}, os.environ.get("AZURE_CONFIG_DIR")))
                    return boundary(args, **kwargs)

                def install(run=run):
                    self.args.evidence_dir = self.root / ("evidence-" + uuid.uuid4().hex)
                    return substrate.install(self.args, self.render(), self.images, self.env, run=run, cloud=self.cloud, clock=self.clock, sleep=lambda _: None)

                with patch.dict(os.environ, {**ambient, "AZURE_CONFIG_DIR": self.env["AZURE_CONFIG_DIR"]}):
                    if fail_resume:
                        with self.assertRaises(substrate.cleanup.CloudError):
                            install()
                    else:
                        self.assertEqual(install()["status"], "passed")
                    self.assertEqual({key: os.environ.get(key) for key in ambient}, ambient)
                    self.assertEqual(os.environ.get("AZURE_CONFIG_DIR"), self.env["AZURE_CONFIG_DIR"])
                self.assertTrue(observed)
                for args, overrides, profile in observed:
                    self.assertEqual(overrides, {}, args)
                    self.assertEqual(profile, self.env["AZURE_CONFIG_DIR"], args)
                for resource in ("actor", "actor-template", "atespace"):
                    self.assertTrue(any("delete" in args and resource in args for args, _, _ in observed), resource)

    def test_pool_readiness_timeout_prevents_actor_creation_and_cleans_pool(self):
        self.boundary.fail = lambda a: "wait" in a and "workerpool/substrate-smoke" in a
        with self.assertRaises(substrate.cleanup.CloudError):
            self.install()
        commands = [a for a, _, _ in self.boundary.calls]
        self.assertFalse(any(Path(a[0]).name == "kubectl-ate" and "create" in a for a in commands))
        self.assertTrue(any("delete" in a and "workerpool/substrate-smoke" in a for a in commands))

    def test_failed_readiness_does_not_reach_actor_proof(self):
        self.boundary.fail = lambda a: "rollout" in a
        with self.assertRaises(substrate.cleanup.CloudError):
            self.install()
        self.assertFalse(any(Path(a[0]).name == "kubectl-ate" and "create" in a for a, _, _ in self.boundary.calls))

    def test_tool_dirty_provenance_rejected_before_mutation(self):
        original = self.boundary
        def dirty(args, **kwargs):
            result = original(args, **kwargs)
            return result.replace(b"vcs.modified=false", b"vcs.modified=true")
        with self.assertRaises(ValueError):
            substrate.install(self.args, self.render(), self.images, self.env, run=dirty, cloud=self.cloud, clock=self.clock)
        self.assertEqual(self.mutations(), [])


if __name__ == "__main__":
    unittest.main()
