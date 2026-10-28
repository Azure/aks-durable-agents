#!/usr/bin/env python3
"""Offline AKS composition of pinned Substrate; --apply installs on an owned disposable target."""
import argparse
import ipaddress
import json
import os
import re
import secrets
import signal
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import cleanup
import lifecycle
import yaml
from substrate_evidence import Evidence

SOURCE_COMMIT = "e8d40c33f96f4b7a4984bfea7334a36ab5b45b7b"
KO = "ko://github.com/agent-substrate/substrate/"
SMOKE = "substrate-smoke"
PIN = re.compile(r"[a-z0-9][a-z0-9.:-]*/[a-z0-9_./:-]+@sha256:[0-9a-f]{64}")
FILES = ("ate-system-namespace.yaml", "sandboxconfig-validation.yaml", "sandboxconfig-gvisor.yaml",
         "pod-certificate-controller.yaml", "postgres/postgres.yaml", "kind/rustfs.yaml",
         "ate-api-server.yaml", "ate-controller.yaml", "atelet.yaml", "atenet-router.yaml",
         "atenet-egress.yaml", "ate-system-networkpolicies.yaml")
SETUP = ("jwt-authority-pool", "actor-id-ca-pool", "actor-id-ca-certs", "egress-mitm-ca-pool",
         "podcertificate-controller-cas", "api-authentication-config", "api-server-env-vars")


def decode(raw):
    return json.loads(raw, object_pairs_hook=cleanup.unique_object)


def verify_source(source, run=lifecycle.command):
    if run(["git", "-C", str(source), "rev-parse", "HEAD"], timeout=15).decode().strip() != SOURCE_COMMIT:
        raise ValueError("wrong Substrate source revision")
    if run(["git", "-C", str(source), "status", "--porcelain", "--untracked-files=all"], timeout=15).strip():
        raise ValueError("Substrate checkout must be clean")


def node_scope(nodes):
    if (not isinstance(nodes, list) or not 1 <= len(nodes) <= 4 or len(set(nodes)) != len(nodes)
            or any(not isinstance(n, str) or len(n) > 253 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", n) for n in nodes)):
        raise ValueError("explicit distinct approved node names required")
    # Field selectors require singleton values; separate terms are ORed.
    return {"requiredDuringSchedulingIgnoredDuringExecution": {"nodeSelectorTerms": [
        {"matchFields": [{"key": "metadata.name", "operator": "In", "values": [node]}]}
        for node in sorted(nodes)]}}


def image_map(data):
    if not isinstance(data, dict) or set(data) != {"sourceCommit", "images"} or data["sourceCommit"] != SOURCE_COMMIT:
        raise ValueError("image map source mismatch")
    images = data["images"]
    if not isinstance(images, dict) or not images or any(not isinstance(k, str) or not isinstance(v, str) or not PIN.fullmatch(v) for k, v in images.items()):
        raise ValueError("all image-map entries require registry-qualified sha256 pins")
    return images


def replace_images(value, images):
    if isinstance(value, dict):
        for key, item in value.items():
            if key in ("image", "workerImage", "pauseImage") and isinstance(item, str):
                if item not in images:
                    raise ValueError("missing immutable source image mapping")
                value[key] = images[item]
            else:
                replace_images(item, images)
    elif isinstance(value, list):
        for item in value:
            replace_images(item, images)


def env_set(container, name, value=None, secret=None):
    env = container.setdefault("env", [])
    env[:] = [e for e in env if e["name"] != name]
    env.append({"name": name, **({"valueFrom": {"secretKeyRef": {"name": "substrate-s3", "key": secret}}} if secret else {"value": value})})


def restrict_router(docs, host):
    # Replace the upstream allow-all rule in the owned render, so reapplication
    # cannot undo an imperative post-install patch. Namespace AND pod must match.
    keys = {"app.kubernetes.io/name", "app.kubernetes.io/instance", "app.kubernetes.io/component"}
    def dns(value):
        return isinstance(value, str) and len(value) <= 63 and bool(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", value))
    if not isinstance(host, dict) or set(host) != {"namespace", "labels"} or not dns(host["namespace"]) or host["namespace"] in ("ate-system", SMOKE, "kube-system", "podcertificate-controller-system"):
        raise ValueError("exact separate host namespace required for router policy")
    labels = host["labels"]
    if not isinstance(labels, dict) or set(labels) != keys or labels["app.kubernetes.io/name"] != "aks-durable-agents" or labels["app.kubernetes.io/component"] != "host" or not dns(labels["app.kubernetes.io/instance"]):
        raise ValueError("exact host-only labels required for router policy")
    policies = [d for d in docs if d["kind"] == "NetworkPolicy" and d["metadata"].get("namespace") == "ate-system" and d["metadata"]["name"] == "atenet-router"]
    ports = [{"protocol": "TCP", "port": port} for port in ("http", "https", "connect", "connect-tls")]
    if len(policies) != 1 or policies[0]["spec"] != {"podSelector": {"matchLabels": {"app": "atenet-router"}}, "policyTypes": ["Ingress"], "ingress": [{"ports": ports}]}:
        raise ValueError("pinned router ingress policy changed")
    policies[0]["spec"]["ingress"][0]["from"] = [
        {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": host["namespace"]}}, "podSelector": {"matchLabels": dict(labels)}},
        {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": SMOKE}}, "podSelector": {"matchLabels": {"substrate.aks/probe": "counter"}}},
    ]


def render(source, mapping, nodes, *, verify=True, router_host=None):
    source = Path(source).resolve()
    if verify:
        verify_source(source)
    scope, images = node_scope(nodes), image_map(mapping)
    base = source / "manifests/ate-install"
    docs: list[dict[str, Any]] = []
    for path in [*sorted((base / "generated").glob("*.yaml")), *(base / p for p in FILES)]:
        docs.extend(d for d in yaml.safe_load_all(path.read_text()) if d)
    if router_host is not None:
        restrict_router(docs, router_host)
    docs.append({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "ate-otel-config", "namespace": "ate-system"},
                 "data": {"OTEL_TRACES_EXPORTER": "none", "OTEL_METRICS_EXPORTER": "none", "OTEL_LOGS_EXPORTER": "none", "OTEL_SDK_DISABLED": "true"}})
    docs.append({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": SMOKE}})
    docs.append({"apiVersion": "ate.dev/v1alpha1", "kind": "WorkerPool", "metadata": {"name": SMOKE, "namespace": SMOKE, "labels": {"workload": SMOKE}},
                 "spec": {"replicas": 1, "workerImage": KO + "cmd/ateom-gvisor", "sandboxClasses": [{"name": "gvisor"}],
                          "template": {"nodeSelector": {"kubernetes.io/os": "linux", "kubernetes.io/arch": "amd64"}, "nodeAffinity": scope,
                                       "resources": {"requests": {"cpu": "250m", "memory": "1Gi"}, "limits": {"cpu": "1", "memory": "1Gi"}}}}})
    template: dict[str, Any] = {"metadata": {"atespace": SMOKE, "name": "counter"}, "workerSelector": {"matchLabels": {"workload": SMOKE}},
                "containers": [{"name": "counter", "image": KO + "demos/counter", "command": ["/ko-app/counter"],
                                "wakeupProbe": {"httpGet": {"path": "/readyz", "port": 80}}, "volumeMounts": [{"name": "data", "mountPath": "/home/counter"}]}],
                "resources": {"limits": [{"name": "cpu", "quantity": "1"}, {"name": "memory", "quantity": "512Mi"}]},
                "snapshotConfig": {"preferredFidelity": "SNAPSHOT_FIDELITY_VOLUMES", "storageLocation": "s3://ate-snapshots/smoke/",
                                   "goldenSnapshotConfig": {"mode": "GOLDEN_SNAPSHOT_MODE_DISABLED"}},
                "sandboxConfig": {"sandboxClass": "gvisor", "configName": "gvisor-default"}, "volumes": [{"name": "data", "durableDir": {}}]}
    # Every source reference, including helper and dataplane images, needs an operator mapping.
    for doc in [*docs, template]:
        replace_images(doc, images)
    if "probe" not in images:
        raise ValueError("pinned Python3 probe image required")
    unique = {}
    for doc in docs:
        kind, meta = doc["kind"], doc["metadata"]
        if kind == "Secret":
            raise ValueError("source secrets must be generated, not rendered")
        if kind == "Namespace" and meta["name"] in ("ate-system", SMOKE):
            meta.setdefault("labels", {}).update({"pod-security.kubernetes.io/enforce": "privileged"})
        if kind == "PersistentVolumeClaim":
            doc["spec"].update(storageClassName="managed-csi")
            doc["spec"]["resources"]["requests"]["storage"] = "4Gi"
        if kind == "Service":
            doc["spec"]["type"] = "ClusterIP"
            if meta["name"] == "rustfs":
                doc["spec"]["ports"] = [p for p in doc["spec"]["ports"] if p.get("name") != "console"]
        if kind in ("Deployment", "DaemonSet", "StatefulSet", "Job"):
            spec = doc["spec"]
            if kind in ("Deployment", "StatefulSet"):
                spec["replicas"] = 1
            pod = spec["template"]["spec"]
            pod.setdefault("nodeSelector", {}).update({"kubernetes.io/os": "linux", "kubernetes.io/arch": "amd64"})
            pod.setdefault("affinity", {})["nodeAffinity"] = scope
            pod["volumes"] = [v for v in pod.get("volumes", []) if not v["name"].startswith("image-credential-provider")]
            for claim in spec.get("volumeClaimTemplates", []):
                claim["spec"]["storageClassName"] = "managed-csi"
                claim["spec"]["resources"]["requests"]["storage"] = "4Gi"
            for c in pod.get("containers", []) + pod.get("initContainers", []):
                c["args"] = [a for a in c.get("args", []) if not a.startswith("--image-credential-provider")]
                c["volumeMounts"] = [v for v in c.get("volumeMounts", []) if not v["name"].startswith("image-credential-provider")]
                if c["name"] == "postgres":
                    c["resources"] = {"requests": {"cpu": "100m", "memory": "256Mi"}, "limits": {"cpu": "1", "memory": "1Gi"}}
                if c["name"] == "objectstore-plugin":
                    for name, val in (("ATE_STORAGE_BACKEND", "s3"), ("AWS_REGION", "us-east-1"), ("AWS_ENDPOINT_URL", "http://rustfs.ate-system.svc:9000"), ("AWS_S3_USE_PATH_STYLE", "true")):
                        env_set(c, name, val)
                    env_set(c, "AWS_ACCESS_KEY_ID", secret="access")
                    env_set(c, "AWS_SECRET_ACCESS_KEY", secret="secret")
                for name in ("AWS_ACCESS_KEY_ID", "RUSTFS_ACCESS_KEY"):
                    if any(e["name"] == name for e in c.get("env", [])):
                        env_set(c, name, secret="access")
                for name in ("AWS_SECRET_ACCESS_KEY", "RUSTFS_SECRET_KEY"):
                    if any(e["name"] == name for e in c.get("env", [])):
                        env_set(c, name, secret="secret")
                if meta["name"] == "rustfs":
                    env_set(c, "RUSTFS_CONSOLE_ENABLE", "false")
                    c["ports"] = [p for p in c.get("ports", []) if p.get("name") != "console"]
                # No ambient GCP telemetry; anonymous gs:// gVisor asset downloads remain intact.
                env_set(c, "OTEL_SDK_DISABLED", "true")
        identity = (kind, meta.get("namespace", ""), meta["name"])
        unique.setdefault(identity, doc)
    bundle = {"sourceCommit": SOURCE_COMMIT, "manifests": list(unique.values()), "actorTemplate": template}
    rendered = json.dumps(bundle)
    if "ko://" in rendered or "${ENVOY_DATAPLANE_IMAGE}" in rendered:
        raise ValueError("unresolved image reference in rendered bundle")
    return bundle


class Client:
    def __init__(self, args, clock, run, evidence, status=None):
        self.args, self.clock, self.run, self.evidence = args, clock, run, evidence
        # Caller-owned classified first-failure snapshot; never exception text, argv or API names.
        self.status, self.where = status, ("other", "other", "other")
        self.native_result = {"status": "notReached"}
        self.cleanup_interrupted = False
        self.cleanup_state = {name: {"resource": name, "status": "notReached"}
                              for name in ("probe", "actor", "actor-template", "atespace", "workerpool", "namespace")}

    def at(self, step, kind="other", name="other"):
        self.where = (step, kind, name)

    def record(self, error):
        # Standalone installs have no public consumer; do not spend their deadline on unused reads.
        if self.status is None:
            return
        # The first classified failure wins; capture precedes cleanup and never replaces the error.
        try:
            import nightly
            nightly.record_install_failure(self.status, *self.where, error,
                lambda args, namespace, limit: self.k(*args, "-n", namespace, limit=limit), self.clock.remaining)
        except Exception:  # noqa: BLE001, S110 — optional diagnostics cannot mask the installer failure.
            pass

    def save(self, name, value):
        # Evidence errors must not mask a primary failure or skip owned cleanup.
        try:
            self.evidence.write_json(name, value)
        except Exception:  # noqa: BLE001 — final evidence cannot replace the primary failure.
            self.evidence.write_failed = True

    def call(self, executable, *args, input=None, limit=90):
        return self.run([str(executable), *args], timeout=min(limit, self.clock.remaining()), input=input)

    def k(self, *args, input=None, limit=90):
        return self.call("kubectl", "--kubeconfig", str(self.args.kubeconfig), "--context", self.args.context, *args, input=input, limit=limit)

    def get(self, *args):
        return decode(self.k("get", *args, "-o", "json"))

    def ate(self, *args, input=None):
        with setup_environment(self.args.source):
            return self.call(self.args.ate, "--kubeconfig", str(self.args.kubeconfig), "--context", self.args.context, *args, input=input)

    def create(self, doc, dry_run=False):
        return self.k("create", "-f", "-", *(["--dry-run=server"] if dry_run else []), input=json.dumps(doc).encode())

    def rollout(self, kind, namespace, name):
        self.k("rollout", "status", kind + "/" + name, "-n", namespace, "--timeout=" + str(max(1, int(min(300, self.clock.remaining())))) + "s", limit=305)


@contextmanager
def setup_environment(source):
    # Dedicated create helpers must not inherit GKE, external DB, dev-file or namespace overrides.
    saved, cwd = dict(os.environ), Path.cwd()
    try:
        for key in list(os.environ):
            if key.startswith(("ATE", "GCP", "GOOGLE", "CLOUDSDK", "KO_", "KUBECTL_", "ACTOR_JWT_", "ANTHROPIC_", "OPENAI_", "AWS_")) or key in ("KUBECONFIG", "BUCKET_NAME", "CLUSTER_NAME", "CLUSTER_LOCATION", "KIND_CLUSTER_NAME", "PROJECT_ID", "EXPECTED_JWT_ISSUER", "NO_DEV_ENV", "AZURE_CLIENT_SECRET"):
                os.environ.pop(key)
        os.environ["NO_DEV_ENV"] = "1"
        os.chdir(source)
        yield
    finally:
        os.chdir(cwd)
        os.environ.clear()
        os.environ.update(saved)


def verify_tools(client):
    for path in (client.args.ate_setup, client.args.ate):
        if path is None or not path.is_absolute() or path.is_symlink() or not path.is_file() or not os.access(path, os.X_OK):
            raise ValueError("explicit prebuilt pinned tools required")
        metadata = client.call("go", "version", "-m", str(path)).decode()
        package = "ate-setup" if path == client.args.ate_setup else "kubectl-ate"
        if ("path\tgithub.com/agent-substrate/substrate/cmd/" + package not in metadata
                or "vcs.revision=" + SOURCE_COMMIT not in metadata or "vcs.modified=false" not in metadata):
            raise ValueError("prebuilt tool provenance mismatch")
        version = client.call(path, "--version").decode()
        if path == client.args.ate and "v0.5.0" not in version:
            raise ValueError("native CLI version mismatch")


def apply_configuration(env):
    if (any(env.get(k) != "true" for k in ("AKS_SUBSTRATE_ENABLED", "AKS_BUDGET_CONFIRMED"))
            or not env.get("AZURE_CONFIG_DIR") or not Path(env["AZURE_CONFIG_DIR"]).expanduser().is_absolute()
            or not env.get("AKS_STARTED_EPOCH")):
        raise ValueError("explicit isolated apply approval and shared epoch required")
    if env.get("AKS_BOOTSTRAP_ENABLED") != "true":
        raise ValueError("explicit owned target required")
    ids = ("AZURE_TENANT_ID", "AZURE_SUBSCRIPTION_ID")
    names = ("AKS_RESOURCE_GROUP", "AKS_CLUSTER_NAME", "AKS_NODE_RESOURCE_GROUP")
    config = {key: env.get(key, "") for key in ids + names}
    if (any(not cleanup.GUID.fullmatch(config[key]) for key in ids)
            or any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,62}", config[key]) for key in names)
            or config["AKS_RESOURCE_GROUP"] == config["AKS_NODE_RESOURCE_GROUP"]):
        raise ValueError("invalid owned target identifiers")
    for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        if not re.fullmatch(r"[1-9][0-9]{0,19}", env.get(key, "")):
            raise ValueError("invalid run identity")
        config[key] = env[key]
    return config


def preflight(config, cloud, client, bundle, nodes):
    cleanup.validate(config, cloud)
    cluster = lifecycle.owned(config, cloud)
    if (cluster.get("provisioningState") != "Succeeded"
            or cleanup.timestamp(cluster["tags"]["ada-expires-at"]).timestamp() <= client.clock.now()):
        raise ValueError("owned cluster is not ready or expired")
    endpoint = cloud.run("aks", "show", "--resource-group", config["AKS_RESOURCE_GROUP"], "--name", config["AKS_CLUSTER_NAME"], "--query", "{fqdn:fqdn,privateFqdn:privateFqdn}")
    view = decode(client.k("config", "view", "--minify", "-o", "json"))
    contexts, clusters = view.get("contexts", []), view.get("clusters", [])
    if (len(contexts) != 1 or contexts[0].get("name") != client.args.context or len(clusters) != 1
            or contexts[0].get("context", {}).get("cluster") != clusters[0].get("name")):
        raise ValueError("explicit kubeconfig context not bound")
    settings = clusters[0]["cluster"]
    server = urlsplit(settings.get("server", ""))
    if (server.scheme != "https" or not server.hostname or server.hostname not in (endpoint.get("fqdn"), endpoint.get("privateFqdn"))
            or server.port not in (None, 443) or server.path not in ("", "/") or server.query or server.fragment
            or server.username or server.password or settings.get("insecure-skip-tls-verify") or settings.get("proxy-url")):
        raise ValueError("kubeconfig server does not match owned AKS FQDN")
    versions = decode(client.k("get", "--raw", "/apis/certificates.k8s.io"))["versions"]
    served = set()
    for version in ("v1", "v1beta1"):
        if any(v.get("version") == version for v in versions):
            resources = decode(client.k("get", "--raw", "/apis/certificates.k8s.io/" + version))["resources"]
            served.update(r["name"] for r in resources)
    if not {"podcertificaterequests", "clustertrustbundles"} <= served:
        raise ValueError("certificate APIs are unavailable")
    if any(d["metadata"]["name"].endswith(".ate.dev") for d in client.get("customresourcedefinitions")["items"]):
        raise ValueError("existing Substrate CRDs cannot be adopted")
    if any(".podcert.ate.dev" in d["metadata"]["name"] for d in client.get("clustertrustbundles")["items"]):
        raise ValueError("existing certificate trust cannot be adopted")
    for doc in bundle["manifests"]:
        if not doc["metadata"].get("namespace") and doc["kind"] not in ("CustomResourceDefinition", "SandboxConfig"):
            present = client.k("get", doc["kind"], doc["metadata"]["name"], "--ignore-not-found", "-o", "json")
            if present.strip():
                raise ValueError("existing cluster-scoped runtime object cannot be adopted")
    inventory = {n["metadata"]["name"]: n for n in client.get("nodes")["items"]}
    for name in nodes:
        node = inventory.get(name, {})
        labels = node.get("metadata", {}).get("labels", {})
        if (labels.get("kubernetes.io/os") != "linux" or labels.get("kubernetes.io/arch") != "amd64"
                or node.get("spec", {}).get("unschedulable") or node.get("spec", {}).get("taints")
                or not any(c.get("type") == "Ready" and c.get("status") == "True" for c in node.get("status", {}).get("conditions", []))):
            raise ValueError("approved node is not available Linux amd64")
        if node.get("status", {}).get("nodeInfo", {}).get("kubeletVersion") != "v" + lifecycle.VERSION:
            raise ValueError("approved kubelet must match the reviewed Kubernetes version")
    if client.get("storageclass/managed-csi").get("provisioner") != "disk.csi.azure.com":
        raise ValueError("Azure Disk CSI storage class required")
    # Schema/admission validation has no persistent effect. Existing default namespace is not adopted.
    client.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "substrate-certificate-preflight", "namespace": "default"},
                   "spec": {"restartPolicy": "Never", "containers": [{"name": "check", "image": bundle["actorTemplate"]["containers"][0]["image"], "volumeMounts": [{"name": "identity", "mountPath": "/identity"}]}],
                            "volumes": [{"name": "identity", "projected": {"sources": [{"podCertificate": {"signerName": "podidentity.podcert.ate.dev/identity", "keyType": "ECDSAP256", "credentialBundlePath": "identity.pem"}}, {"clusterTrustBundle": {"signerName": "podidentity.podcert.ate.dev/identity", "labelSelector": {"matchLabels": {"podcert.ate.dev/canarying": "live"}}, "path": "ca.pem"}}]}}]}}, dry_run=True)


def running_actor(actor, nodes, client):
    status = actor.get("status", {})
    assignment = status.get("workerAssignment", {})
    if (actor.get("metadata", {}).get("atespace") != SMOKE or actor.get("metadata", {}).get("name") != "counter"
            or not actor.get("metadata", {}).get("uid") or status.get("state") != "ACTOR_STATE_RUNNING"
            or assignment.get("sandboxRuntime", {}).get("sandboxClass") != "gvisor"
            or not assignment.get("sandboxRuntime", {}).get("version") or not assignment.get("worker", {}).get("name")
            or assignment.get("workerNamespace") != SMOKE or assignment.get("workerPool") != SMOKE
            or assignment.get("nodeName") not in nodes or not assignment.get("workerPod") or not assignment.get("workerPodUid")
            or not assignment.get("workerPodIps")):
        raise ValueError("actor is not running on the owned gVisor worker")
    for address in assignment["workerPodIps"]:
        ipaddress.ip_address(address)
    pod = client.get("pod/" + assignment["workerPod"], "-n", SMOKE)
    if (pod.get("metadata", {}).get("uid") != assignment["workerPodUid"]
            or pod.get("spec", {}).get("nodeName") != assignment["nodeName"]
            or pod.get("metadata", {}).get("labels", {}).get("ate.dev/worker-pool") != SMOKE):
        raise ValueError("authoritative worker assignment differs from owned worker pod")
    return actor["metadata"]["uid"], assignment


def counter_response(raw):
    match = re.fullmatch(r"hello from: ([^ |]+) \| preserved memory count: ([0-9]+) \| preserved file counter: ([0-9]+) \| preserved rootfs counter: ([0-9]+)\n?", raw.decode())
    if not match:
        raise ValueError("counter response missing or malformed")
    ipaddress.ip_address(match[1])
    return match[1], int(match[2]), int(match[3])


def probe_pod(images, nodes):
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "counter-probe", "namespace": SMOKE, "labels": {"substrate.aks/probe": "counter"}},
            "spec": {"automountServiceAccountToken": False, "restartPolicy": "Never", "terminationGracePeriodSeconds": 5,
                     "nodeSelector": {"kubernetes.io/os": "linux", "kubernetes.io/arch": "amd64"},
                     "affinity": {"nodeAffinity": node_scope(nodes)}, "containers": [{"name": "probe", "image": images["probe"],
                     "command": ["python3", "-c", "import signal,sys,time; signal.signal(signal.SIGTERM, lambda *_: sys.exit(0)); time.sleep(600)"],
                     "resources": {"requests": {"cpu": "10m", "memory": "32Mi"}, "limits": {"cpu": "100m", "memory": "128Mi"}},
                     "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}, "runAsNonRoot": True,
                                         "runAsUser": 65532, "seccompProfile": {"type": "RuntimeDefault"}}}]}}


def run_smoke_cleanup(client, actions, primary):
    client.evidence.cleanup_started = True
    if client.cleanup_interrupted:
        return
    failed = False
    for name, action in actions:
        try:
            action()
            client.cleanup_state[name]["status"] = "passed"
        except BaseException as error:
            client.cleanup_state[name].update(status="failed", errorType=type(error).__name__)
            if isinstance(error, (KeyboardInterrupt, SystemExit)):
                client.cleanup_interrupted = True
                if primary is None:
                    client.at("cleanup")
                raise
            failed = True
    if failed and primary is None:
        client.at("cleanup")
        raise cleanup.CloudError("smoke cleanup incomplete; caller must tear down owned cluster")


def smoke(client, bundle, images, nodes):
    actions, primary = [], None
    client.at("smoke", "WorkerPool", SMOKE)
    try:
        actions.append(("atespace", lambda: client.ate("delete", "atespace", SMOKE)))
        client.ate("create", "atespace", SMOKE)
        actions.append(("actor-template", lambda: client.ate("delete", "actor-template", "counter", "-a", SMOKE)))
        client.ate("create", "actor-template", "-f", "-", input=json.dumps(bundle["actorTemplate"]).encode())
        actions.append(("actor", lambda: client.ate("delete", "actor", "counter", "-a", SMOKE, "--any-state")))
        client.ate("create", "actor", "counter", "--template", "counter", "-a", SMOKE)
        client.ate("resume", "actor", "counter", "-a", SMOKE)
        before = decode(client.ate("get", "actor", "counter", "-a", SMOKE, "-o", "json"))
        identity = running_actor(before, nodes, client)
        actions.append(("probe", lambda: client.k("delete", "pod/counter-probe", "-n", SMOKE, "--ignore-not-found", "--wait=true", "--timeout=30s")))
        client.create(probe_pod(images, nodes))
        client.k("wait", "--for=condition=Ready", "pod/counter-probe", "-n", SMOKE, "--timeout=60s")
        code = ("import urllib.request; r=urllib.request.urlopen(urllib.request.Request('http://atenet-router.ate-system.svc:80/', "
                "headers={'ate-target-actor':'substrate-smoke/counter'}), timeout=20); "
                "assert r.status == 200; print(r.read(4096).decode(),end='')")
        first, second = [counter_response(client.k("exec", "-n", SMOKE, "pod/counter-probe", "--", "python3", "-c", code)) for _ in range(2)]
        after = decode(client.ate("get", "actor", "counter", "-a", SMOKE, "-o", "json"))
        if (running_actor(after, nodes, client) != identity or first[0] != second[0]
                or first[1:] != (1, 1) or second[1:] != (2, 2)):
            raise ValueError("same actor did not advance both native counters")
        proof = {"status": "passed", "sourceCommit": SOURCE_COMMIT, "runtime": "gvisor", "requests": 2,
                 "memoryCounts": [1, 2], "fileCounts": [1, 2]}
        # Persist the verified result before finally can fail or be interrupted.
        client.evidence.write_json("native-proof.json", {**proof, "status": "nativePassed", "stableIdentity": True})
        client.native_result = {"status": "nativePassed"}
        client.save("native-result.json", client.native_result)
        return {**proof, "smokeCleanup": "passed"}
    except BaseException as error:
        primary = error
        client.record(error)
        client.native_result = {"status": "failed", "errorType": type(error).__name__}
        client.save("native-result.json", client.native_result)
        raise
    finally:
        run_smoke_cleanup(client, reversed(actions), primary)


def install(args, bundle, mapping, env, *, run=lifecycle.command, cloud=None, clock=None, sleep=time.sleep, status=None):
    config = apply_configuration(env)
    clock = clock or lifecycle.Deadline(env["AKS_STARTED_EPOCH"])
    clock.remaining()
    if (args.kubeconfig is None or not args.kubeconfig.is_absolute() or args.kubeconfig.is_symlink()
            or not args.kubeconfig.is_file() or args.kubeconfig.stat().st_mode & 0o077
            or not args.context or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,252}", args.context)):
        raise ValueError("explicit private kubeconfig and context required")
    nodes, images = args.nodes.split(","), image_map(mapping)
    node_scope(nodes)
    if getattr(args, "evidence_dir", None) is None:
        raise ValueError("explicit fresh private evidence directory required")
    evidence = Evidence(args.evidence_dir, run=run)
    client = Client(args, clock, evidence.command, evidence, status)
    result, primary = {"status": "failed"}, None
    try:
        client.at("source")
        verify_source(args.source, run=lambda argv, *, timeout: client.call(*argv, limit=timeout))
        if bundle is None:
            bundle = render(args.source, mapping, nodes, verify=False)
        proof = install_runtime(args, bundle, images, nodes, client, config, cloud or lifecycle.Azure(config, clock, run=evidence.command), sleep)
        result = {"status": "passed"}
        return proof
    except BaseException as error:
        primary = error
        client.record(error)
        result["errorType"] = type(error).__name__
        raise
    finally:
        states = [a["status"] for a in client.cleanup_state.values()]
        cleanup_status = "failed" if "failed" in states else "passed" if "passed" in states else "notReached"
        client.save("cleanup.json", {"status": cleanup_status, "actions": list(client.cleanup_state.values())})
        client.save("native-result.json", client.native_result)
        if evidence.write_failed and primary is None:
            result = {"status": "failed", "errorType": "EvidenceWriteError"}
        client.save("install-result.json", result)
        evidence.close()
        if evidence.write_failed and primary is None:
            raise cleanup.CloudError("installer evidence writing failed")


def install_runtime(args, bundle, images, nodes, client, config, cloud, sleep):
    clock = client.clock
    client.at("tools")
    verify_tools(client)
    client.at("preflight")
    preflight(config, cloud, client, bundle, nodes)
    docs = bundle["manifests"]
    foundations = [d for d in docs if d["kind"] in ("Namespace", "CustomResourceDefinition")]
    client.at("foundation")
    for doc in foundations:
        client.create(doc)
    for doc in foundations:
        if doc["kind"] == "CustomResourceDefinition":
            client.k("wait", "--for=condition=Established", "crd/" + doc["metadata"]["name"], "--timeout=60s")
    workloads = ("Deployment", "DaemonSet", "StatefulSet", "Job", "WorkerPool")
    client.at("manifest")
    for doc in docs:
        if doc not in foundations and doc["kind"] not in workloads:
            client.create(doc)
    with setup_environment(args.source):
        for subcommand in SETUP:
            client.at("setup-" + subcommand)
            client.call(args.ate_setup, "--no-dev-env", "--kubeconfig", str(args.kubeconfig), "--context", args.context, "create", subcommand)
    client.at("secret")
    client.create({"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "substrate-s3", "namespace": "ate-system"}, "type": "Opaque",
                   "stringData": {"access": secrets.token_hex(16), "secret": secrets.token_urlsafe(32)}})
    for phase in (("podcertificate-controller",), ("postgres", "rustfs", "rustfs-bucket-init"), ("ate-api-server", "ate-controller", "atelet", "atenet-router", "atenet-egress")):
        selected = [d for d in docs if d["kind"] in workloads and d["metadata"]["name"] in phase]
        for doc in selected:
            client.at("workload-create", doc["kind"], doc["metadata"]["name"])
            client.create(doc)
        for doc in selected:
            client.at("workload-rollout", doc["kind"], doc["metadata"]["name"])
            if doc["kind"] == "Job":
                client.k("wait", "--for=condition=Complete", "job/" + doc["metadata"]["name"], "-n", doc["metadata"]["namespace"], "--timeout=180s", limit=185)
            else:
                client.rollout(doc["kind"].lower(), doc["metadata"]["namespace"], doc["metadata"]["name"])
        if phase[0] == "podcertificate-controller":
            client.at("trust", "Deployment", phase[0])
            required = {s + ".podcert.ate.dev:identity:primary-bundle" for s in ("podidentity", "servicedns", "postgres")}
            until = time.monotonic() + min(120, clock.remaining())
            while not required <= {b["metadata"]["name"] for b in client.get("clustertrustbundles")["items"]}:
                if time.monotonic() >= until:
                    raise ValueError("certificate trust not ready")
                sleep(min(2, clock.remaining()))
        if phase[0] == "postgres":
            client.at("database", "StatefulSet", "postgres")
            variables = {"schema": "substrate", "owner_role": "substrate_owner", "owner_user": "substrate_owner_user", "owner_password": "",
                         "readwrite_role": "substrate_readwrite", "readwrite_user": "substrate_readwrite_user", "readwrite_password": ""}
            sql = "BEGIN;\n" + (args.source / "pkg/postgressetup/setup.sql").read_text() + "\nCOMMIT;\n"
            client.k("exec", "-i", "-n", "ate-system", "postgres-0", "-c", "postgres", "--", "psql", "--no-psqlrc", "--set=ON_ERROR_STOP=1", "--username", "postgres", "--dbname", "atepg",
                     *("--set=substrate_" + key + "=" + value for key, value in variables.items()), input=sql.encode())
    pools = [d for d in docs if d["kind"] == "WorkerPool"]
    primary = None
    try:
        for pool in pools:
            client.at("workerpool", "WorkerPool", pool["metadata"]["name"])
            client.create(pool)
            # ResumeActor retries assignment conflicts, not an empty pool during rollout.
            client.k("wait", "--for=jsonpath={.status.readyReplicas}=1", "workerpool/" + pool["metadata"]["name"],
                     "-n", pool["metadata"]["namespace"], "--timeout=180s", limit=185)
        return smoke(client, bundle, images, nodes)
    except BaseException as error:
        primary = error
        client.record(error)
        raise
    finally:
        actions = [(kind, lambda kind=kind: client.k("delete", kind + "/" + SMOKE, "-n", SMOKE, "--ignore-not-found", "--wait=true", "--timeout=30s"))
                   for kind in ("workerpool", "namespace")]
        run_smoke_cleanup(client, actions, primary)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--image-map", required=True, type=Path)
    parser.add_argument("--nodes", required=True, help="comma-separated approved existing Linux amd64 nodes")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--evidence-dir", type=Path, help="new private evidence directory (required with --apply; parent must exist)")
    parser.add_argument("--kubeconfig", type=Path)
    parser.add_argument("--context")
    parser.add_argument("--ate-setup", type=Path)
    parser.add_argument("--ate", type=Path)
    args = parser.parse_args(argv)
    previous_term = signal.signal(signal.SIGTERM, lifecycle.interrupt)
    try:
        mapping = decode(args.image_map.read_bytes())
        if args.apply:
            result = install(args, None, mapping, os.environ)
        else:
            result = render(args.source, mapping, args.nodes.split(","))
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except (ValueError, KeyError, TypeError, OSError, yaml.YAMLError, cleanup.CloudError, KeyboardInterrupt):
        print('{"status":"failed-closed"}', file=sys.stderr)
        return 1
    finally:
        signal.signal(signal.SIGTERM, previous_term)


if __name__ == "__main__":
    raise SystemExit(main())
