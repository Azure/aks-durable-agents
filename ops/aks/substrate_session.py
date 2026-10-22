"""Explicit actor adapter for the manual-only Sessions/Substrate scenario."""
import copy
import ipaddress
import json
import re
import socket
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

import nightly
import substrate
from substrate_evidence import Evidence

APP = "substrate-sessions"
PROBES = "agents-probes"
FIELDS = {"atespace", "actor", "actorUID", "templateAtespace", "template", "worker", "namespace", "pool", "pod", "podUID", "node", "runtime", "runtimeSchema", "runtimeDigest"}
require = nightly.require


def placement(document, session, nodes, pod):
    require(type(document) is dict and document.keys() == {"version", "first", "latest"} and type(document["version"]) is int and document["version"] == 1)
    first, latest = document["first"], document["latest"]
    for p in (first, latest):
        require(type(p) is dict and p.keys() == FIELDS)
        require(all(type(v) is str and 0 < len(v) <= 253 and not re.search(r"[\s\x00]", v) for v in p.values()))
        require(p["atespace"] == p["templateAtespace"] == p["namespace"] == p["pool"] == APP and p["actor"] == session and p["template"] == "release-notes" and p["runtime"] == "gvisor" and p["node"] in nodes and nightly.hex_digest(p["runtimeDigest"]))
    require(all(first[k] == latest[k] for k in ("atespace", "actor", "actorUID", "templateAtespace", "template")), "controlled actor replaced")
    require(pod.get("metadata", {}).get("uid") == latest["podUID"] and pod.get("spec", {}).get("nodeName") == latest["node"] and pod.get("metadata", {}).get("labels", {}).get("ate.dev/worker-pool") == APP, "worker identity differs from native placement")
    return latest


def held_checkpoint(actor, checkpoint, first):
    require(type(checkpoint) is dict and checkpoint.keys() == {"version", "actor", "uri", "memory"} and type(checkpoint["version"]) is int and checkpoint["version"] == 1 and checkpoint["memory"] is False)
    require(checkpoint["actor"] == first["actor"] and type(checkpoint["uri"]) is str and checkpoint["uri"].startswith("s3://"))
    meta, status = actor.get("metadata", {}), actor.get("status", {})
    require(meta.get("atespace") == APP and meta.get("name") == first["actor"] and meta.get("uid") == first["actorUID"] and actor.get("actorTemplate") == {"atespace": APP, "name": "release-notes"})
    require(status.get("state") == "ACTOR_STATE_SUSPENDED", "park does not prove suspended compute")
    snapshots = status.get("snapshots", [])
    require(isinstance(snapshots, list) and snapshots)
    require(all(type(s.get("generation")) is int and s["generation"] >= 0 for s in snapshots))
    newest = max(snapshots, key=lambda s: s["generation"])
    stored = newest.get("durableSnapshot", {})
    require(newest.get("fidelity") == "SNAPSHOT_FIDELITY_VOLUMES" and stored.get("status") == "SNAPSHOT_STORAGE_STATUS_COMPLETED" and stored.get("object", {}).get("snapshotUri") == checkpoint["uri"], "held newest VOLUMES checkpoint mismatch")


def application_bundle(bundle, image):
    require(type(image) is str and re.fullmatch(r"[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}", image), "immutable actor harness image required")
    pool = copy.deepcopy(next(d for d in bundle["manifests"] if d["kind"] == "WorkerPool"))
    pool["metadata"] = {"name": APP, "namespace": APP, "labels": {"workload": APP}}
    template = copy.deepcopy(bundle["actorTemplate"])
    template.update(metadata={"atespace": APP, "name": "release-notes"}, workerSelector={"matchLabels": {"workload": APP}},
        containers=[{"name": "harness", "image": image, "command": ["/session-fixture", "actor-harness"], "volumeMounts": [{"name": "data", "mountPath": "/durable"}]}],
        resources={"limits": [{"name": "cpu", "quantity": "1"}, {"name": "memory", "quantity": "1Gi"}]},
        snapshotConfig={"preferredFidelity": "SNAPSHOT_FIDELITY_VOLUMES", "storageLocation": "s3://ate-snapshots/sessions/", "goldenSnapshotConfig": {"mode": "GOLDEN_SNAPSHOT_MODE_DISABLED"}})
    return pool, template


def cleanup_actions(actions, evidence, primary):
    states = [{"action": name, "status": "notReached"} for name, _ in actions]
    failed = False
    try:
        for state, (_, action) in zip(states, actions, strict=True):
            try:
                action()
                state["status"] = "passed"
            except BaseException as error:
                state["status"] = "failed"
                failed = True
                if not isinstance(error, Exception):
                    raise
    finally:
        try:
            evidence.write_json("cleanup.json", {"status": "failed" if failed else "passed", "actions": states})
        except Exception:  # noqa: BLE001 — evidence cannot mask the primary or skip cleanup.
            failed = True
    if failed and primary is None:
        raise ValueError("actor cleanup/evidence failed; owned cluster teardown required")
    return not failed


def network_jobs(phase, labels, image, router, control, peer, model):
    cases = {
        "untrusted-router": (PROBES, {"nightly-probe": "actor"}, peer, router),
        "untrusted-control": (PROBES, {"nightly-probe": "actor"}, peer, control),
        "executor-router": (nightly.NAMESPACE, labels["harness"], "127.0.0.1:9000", router),
        "executor-control": (nightly.NAMESPACE, labels["harness"], "127.0.0.1:9000", control),
        "executor-model": (nightly.NAMESPACE, labels["harness"], "127.0.0.1:9000", model),
        "host-egress": (nightly.NAMESPACE, labels["host"], router, peer),
    }
    jobs = {}
    for case, (namespace, pod_labels, positive, negative) in cases.items():
        job = nightly.netpolicy.probe_job("actor-" + phase + "-" + case, pod_labels, image, positive, negative)
        spec = job["spec"]["template"]["spec"]
        spec.update(terminationGracePeriodSeconds=5, enableServiceLinks=False)
        if case.startswith("executor"):
            spec["initContainers"].insert(0, {"name": "loopback", "image": image, "restartPolicy": "Always", "securityContext": nightly.netpolicy.SECURITY,
                "command": ["python3", "-c", "import http.server,signal,sys;signal.signal(signal.SIGTERM,lambda *_:sys.exit(0));http.server.HTTPServer(('127.0.0.1',9000),http.server.BaseHTTPRequestHandler).serve_forever()"],
                "startupProbe": {"exec": {"command": ["/session-fixture", "network-probe", "--address", "127.0.0.1:9000", "--expect", "allowed"]}, "periodSeconds": 1, "failureThreshold": 20}})
        for container in spec["initContainers"] + spec["containers"]:
            container["resources"] = {"requests": {"cpu": "10m", "memory": "32Mi"}, "limits": {"cpu": "100m", "memory": "128Mi"}}
        jobs[case] = namespace, job
    return jobs


class SubstrateScenario(nightly.Scenario):
    """Map the shared flow's peer slot to the trusted executor, never a harness.

    The common restart/fence/archive invariants apply to both two-writer layouts.
    Actual actor/checkpoint proof is independent of that peer identity check.
    """
    def __init__(self, workdir, client, chart, env, source, images, tools, executor=None):
        require(env.get("AKS_SUBSTRATE_ENABLED") == "true", "explicit Substrate enablement required")
        for path in (source, images, tools):
            require(isinstance(path, Path) and path.is_absolute() and path.resolve() == path, "explicit pinned Substrate inputs required")
        super().__init__(workdir, client, chart, env, executor)
        self.source, self.tools = source, tools
        self.mapping = nightly.strict_json(images.read_bytes())
        substrate.image_map(self.mapping)
        self.values["runtime"] = {"mode": "substrate", "substrate": {"atespace": APP, "templateAtespace": APP, "template": "release-notes"}}
        self.values_path = workdir / "substrate-values.json"
        nightly.write_json(self.values_path, self.values)
        self.native_evidence = Evidence(workdir / "actor-evidence")
        self.app_attempted, self.space_attempted, self.native_cleanup_passed = False, False, False
        self.session, self.first, self.checkpoint = None, None, None
        self.native_passed = False

    def native(self, *args, data=None, cleanup=False):
        with substrate.setup_environment(self.source):
            return self.native_evidence.command([str(self.tools / "kubectl-ate"), "--kubeconfig", str(self.kubeconfig), "--context", nightly.CONTEXT, *args],
                timeout=min(90, self.deadlines.remaining(cleanup=cleanup)), input=data)

    def actor(self):
        require(self.session is not None)
        return nightly.strict_json(self.native("get", "actor", self.session, "-a", APP, "-o", "json"))

    def preflight(self):
        rendered = [d for d in nightly.yaml.safe_load_all(self.helm("template", nightly.RELEASE, self.chart, "--namespace", nightly.NAMESPACE, "--kube-version", "1.37.0", "-f", self.values_path)) if d]
        nightly.verify_bindings(self.pins, rendered, self.publication, self.receipt, self.helper, peer_role="executor")
        roles = {d["metadata"]["labels"]["app.kubernetes.io/component"]: d for d in rendered if d["kind"] == "Deployment"}
        require(set(roles) == {"host", "executor"}, "remote harness fallback or extra writer")
        for role, doc in roles.items():
            require(doc["spec"]["replicas"] == 0)
            key = "harness" if role == "executor" else role
            self.deployments[key] = doc["metadata"]["name"]
            self.labels[key] = nightly.netpolicy.policy_labels(doc["spec"]["template"])
            require(self.labels[key] == doc["spec"]["selector"]["matchLabels"])
        self.host_service_account = roles["host"]["spec"]["template"]["spec"]["serviceAccountName"]
        self.rendered_policies = {d["metadata"]["name"]: nightly.policy_spec(d["spec"]) for d in rendered if d["kind"] == "NetworkPolicy"}
        require(len(self.rendered_policies) == 2)
        for namespace in (nightly.NAMESPACE, APP, PROBES):
            require(not self.kube("get", "namespace", namespace, "--ignore-not-found", "-o", "name").strip(), "owned scenario namespace already exists")
        self.nodes = self.nodes_ready()
        self.bundle = substrate.render(self.source, self.mapping, sorted(self.nodes), router_host={"namespace": nightly.NAMESPACE, "labels": self.labels["host"]})
        self.runtime_policies = {d["metadata"]["name"]: nightly.policy_spec(d["spec"]) for d in self.bundle["manifests"] if d["kind"] == "NetworkPolicy" and d["metadata"].get("namespace") == "ate-system"}
        self.pool, self.template = application_bundle(self.bundle, self.pins["harness"])

    def install(self):
        args = SimpleNamespace(source=self.source, nodes=",".join(sorted(self.nodes)), kubeconfig=self.kubeconfig, context=nightly.CONTEXT,
            ate_setup=self.tools / "ate-setup", ate=self.tools / "kubectl-ate", evidence_dir=self.workdir / "installer-evidence")
        # Mirror the original clock; no new start epoch or grace window.
        clock = SimpleNamespace(remaining=self.deadlines.remaining, now=lambda: max(self.deadlines.clock(), self.deadlines.anchor + time.monotonic() - self.deadlines.monotonic))
        substrate.install(args, self.bundle, self.mapping, self.env, clock=clock)
        super().install()
        self.kube("label", "namespace", nightly.NAMESPACE, "ate.dev/api-access=true")
        self.app_attempted = True
        self.create({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": APP, "labels": {"pod-security.kubernetes.io/enforce": "privileged"}}})
        self.create({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": PROBES}})
        self.create(self.pool, namespace=APP)
        self.wait("workerpool/" + APP, "jsonpath={.status.readyReplicas}=1", namespace=APP)
        self.space_attempted = True
        self.native("create", "atespace", APP)
        self.native("create", "actor-template", "-f", "-", data=json.dumps(self.template).encode())
        actual = nightly.strict_json(self.native("get", "actor-template", "release-notes", "-a", APP, "-o", "json"))
        require(actual.get("containers") == self.template["containers"] and actual.get("workerSelector") == self.template["workerSelector"], "actor template command/digest drift")

    def check_policies(self, initial=False):
        super().check_policies(initial)
        actual = self.get("networkpolicies", namespace="ate-system")["items"]
        require({d["metadata"]["name"]: nightly.policy_spec(d["spec"]) for d in actual} == self.runtime_policies, "effective runtime policy drift")
        inventory = {d["metadata"]["name"]: d["metadata"]["uid"] for d in actual}
        if initial:
            self.runtime_policy_uids = inventory
        else:
            require(inventory == self.runtime_policy_uids, "runtime policy replaced")
        resources = set(self.kube("api-resources", "--api-group=cilium.io", "--verbs=list", "-o", "name").decode().splitlines())
        if "ciliumnetworkpolicies.cilium.io" in resources:
            require(not self.get("ciliumnetworkpolicies.cilium.io", namespace="ate-system")["items"], "additional runtime Cilium policy")

    def network(self, phase):
        self.nodes_ready()
        self.check_policies()
        jobs, actions = {}, []
        try:
            peer = nightly.listener("actor-peer", {"nightly-probe": "peer"})
            actions.append(("peer", lambda: self.kube("delete", "pod/actor-peer", "--ignore-not-found", "--wait=true", "--timeout=30s", namespace=PROBES, cleanup=True)))
            self.create(peer, namespace=PROBES)
            self.wait("pod/actor-peer", namespace=PROBES)
            peer_target = nightly.netpolicy.address(self.get("pod/actor-peer", namespace=PROBES)["status"]["podIP"])
            targets = []
            for app, port in (("atenet-router", 8080), ("ate-api-server", 443)):
                pods = self.get("pods", "-l", "app=" + app, namespace="ate-system")["items"]
                require(len(pods) == 1 and nightly.ready(pods[0]))
                targets.append(str(ipaddress.IPv4Address(pods[0]["status"]["podIP"])) + ":" + str(port))
            model = str(ipaddress.IPv4Address(socket.gethostbyname(urlsplit(self.env["MODEL_ENDPOINT"]).hostname))) + ":443"
            jobs = network_jobs(phase, self.labels, self.helper, *targets, peer_target, model)
            for namespace, job in jobs.values():
                actions.append((job["metadata"]["name"], lambda namespace=namespace, job=job: self.kube("delete", "job/" + job["metadata"]["name"], "--ignore-not-found", "--cascade=foreground", "--wait=true", "--timeout=30s", namespace=namespace, cleanup=True)))
                self.create(job, namespace=namespace)
            records = []
            for case, (namespace, job) in jobs.items():
                self.wait("job/" + job["metadata"]["name"], "condition=Complete", namespace=namespace)
                spec = job["spec"]["template"]["spec"]
                for stage, container in (("control", spec["initContainers"][-1]), ("denial", spec["containers"][0])):
                    target, expected = container["command"][-3], container["command"][-1]
                    nightly.netpolicy.proof(self.kube("logs", "job/" + job["metadata"]["name"], "-c", stage, namespace=namespace), target, expected, case, stage)
                    records.append({"phase": phase, "case": case, "stage": stage, "passed": True})
            self.check_policies()
            return records
        finally:
            cleanup_actions(actions, self.native_evidence, sys.exc_info()[1])

    def marker(self):
        host, peer = self.component("host"), self.component("harness")
        spec, labels = peer["spec"], peer["metadata"]["labels"]
        require(host["spec"]["nodeName"] == spec["nodeName"] and labels.get("app.kubernetes.io/component") == "executor")
        require("azure.workload.identity/use" not in labels and not spec.get("automountServiceAccountToken", True))
        require([c["name"] for c in spec["containers"]] == ["executor"] and not any(v["name"] == "substrate-control" for v in spec.get("volumes", [])))
        require(not any(e["name"].startswith("AZURE_") for c in spec["containers"] for e in c.get("env", [])), "executor received identity mutation")
        return {"podUID": peer["metadata"]["uid"], "nodeName": spec["nodeName"]}

    def evidence(self):
        host = self.component("host")
        return nightly.strict_json(self.kube("exec", host["metadata"]["name"], "-c", "daemon", "--", "/session-fixture", "evidence", "--scenario", "v2", "--data", "/data"))

    def read_placement(self):
        host = self.component("host")
        doc = nightly.strict_json(self.kube("exec", host["metadata"]["name"], "-c", "daemon", "--", "/session-fixture", "placement-evidence", "--data", "/data"))
        require(type(doc) is dict and type(doc.get("latest")) is dict)
        latest = doc["latest"]
        require(latest.get("namespace") == APP and type(latest.get("pod")) is str and re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,252}", latest["pod"]))
        p = placement(doc, self.session, self.nodes, self.get("pod/" + latest["pod"], namespace=APP))
        if self.first is None:
            self.first = doc["first"]
        require(self.first == doc["first"], "first placement rewritten")
        return p

    def checkpoint_rpc(self):
        host = self.component("host")
        with self.executor.forward(self.prefix, host["metadata"]["name"]) as port:
            return nightly.strict_json(self.executor.run([str(self.client), "checkpoint", "--data", str(self.state), "--server", "http://127.0.0.1:" + str(port)], limit=65))

    def rpc(self, command):
        if command in ("approve", "continue"):
            require(self.read_placement() == self.parked_placement)
            held_checkpoint(self.actor(), self.checkpoint, self.first)
        result = super().rpc(command)
        if command == "park":
            self.session = result["session"]
            self.parked_placement = self.read_placement()
            self.checkpoint = self.checkpoint_rpc()
            held_checkpoint(self.actor(), self.checkpoint, self.first)
        elif command == "approve":
            require(self.read_placement() == self.parked_placement)
            held_checkpoint(self.actor(), self.checkpoint, self.first)
        elif command == "continue":
            latest = self.read_placement()
            actor = self.actor()
            if self.first is None:
                raise ValueError("missing first actor placement")
            assignment = actor.get("status", {}).get("workerAssignment", {})
            require(actor.get("metadata", {}).get("uid") == self.first["actorUID"] and actor.get("status", {}).get("state") == "ACTOR_STATE_RUNNING")
            require(assignment.get("workerPodUid") == latest["podUID"] and assignment.get("nodeName") == latest["node"] and assignment.get("sandboxRuntime", {}).get("sandboxClass") == "gvisor")
            self.native_evidence.write_json("native-proof.json", {"status": "nativePassed", "harnessImage": self.pins["harness"], "placement": {"first": self.first, "latest": latest}, "checkpoint": self.checkpoint})
            self.native_passed = True
        return result

    def backup_args(self, command, namespace):
        return [*super().backup_args(command, namespace), *(["--runtime", "substrate"] if command == "backup" else [])]

    def delete_actors(self):
        actors = nightly.strict_json(self.native("get", "actor", "-a", APP, "-o", "json", cleanup=True)).get("actors", [])
        require(type(actors) is list and len(actors) <= 1, "unexpected actors in owned scenario")
        for actor in actors:
            meta = actor.get("metadata", {})
            require(meta.get("atespace") == APP and type(meta.get("name")) is str and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", meta["name"]))
            self.native("delete", "actor", meta["name"], "-a", APP, "--any-state", cleanup=True)

    def cleanup(self):
        self.native_evidence.cleanup_started = True
        actions = []
        if self.owned:
            actions.append(("writers", lambda: self.fence(cleanup=True)))
        if self.space_attempted:
            actions += [("actors", self.delete_actors),
                ("actor-template", lambda: self.native("delete", "actor-template", "release-notes", "-a", APP, cleanup=True)),
                ("atespace", lambda: self.native("delete", "atespace", APP, cleanup=True))]
        if self.app_attempted:
            actions += [("workerpool", lambda: self.kube("delete", "workerpool/" + APP, "--ignore-not-found", "--wait=true", "--timeout=30s", namespace=APP, cleanup=True)),
                ("namespaces", lambda: self.kube("delete", "namespace", APP, PROBES, "--ignore-not-found", "--wait=true", "--timeout=30s", cleanup=True))]
        self.native_cleanup_passed = cleanup_actions(actions, self.native_evidence, sys.exc_info()[1])


def run(api):
    import substrate_proof
    primary = None
    try:
        _, records = nightly.run_scenario(api)
        require(api.native_passed and api.native_cleanup_passed and not api.native_evidence.write_failed, "native proof or owned cleanup incomplete")
        network = substrate_proof.validate_network(records)
        return {**substrate_proof.FINAL, "replay": dict(substrate_proof.REPLAY)}, network
    except BaseException as error:
        primary = error
        raise
    finally:
        if not api.native_cleanup_passed:
            api.cleanup_status = "failed"
            if api.diagnostics is not None:
                api.diagnostics["cleanup"] = "failed"
        try:
            api.native_evidence.write_json("scenario-result.json", {"status": "passed" if primary is None else "failed", "native": "nativePassed" if api.native_passed else "failed", "cleanup": api.cleanup_status})
        except Exception:  # noqa: BLE001 — final evidence cannot replace the primary error.
            api.native_evidence.write_failed = True
        try:
            api.native_evidence.close()
        except OSError:
            api.native_evidence.write_failed = True
        if primary is None and api.native_evidence.write_failed:
            raise ValueError("private actor evidence could not be persisted")
