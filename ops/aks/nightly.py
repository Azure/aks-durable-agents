#!/usr/bin/env python3
"""Disposable AKS production-host scenario. No Azure API, retries, or demo meter.

All subprocess output and client/archive state are private. Success proofs exist
only after the complete scenario, strict recovery, and final source fencing.
Failures may publish only closed, fixed-enum diagnostics without error text.
Cluster/FIC/node-RG teardown belongs to the workflow, not this program.
"""
import argparse
import contextlib
import datetime
import hashlib
import importlib.util
import json
import math
import os
import re
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

# Local imports must not create files outside the private working directory.
sys.dont_write_bytecode = True
import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
CONTEXT = "aks-nightly"
NAMESPACE = "agents"
RELEASE = "kaimahi"
PVC = "nightly-data"
STORAGE_CLASS = "managed-csi"
STAGES = ("preflight", "install", "network-dormant", "network-live", "park", "restart", "approve", "continue", "backup", "replay", "cleanup")
RPCS = {"park", "check-parked", "approve", "continue"}
HEX = re.compile(r"[0-9a-f]{64}")


def local_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


node_profile = local_module("aks_node_profile", HERE / "profile.py")
rollout_schema = local_module("aks_rollout_schema", HERE / "proof.py")
# Existing modules import their adjacent helpers by name. Pin search paths to
# this checkout; no pip install, package discovery, or downloaded implementation.
_search_path = sys.path[:]
try:
    for directory in (ROOT, ROOT / "ops/demo", ROOT / "ops/images"):
        if str(directory) not in sys.path:
            sys.path.append(str(directory))
    from ops.demo import netpolicy
    from ops.demo.demo import published_images
    from ops.images import backup_helper, update_pins
finally:
    sys.path[:] = _search_path


class SafeFailure(ValueError):
    """Private error context with an explicit, non-sensitive failure category."""
    def __init__(self, reason, message="scenario failed"):
        super().__init__(message)
        self.reason = reason


def failure_reason(error):
    if isinstance(error, SafeFailure):
        return error.reason
    if isinstance(error, KeyboardInterrupt):
        return "interrupted"
    if isinstance(error, OSError):
        return "io-failed"
    return "unclassified-failure"


def failure_diagnostics(api, error):
    return {"version": 1, "phase": getattr(api, "phase_name", "preflight"),
            "operation": getattr(api, "operation", "phase"),
            "reason": failure_reason(error), "cleanup": getattr(api, "cleanup_status", "not-run")}


def require(condition, message="scenario invariant failed"):
    if not condition:
        raise SafeFailure("invariant-failed", message)


def strict_json(raw):
    return json.loads(raw, object_pairs_hook=update_pins.unique_object)


def rollout_fallback(kind, name):
    if (type(kind) is not str or type(name) is not str
            or (kind, name) not in rollout_schema.ROLLOUT_CONTROLLERS):
        kind, name = "other", "other"
    return {"version": 1, "controllerKind": kind, "controllerName": name,
            "podReasons": ["other"], "readyNodes": None, "desiredNodes": None}


def controller_uid(obj, kind, name):
    require(obj["apiVersion"] == "apps/v1" and obj["kind"] == kind and obj["metadata"]["name"] == name)
    uid = obj["metadata"]["uid"]
    require(type(uid) is str and bool(uid))
    return uid


def controlled_by(obj, kind, owners):
    references = obj["metadata"].get("ownerReferences", [])
    require(type(references) is list)
    controllers = [ref for ref in references if ref.get("controller") is True]
    require(len(controllers) <= 1)
    if not controllers:
        return False
    ref = controllers[0]
    return (ref.get("apiVersion") == "apps/v1" and ref.get("kind") == kind
            and type(ref.get("name")) is str and type(ref.get("uid")) is str
            and ref["name"] in owners and ref["uid"] == owners[ref["name"]])


def pod_reason_codes(pod):
    # Only literal structured reason fields. Running/not Ready does not prove a
    # probe-specific cause; the schema's readiness label is reserved, not emitted.
    status, reasons = pod.get("status", {}), set()
    conditions = status.get("conditions", [])
    require(type(conditions) is list)
    if any(c.get("type") == "PodScheduled" and c.get("status") == "False"
           and c.get("reason") == "Unschedulable" for c in conditions):
        reasons.add("Unschedulable")
    choices = rollout_schema.POD_REASONS - {"readiness probe failing"}
    for field in ("containerStatuses", "initContainerStatuses"):
        containers = status.get(field, [])
        require(type(containers) is list)
        for container in containers:
            state, last = container.get("state", {}), container.get("lastState", {})
            for source, state_kind in ((state, "waiting"), (state, "terminated"), (last, "terminated")):
                if state_kind in source:
                    reason = source[state_kind].get("reason")
                    reasons.add(reason if type(reason) is str and reason in choices else "other")
    return reasons or {"other"}


def project_rollout(kind, name, labels, controller, pods, replicasets=None):
    if controller.get("kind") != kind or controller.get("metadata", {}).get("name") != name:
        return rollout_schema.validate_rollout_status(rollout_fallback("other", "other"))
    uid = controller_uid(controller, kind, name)
    # Selectors are trusted constants/chart labels, never taken from the API.
    require(controller["spec"]["selector"] == {"matchLabels": labels})
    owners, owner_kind = {name: uid}, kind
    if kind == "Deployment":
        if type(replicasets) is not dict:
            raise SafeFailure("invariant-failed", "invalid ReplicaSet list")
        require((replicasets["apiVersion"], replicasets["kind"]) in (("apps/v1", "ReplicaSetList"), ("v1", "List")))
        require(type(replicasets["items"]) is list)
        owners, owner_kind = {}, "ReplicaSet"
        for replica in replicasets["items"]:
            if controlled_by(replica, "Deployment", {name: uid}):
                rs_name = replica["metadata"]["name"]
                require(type(rs_name) is str and bool(rs_name))
                owners[rs_name] = controller_uid(replica, "ReplicaSet", rs_name)
        # RS selectors contain private pod-template-hash labels in addition to
        # the Deployment core selector. Ownership, not selector equality, binds.
    require(pods["apiVersion"] == "v1" and pods["kind"] in ("PodList", "List"))
    require(type(pods["items"]) is list)
    reasons = set()
    for pod in pods["items"]:
        require(pod["apiVersion"] == "v1" and pod["kind"] == "Pod")
        metadata = pod["metadata"]
        if metadata.get("deletionTimestamp"):
            continue
        pod_labels = metadata.get("labels", {})
        require(type(pod_labels) is dict)
        if (all(pod_labels.get(key) == value for key, value in labels.items())
                and controlled_by(pod, owner_kind, owners)):
            reasons.update(pod_reason_codes(pod))
    report = rollout_fallback(kind, name)
    report["podReasons"] = sorted(reasons or {"other"})
    if kind == "DaemonSet":
        status = controller.get("status", {})
        for key, source in (("readyNodes", "numberReady"), ("desiredNodes", "desiredNumberScheduled")):
            count = status.get(source)
            report[key] = count if type(count) is int and 0 <= count <= 2147483647 else None
    return rollout_schema.validate_rollout_status(report)


def json_records(raw):
    # backup.py deliberately inherits kubectl's human progress output. Its
    # structured worker proofs are separate JSON lines, never its final line
    # number or the mere existence of an archive.
    records = [strict_json(line) for line in raw.splitlines() if line.lstrip().startswith(b"{")]
    require(records and all(isinstance(record, dict) for record in records), "missing backup/recovery proof")
    return records


def integer(value, low=0, high=2**31):
    return type(value) is int and low <= value <= high


def hex_digest(value):
    return isinstance(value, str) and HEX.fullmatch(value) is not None


def timestamp(value):
    require(isinstance(value, str) and len(value) <= 64)
    result = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(result.tzinfo is not None)
    return result


def check_evidence(ev, calls, effects):
    require(isinstance(ev, dict))
    for name, expected in (("realModelCalls", calls), ("fakeModelCalls", 0), ("publicationCount", effects), ("receiptCount", effects)):
        require(type(ev.get(name)) is int and ev[name] == expected, "model/effect inventory mismatch")
    require(hex_digest(ev.get("realLedgerDigest")), "missing real ledger digest")
    attempts, artifacts = ev.get("realAttempts"), ev.get("artifacts")
    require(isinstance(attempts, list) and len(attempts) == calls)
    require(isinstance(artifacts, list) and len(artifacts) == effects)
    for attempt in attempts:
        require(isinstance(attempt, dict) and type(attempt.get("attemptId")) is int and attempt["attemptId"] == 1)
        require(attempt.get("outcome") == "succeeded", "unknown or unsuccessful attempt")
        require(timestamp(attempt.get("finishedAt")) >= timestamp(attempt.get("time")))
        require(integer(attempt.get("inputTokens"), high=8192) and integer(attempt.get("outputTokens"), high=4096))
        # Nightly qualification is stricter than general ledger parsing: unknown
        # reasoning usage is not evidence of all-known usage.
        require(integer(attempt.get("reasoningTokens"), high=attempt["outputTokens"]))
    for artifact in artifacts:
        require(isinstance(artifact, dict) and set(artifact) == {"name", "digest"})
        require(isinstance(artifact["name"], str) and re.fullmatch(r"[0-9a-f]{64}\.json", artifact["name"]) is not None)
        require(hex_digest(artifact["digest"]))
    return ev


def same_ledger(before, after):
    require(all(before.get(key) == after.get(key) for key in ("realModelCalls", "fakeModelCalls", "realLedgerDigest", "realAttempts")), "real ledger changed after park")


def policy_spec(spec):
    # The API omits empty ingress/egress lists. Normalize only those equivalent
    # empty forms; retain every selector, policy type and allow rule verbatim.
    result = dict(spec)
    for direction in ("ingress", "egress"):
        result.setdefault(direction, [])
    return result


def ready(pod):
    return not pod["metadata"].get("deletionTimestamp") and any(c.get("type") == "Ready" and c.get("status") == "True" for c in pod.get("status", {}).get("conditions", []))


def check_restart(old, new, before_peer, peer, marker):
    require(old["metadata"]["uid"] != new["metadata"]["uid"], "host UID did not change")
    require(before_peer["metadata"]["uid"] == peer["metadata"]["uid"], "harness restarted")
    node = peer["spec"]["nodeName"]
    require(node and all(p["spec"]["nodeName"] == node for p in (old, new, before_peer)))
    require(ready(new) and ready(peer))
    require(marker == {"podUID": peer["metadata"]["uid"], "nodeName": node}, "fixture marker differs from live harness placement")


def check_replay(result, completed):
    require(isinstance(result, dict) and result.get("restored_hashes") == "unchanged")
    proof = result.get("replay", {})
    require(proof.get("completed") is True and proof.get("error", "") == "")
    require(type(proof.get("provider_calls")) is int and proof["provider_calls"] == 0)
    require(type(proof.get("executor_calls")) is int and proof["executor_calls"] == 0)
    require(proof.get("session_uid") == completed["session"] and proof.get("head_seq") == completed["headSeq"] and proof.get("head_hash") == completed["headHash"], "replay head mismatch")
    expected, covered = proof.get("expected_execution_ids"), proof.get("covered_execution_ids")
    require(isinstance(expected, list) and expected and all(isinstance(x, str) and x for x in expected))
    require(len(set(expected)) == len(expected) and expected == covered)
    require(completed["pending"]["executionID"] in covered, "replay did not cover approved execution")


def check_fence(deployments, pods):
    require(len(deployments) == 2 and all(d["spec"].get("replicas", 1) == 0 for d in deployments), "source writers not zero")
    for pod in pods:
        if pod.get("status", {}).get("phase") in ("Succeeded", "Failed"):
            continue
        require(not any(v.get("persistentVolumeClaim", {}).get("claimName") == PVC for v in pod["spec"].get("volumes", [])), "source PVC still has consumers")


def rpc_command(client, command, directory, port):
    require(command in RPCS, "RPC not allowlisted")
    require(integer(port, 1, 65535))
    return [str(client), command, "--data", str(directory), "--server", f"127.0.0.1:{port}"]


def chart_images(root):
    # The existing demo pin reader is pure; importing it does not run the demo.
    return published_images(root)


def verify_bindings(pins, rendered, publication, receipt, helper, *, peer_role="harness"):
    require(peer_role in ("harness", "executor"), "unsupported writer role")
    publication = update_pins.validate_manifest(publication)
    backup_helper.validate_receipt(receipt)
    require(publication["sourceCommit"] == receipt["sourceCommit"], "publication source mismatch")
    require(helper == backup_helper.validate_host(receipt, pins["host"]), "helper mismatch")
    for role in ("host", "harness"):
        image = publication["images"][role]
        require(image["repository"] + "@" + image["digest"] == pins[role], "publication/chart mismatch")
        deployments = [o for o in rendered if o.get("kind") == "Deployment" and o.get("metadata", {}).get("labels", {}).get("app.kubernetes.io/component") == (peer_role if role == "harness" else role)]
        require(len(deployments) == 1, "ambiguous rendered workload")
        containers = deployments[0]["spec"]["template"]["spec"]["containers"]
        require(containers and all(c["image"] == pins[role] for c in containers), "rendered image differs from reviewed publication")
        if role == "host":
            require(len(containers) == 1)


def prepare_manifest(subpath, fixture):
    require(re.fullmatch(r"nightly-[1-9][0-9]*-[1-9][0-9]*", subpath) is not None)
    directory = "/volume/" + subpath
    mount = [{"name": "data", "mountPath": "/volume"}]
    secure = dict(netpolicy.SECURITY)
    def container(name, image, command, security=secure):
        return {"name": name, "image": image, "command": command, "securityContext": security, "volumeMounts": mount}
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "nightly-prepare"}, "spec": {
        "restartPolicy": "Never", "automountServiceAccountToken": False, "enableServiceLinks": False,
        "nodeSelector": {"kubernetes.io/os": "linux", "kubernetes.io/arch": "amd64"},
        "initContainers": [container("ownership", node_profile.ALPINE,
            ["/bin/sh", "-ec", f"test ! -e {directory}; test ! -L {directory}; mkdir -m 0700 {directory}; chown 65532:65532 {directory}"],
            dict(secure, runAsUser=0, runAsGroup=0, runAsNonRoot=False, capabilities={"drop": ["ALL"], "add": ["CHOWN"]})),
            container("fixture", fixture, ["/session-fixture", "init", "--scenario", "v2", "--data", directory, "--socket", "/data/publish.sock"])],
        "containers": [container("tmpdirs", node_profile.ALPINE, ["/bin/sh", "-ec",
            (f"test -f {directory}/scenario.json; test -f {directory}/instructions.txt; test -f {directory}/tools.json; "
             f"for n in tmp-daemon tmp-fixture-harness tmp-executor tmp-fake; do mkdir -m 0700 {directory}/$n; done")])],
        "volumes": [{"name": "data", "persistentVolumeClaim": {"claimName": PVC}}]}}


def listener(name, labels):
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "labels": labels}, "spec": {
        "restartPolicy": "Never", "automountServiceAccountToken": False, "enableServiceLinks": False,
        "containers": [{"name": "listener", "image": node_profile.ALPINE, "securityContext": netpolicy.SECURITY,
            "command": ["/bin/busybox", "nc", "-lk", "-p", "9000", "-e", "/bin/cat"],
            "readinessProbe": {"exec": {"command": ["/bin/busybox", "nc", "-z", "-w", "1", "127.0.0.1", "9000"]}, "periodSeconds": 1}}]}}


def marker_manifest(subpath, helper, node):
    # A production fixture has no arbitrary-file or placement read RPC. A
    # short-lived read-only helper reads just the marker, without a cloud token.
    script = """import os,stat,sys
p='/data/fixture-node.json'
f=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
s=os.fstat(f)
assert stat.S_ISREG(s.st_mode) and s.st_uid==65532 and stat.S_IMODE(s.st_mode)==0o600 and s.st_size<=4096
sys.stdout.buffer.write(os.read(f,4097))
os.close(f)
"""
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "nightly-marker"}, "spec": {
        "nodeName": node, "restartPolicy": "Never", "automountServiceAccountToken": False, "enableServiceLinks": False,
        "containers": [{"name": "marker", "image": helper, "command": ["python3", "-c", script],
            "securityContext": dict(netpolicy.SECURITY, seccompProfile={"type": "Localhost", "localhostProfile": node_profile.FILENAME}),
            "volumeMounts": [{"name": "data", "mountPath": "/data", "subPath": subpath, "readOnly": True}]}],
        "volumes": [{"name": "data", "persistentVolumeClaim": {"claimName": PVC, "readOnly": True}}]}}


def credential_probe_script():
    # Credential-only WI propagation gate, not an inference/model health check.
    # Assertion and bearer response stay in memory; nothing is logged, even on
    # HTTP failure. Retries are only OAuth exchanges and stop after 90 seconds.
    return """import json,os,re,time,urllib.parse,urllib.request
from pathlib import Path
end=time.monotonic()+90
ok=False
while time.monotonic()<end:
    try:
        client=os.environ['AZURE_CLIENT_ID']
        tenant=os.environ['AZURE_TENANT_ID']
        authority=os.environ['AZURE_AUTHORITY_HOST']
        assert authority=='https://login.microsoftonline.com/'
        assert re.fullmatch(r'[0-9a-fA-F-]{36}',client) and re.fullmatch(r'[0-9a-fA-F-]{36}',tenant)
        assertion=Path(os.environ['AZURE_FEDERATED_TOKEN_FILE']).read_text()
        assert 0<len(assertion)<=16384
        body=urllib.parse.urlencode({'client_id':client,'scope':'https://ai.azure.com/.default','grant_type':'client_credentials',
            'client_assertion_type':'urn:ietf:params:oauth:client-assertion-type:jwt-bearer','client_assertion':assertion}).encode()
        request=urllib.request.Request(authority+tenant+'/oauth2/v2.0/token',data=body,headers={'Content-Type':'application/x-www-form-urlencoded'})
        with urllib.request.urlopen(request,timeout=min(10,max(.1,end-time.monotonic()))) as response:
            result=json.loads(response.read(65537))
        assert isinstance(result.get('access_token'),str) and result['access_token'] and result.get('token_type','').lower()=='bearer'
        assert float(result['expires_in'])>60
        ok=True
        break
    except Exception:
        time.sleep(min(2,max(0,end-time.monotonic())))
if not ok:
    raise SystemExit(1)
"""


def network_probes(phase, labels, fixture, harness, peer):
    require(phase in ("dormant", "live"))
    prefix = "nightly-" + phase
    # Each source proves a permitted path in its own init container before
    # testing denial. An unlabelled source/peer is outside the chart selectors,
    # so this needs no additive allow policy and cannot mistake a broken source
    # network for successful ingress enforcement.
    ingress = netpolicy.probe_job(prefix + "-untrusted", {"nightly-probe": "untrusted"}, fixture, peer, harness)
    egress = netpolicy.probe_job(prefix + "-egress", labels["host"], fixture, harness, peer)
    for job in (ingress, egress):
        job["spec"]["template"]["spec"]["enableServiceLinks"] = False
    return [ingress, egress]


class Deadlines:
    def __init__(self, work, hard, clock=time.time):
        require(all(type(n) in (float, int) and math.isfinite(n) for n in (work, hard)))
        require(work < hard and hard - work <= 900, "invalid immutable deadlines")
        self.work, self.hard, self.clock = work, hard, clock
        # A monotonic mirror prevents wall-clock rollback extending authority.
        self.anchor, self.monotonic = clock(), time.monotonic()
        require(hard - self.anchor <= 2700, "deadline exceeds full run cap")

    def remaining(self, cleanup=False):
        now = max(self.clock(), self.anchor + time.monotonic() - self.monotonic)
        seconds = (self.hard if cleanup else self.work) - now
        if not seconds > 0:
            raise SafeFailure("deadline-exhausted", "deadline exhausted")
        return seconds


class Executor:
    def __init__(self, directory, env, deadlines):
        self.directory, self.env, self.deadlines = directory, env, deadlines
        self.sequence = 0

    def logs(self):
        self.sequence += 1
        files = []
        for suffix in ("stdout", "stderr"):
            path = self.directory / f"command-{self.sequence:04}.{suffix}"
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            files.append(os.fdopen(fd, "wb"))
        return files

    @staticmethod
    def kill(process):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()

    def run(self, args, data=None, cleanup=False, limit=None):
        timeout = self.deadlines.remaining(cleanup)
        if limit is not None:
            timeout = min(timeout, limit)
        stdout, stderr = self.logs()
        with stdout, stderr:
            process = subprocess.Popen(list(map(str, args)), stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
                stdout=stdout, stderr=stderr, env=self.env, start_new_session=True)
            try:
                process.communicate(data, timeout=timeout)
            except BaseException as error:
                self.kill(process)
                reason = "command-timeout" if isinstance(error, subprocess.TimeoutExpired) else failure_reason(error)
                # ValueError catchability lets fence attempt the second scale
                # even when cancellation interrupts the first external command.
                raise SafeFailure(reason, "external command interrupted or expired") from None
        if process.returncode != 0:
            raise SafeFailure("command-failed", "external command failed")
        path = Path(stdout.name) if isinstance(stdout.name, str) else self.directory / f"command-{self.sequence:04}.stdout"
        require(path.stat().st_size <= 16 * 1024 * 1024, "command output too large")
        return path.read_bytes()

    @contextlib.contextmanager
    def forward(self, prefix, pod):
        # Let kubectl choose a free local port; no reserve/release bind race.
        stdout, stderr = self.logs()
        path = self.directory / f"command-{self.sequence:04}.stdout"
        process = subprocess.Popen([*map(str, prefix), "port-forward", "--address", "127.0.0.1", "pod/" + pod, ":8080"],
            stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, env=self.env, start_new_session=True)
        try:
            until = time.monotonic() + min(30, self.deadlines.remaining())
            while True:
                require(process.poll() is None, "port forward failed")
                require(time.monotonic() < until, "port forward readiness expired")
                self.deadlines.remaining()
                raw = path.read_bytes()
                match = re.search(rb"Forwarding from 127\.0\.0\.1:([0-9]+) -> 8080", raw)
                if match:
                    yield int(match[1])
                    break
                time.sleep(.05)
        finally:
            self.kill(process)
            stdout.close()
            stderr.close()


def private_directory(path):
    require(path.is_absolute() and path.resolve() == path, "directory must be absolute without symlinks")
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, "private owned mode-0700 directory required")


def private_json(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= 1024 * 1024)
        return strict_json(source.read())


def write_json(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as out:
        json.dump(value, out, sort_keys=True, allow_nan=False)
        out.write("\n")


def values_from_env(env, subpath):
    for flag in ("AKS_SCENARIO_ENABLED", "AKS_BUDGET_CONFIRMED"):
        require(env.get(flag) == "true", "scenario enablement and confirmed budget required")
    for key in ("MODEL_ENDPOINT", "MODEL_DEPLOYMENT", "MODEL_CLIENT_ID", "MODEL_PRICE_SOURCE", "MODEL_PRICE_AS_OF"):
        require(isinstance(env.get(key), str) and env[key] and "\n" not in env[key], "required model configuration missing")
    require(re.fullmatch(r"[0-9a-fA-F-]{36}", env["MODEL_CLIENT_ID"]) is not None)
    require(env["MODEL_ENDPOINT"].startswith("https://") and env["MODEL_PRICE_SOURCE"].startswith("https://"))
    as_of = datetime.date.fromisoformat(env["MODEL_PRICE_AS_OF"])
    require(0 <= (datetime.datetime.now(datetime.timezone.utc).date() - as_of).days <= 30 and env.get("MODEL_PRICE_EXTRA") == "0", "dated verified zero-extra pricing required")
    prices = {}
    for source, target in (("MODEL_PRICE_INPUT", "inputMicroUSDPerMillionTokens"), ("MODEL_PRICE_OUTPUT", "outputMicroUSDPerMillionTokens")):
        require(re.fullmatch(r"[1-9][0-9]*", env.get(source, "")) is not None)
        prices[target] = int(env[source])
    prices.update(extraMicroUSDPerCall=0, source=env["MODEL_PRICE_SOURCE"], asOf=env["MODEL_PRICE_AS_OF"])
    return {"workloads": {"enabled": False}, "auth": {"mode": "off", "trustedNetwork": True},
        "workloadIdentity": {"clientID": env["MODEL_CLIENT_ID"]}, "harness": {"native": {"enabled": False}},
        "networkPolicy": {"enabled": True}, "persistence": {"existingClaim": PVC, "storageClass": STORAGE_CLASS, "subPath": subpath, "size": "1Gi"},
        "model": {"endpoint": env["MODEL_ENDPOINT"], "deployment": env["MODEL_DEPLOYMENT"], "policy": {"runID": subpath, "maxAttempts": 2, "pricing": prices}}}


class Scenario:
    def __init__(self, workdir, client, chart, env, executor=None):
        private_directory(workdir)
        self.workdir, self.client, self.chart = workdir, client, chart
        self.env = dict(env)
        run, attempt = env.get("GITHUB_RUN_ID", ""), env.get("GITHUB_RUN_ATTEMPT", "")
        require(re.fullmatch(r"[1-9][0-9]*", run) and re.fullmatch(r"[1-9][0-9]*", attempt))
        self.subpath = f"nightly-{run}-{attempt}"
        self.values = values_from_env(env, self.subpath)
        started = float(env["AKS_STARTED_EPOCH"])
        work, hard = float(env["WORK_DEADLINE_EPOCH"]), float(env["HARD_DEADLINE_EPOCH"])
        require(math.isfinite(started) and 0 < started <= time.time() and work == started + 1800 and hard == started + 2700, "persisted provisioning clock mismatch")
        self.deadlines = Deadlines(work, hard)
        self.deadlines.remaining()
        self.kubeconfig = Path(env["KUBECONFIG"])
        require(self.kubeconfig.is_absolute() and self.kubeconfig.resolve() == self.kubeconfig)
        info = self.kubeconfig.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600)
        require(client.is_absolute() and client.resolve() == client and client.is_file() and os.access(client, os.X_OK))
        self.env.update(KUBECONFIG=str(self.kubeconfig), PYTHONDONTWRITEBYTECODE="1", TMPDIR=str(workdir))
        self.executor = executor or Executor(workdir, self.env, self.deadlines)
        self.prefix = ["kubectl", "--kubeconfig", str(self.kubeconfig), "--context", CONTEXT, "--namespace", NAMESPACE]
        self.state = workdir / "client-state"
        self.state.mkdir(mode=0o700)
        self.archive = workdir / "source.tar.gz"
        self.values_path = workdir / "values.json"
        write_json(self.values_path, self.values)
        self.phase_name, self.phase_started, self.started = "preflight", time.monotonic(), time.monotonic()
        self.operation, self.diagnostics, self.cleanup_status = "phase", None, "not-run"
        self.rollout_status = None
        self.phases = {}
        self.deployments, self.labels = {}, {}
        self.owned = False
        self.pins = chart_images(ROOT)
        self.helper = env["BACKUP_HELPER_IMAGE"]
        self.receipt = strict_json(env["BACKUP_HELPER_RECEIPT"])
        self.publication = strict_json(env["PUBLISHED_IMAGES"])

    def phase(self, name):
        require(name in STAGES)
        now = time.monotonic()
        self.phases[self.phase_name] = self.phases.get(self.phase_name, 0) + now - self.phase_started
        self.phase_name, self.phase_started = name, now
        self.operation = "phase"

    def timings(self):
        now = time.monotonic()
        phases = dict(self.phases)
        phases[self.phase_name] = phases.get(self.phase_name, 0) + now - self.phase_started
        return {"version": 1, "phases": phases, "totalSeconds": now - self.started}

    def kube(self, *args, data=None, cleanup=False, namespace=None, limit=None):
        prefix = self.prefix if namespace is None else [*self.prefix[:-1], namespace]
        options = {"limit": limit} if limit is not None else {}
        return self.executor.run([*prefix, *args], data=data, cleanup=cleanup, **options)

    def rollout(self, kind, name, namespace=None):
        previous = self.operation
        if kind in ("DaemonSet", "Deployment"):
            self.operation = "profile-rollout" if kind == "DaemonSet" else "deployment-rollout"
        try:
            self.kube("rollout", "status", kind.lower() + "/" + name, "--timeout=180s", namespace=namespace)
        except (Exception, KeyboardInterrupt) as error:
            # Save the full safe fallback before any optional reads or cleanup.
            self.rollout_status = rollout_fallback(kind, name)
            if isinstance(error, SafeFailure) and error.reason == "command-failed":
                try:
                    self.capture_rollout(kind, name, namespace)
                except (Exception, KeyboardInterrupt):
                    # A secondary cancellation stops ALL capture. Bare raise
                    # below retains the active rollout failure and finally fence.
                    pass
            raise
        self.operation = previous

    def capture_rollout(self, kind, name, namespace):
        if self.rollout_status is None or self.rollout_status["controllerKind"] == "other":
            return
        if kind == "DaemonSet":
            require(namespace == node_profile.NAMESPACE)
            labels = {"nightly-profile": "installer"}
        else:
            require(namespace in (None, NAMESPACE))
            roles = [role for role, deployment in self.deployments.items() if deployment == name]
            require(len(roles) == 1)
            labels = self.labels[roles[0]]
        end = time.monotonic() + min(5, self.deadlines.remaining())

        def remaining():
            seconds = min(self.deadlines.remaining(), end - time.monotonic())
            require(seconds >= .001)
            return seconds

        def read(resource, *args):
            seconds = remaining()
            # Round down, never let kubectl's request timeout exceed authority.
            timeout = int(seconds * 1000) / 1000
            raw = self.kube("get", resource, *args, "-o", "json", f"--request-timeout={timeout:.3f}s",
                            namespace=namespace, limit=seconds)
            remaining()
            require(len(raw) <= 16 * 1024 * 1024)
            value = strict_json(raw)
            remaining()
            return value

        selector = ",".join(key + "=" + value for key, value in labels.items())
        controller = read(kind.lower() + "/" + name)
        replicasets = read("replicasets", "-l", selector) if kind == "Deployment" else None
        pods = read("pods", "-l", selector)
        remaining()
        report = project_rollout(kind, name, labels, controller, pods, replicasets)
        remaining()
        # No partial counts survive errors, expired work or cancellation.
        self.rollout_status = report

    def get(self, kind, *args, namespace=None):
        return strict_json(self.kube("get", kind, *args, "-o", "json", namespace=namespace))

    def create(self, obj, namespace=None):
        return self.kube("create", "-f", "-", data=json.dumps(obj).encode(), namespace=namespace)

    def helm(self, *args):
        return self.executor.run(["helm", "--kubeconfig", str(self.kubeconfig), "--kube-context", CONTEXT, *args])

    def wait(self, resource, condition="condition=Ready", namespace=None):
        seconds = min(180, self.deadlines.remaining())
        self.kube("wait", "--for=" + condition, resource, f"--timeout={seconds:.3f}s", namespace=namespace)

    def nodes_ready(self):
        nodes = node_profile.eligible_nodes(self.get("nodes")["items"])
        if hasattr(self, "nodes"):
            require(nodes == self.nodes, "node inventory changed after profile verification")
        # Azure lifecycle verifies autoscaler disabled. Reject its in-cluster
        # deployment as an additional local tripwire; never mutate autoscaling.
        controllers = self.get("deployments", namespace="kube-system")["items"]
        require(not any("cluster-autoscaler" in x["metadata"]["name"] for x in controllers))
        cilium = self.get("daemonsets", "-l", "k8s-app=cilium", namespace="kube-system")["items"]
        require(len(cilium) == 1)
        status = cilium[0]["status"]
        require(status.get("desiredNumberScheduled") == 2 and status.get("numberReady") == 2 and status.get("numberUnavailable", 0) == 0)
        pods = self.get("pods", "-l", "k8s-app=cilium", namespace="kube-system")["items"]
        require(len(pods) == 2 and {p["spec"]["nodeName"] for p in pods} == nodes and all(ready(p) for p in pods))
        return nodes

    def preflight(self):
        rendered = list(yaml.safe_load_all(self.helm("template", RELEASE, self.chart, "--namespace", NAMESPACE, "--kube-version", "1.37.0", "-f", self.values_path)))
        rendered = [x for x in rendered if x]
        verify_bindings(self.pins, rendered, self.publication, self.receipt, self.helper)
        for obj in rendered:
            if obj["kind"] == "Deployment":
                role = obj["metadata"]["labels"]["app.kubernetes.io/component"]
                require(obj["spec"]["replicas"] == 0)
                self.deployments[role] = obj["metadata"]["name"]
                template = obj["spec"]["template"]
                self.labels[role] = netpolicy.policy_labels(template)
                require(self.labels[role] == obj["spec"]["selector"]["matchLabels"])
                if role == "host":
                    self.host_service_account = template["spec"]["serviceAccountName"]
        require(set(self.deployments) == {"host", "harness"})
        self.rendered_policies = {o["metadata"]["name"]: policy_spec(o["spec"]) for o in rendered if o["kind"] == "NetworkPolicy"}
        require(len(self.rendered_policies) == 3)
        require(not self.kube("get", "namespace", NAMESPACE, "--ignore-not-found", "-o", "name").strip(), "source namespace already exists")
        self.nodes = self.nodes_ready()

    def profile(self):
        self.operation = "profile-create"
        raw = (ROOT / "ops/backup/no-network.json").read_bytes()
        for obj in node_profile.manifests(raw):
            self.create(obj, namespace=node_profile.NAMESPACE)
        self.operation = "profile-rollout"
        self.rollout("DaemonSet", node_profile.NAME, namespace=node_profile.NAMESPACE)
        self.operation = "profile-verify"
        pods = self.get("pods", "-l", "nightly-profile=installer", namespace=node_profile.NAMESPACE)["items"]
        require(len(pods) == 2 and {p["spec"]["nodeName"] for p in pods} == self.nodes and all(ready(p) for p in pods))
        for pod in pods:
            self.kube("exec", pod["metadata"]["name"], "-c", "install", "--", "/bin/sh", "-ec", node_profile.verify_script(raw), namespace=node_profile.NAMESPACE)
        self.operation = "profile-remove"
        self.kube("delete", "daemonset/" + node_profile.NAME, "configmap/" + node_profile.NAME, "--cascade=foreground", "--wait=true", "--timeout=120s", namespace=node_profile.NAMESPACE)
        self.kube("delete", "namespace", node_profile.NAMESPACE, "--wait=true", "--timeout=120s")
        require(not self.kube("get", "namespace", node_profile.NAMESPACE, "--ignore-not-found", "-o", "name").strip())
        self.operation = "profile-node-check"
        self.nodes_ready()

    def install(self):
        self.profile()
        self.operation = "namespace-create"
        self.create({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": NAMESPACE}})
        self.owned = True
        self.operation = "volume-create"
        self.create({"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": PVC}, "spec": {
            "accessModes": ["ReadWriteOnce"], "storageClassName": STORAGE_CLASS, "resources": {"requests": {"storage": "1Gi"}}}})
        self.operation = "chart-install"
        self.helm("install", RELEASE, self.chart, "--namespace", NAMESPACE, "-f", self.values_path)
        self.operation = "policy-check"
        self.check_policies(initial=True)
        self.operation = "fixture-init-create"
        self.create(prepare_manifest(self.subpath, self.pins["harness"]))
        self.operation = "fixture-init-wait"
        self.wait("pod/nightly-prepare", "jsonpath={.status.phase}=Succeeded")
        self.operation = "fixture-init-remove"
        self.kube("delete", "pod/nightly-prepare", "--wait=true", "--timeout=120s")

    def check_policies(self, initial=False):
        objects = self.get("networkpolicies")["items"]
        require({p["metadata"]["name"]: policy_spec(p["spec"]) for p in objects} == self.rendered_policies, "policy inventory differs from rendered chart")
        inventory = {p["metadata"]["name"]: {"uid": p["metadata"]["uid"], "spec": policy_spec(p["spec"])} for p in objects}
        if initial:
            self.policy_inventory = inventory
        else:
            require(inventory == self.policy_inventory, "policy UID/spec changed between phases")
        require(not self.get("hpa")["items"], "unexpected source autoscaler")
        # Managed Cilium need not expose custom-policy CRDs. Discover support;
        # a failed discovery/list is still an error, never inferred absence.
        resources = set(self.kube("api-resources", "--api-group=cilium.io", "--verbs=list", "-o", "name").decode().splitlines())
        for resource in ("ciliumnetworkpolicies.cilium.io", "ciliumclusterwidenetworkpolicies.cilium.io"):
            if resource in resources:
                require(not self.get(resource)["items"], "additional Cilium policies present")

    def component(self, role):
        selector = ",".join(k + "=" + v for k, v in self.labels[role].items())
        items = self.get("pods", "-l", selector)["items"]
        require(len(items) == 1 and ready(items[0]), "expected one Ready workload pod")
        require(netpolicy.policy_labels(items[0]) == self.labels[role])
        return items[0]

    def network(self, phase):
        self.nodes_ready()
        self.check_policies()
        peer = listener("nightly-peer", {"nightly-probe": "peer"})
        self.create(peer)
        if phase == "dormant":
            self.create(listener("nightly-listener", self.labels["harness"]))
            self.wait("pod/nightly-listener")
            harness = self.get("pod/nightly-listener")
        else:
            harness = self.component("harness")
        self.wait("pod/nightly-peer")
        peer_target = netpolicy.address(self.get("pod/nightly-peer")["status"]["podIP"])
        harness_target = netpolicy.address(harness["status"]["podIP"])
        objects = network_probes(phase, self.labels, self.pins["harness"], harness_target, peer_target)
        records = []
        for obj in objects:
            self.create(obj)
            self.wait("job/" + obj["metadata"]["name"], "condition=Complete")
        sources = [(objects[0], "control", peer_target, "allowed", "untrusted-ingress", "control"),
                   (objects[0], "denial", harness_target, "denied", "untrusted-ingress", "denial"),
                   (objects[1], "control", harness_target, "allowed", "host-egress", "control"),
                   (objects[1], "denial", peer_target, "denied", "host-egress", "denial")]
        for obj, container, target, expect, case, stage in sources:
            netpolicy.proof(self.kube("logs", "job/" + obj["metadata"]["name"], "-c", container), target, expect, case, stage)
            records.append({"phase": phase, "case": case, "stage": stage, "passed": True})
        resources = ["job/" + o["metadata"]["name"] for o in objects] + ["pod/nightly-peer"]
        if phase == "dormant":
            resources.append("pod/nightly-listener")
        self.kube("delete", *resources, "--cascade=foreground", "--wait=true", "--timeout=120s")
        require(not self.get("pods", "-l", "nightly-probe")["items"])
        self.check_policies()
        return records

    def enable(self):
        self.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "nightly-credential",
            "labels": dict(self.labels["host"], **{"azure.workload.identity/use": "true"})}, "spec": {
            "restartPolicy": "Never", "activeDeadlineSeconds": 120, "serviceAccountName": self.host_service_account,
            "automountServiceAccountToken": False, "enableServiceLinks": False,
            "containers": [{"name": "credential", "image": self.helper, "securityContext": netpolicy.SECURITY,
                "command": ["python3", "-c", credential_probe_script()]}]}})
        self.wait("pod/nightly-credential", "jsonpath={.status.phase}=Succeeded")
        credential = self.get("pod/nightly-credential")
        env = {e["name"]: e.get("value") for e in credential["spec"]["containers"][0].get("env", [])}
        require(env.get("AZURE_CLIENT_ID") == self.env["MODEL_CLIENT_ID"] and env.get("AZURE_FEDERATED_TOKEN_FILE"), "WI webhook identity mismatch")
        self.kube("delete", "pod/nightly-credential", "--wait=true", "--timeout=120s")
        for role in ("harness", "host"):
            self.kube("scale", "deployment/" + self.deployments[role], "--replicas=1")
            self.rollout("Deployment", self.deployments[role])
        self.marker()

    def evidence(self):
        harness = self.component("harness")
        return strict_json(self.kube("exec", harness["metadata"]["name"], "-c", "fixture-harness", "--", "/session-fixture", "evidence", "--scenario", "v2", "--data", "/data"))

    def marker(self):
        host, peer = self.component("host"), self.component("harness")
        self.create(marker_manifest(self.subpath, self.helper, peer["spec"]["nodeName"]))
        self.wait("pod/nightly-marker", "jsonpath={.status.phase}=Succeeded")
        marker = strict_json(self.kube("logs", "pod/nightly-marker", "-c", "marker"))
        self.kube("delete", "pod/nightly-marker", "--wait=true", "--timeout=120s")
        require(host["spec"]["nodeName"] == peer["spec"]["nodeName"])
        require(marker == {"podUID": peer["metadata"]["uid"], "nodeName": peer["spec"]["nodeName"]})
        return marker

    def rpc(self, command):
        require(command in RPCS)
        host = self.component("host")
        with self.executor.forward(self.prefix, host["metadata"]["name"]) as port:
            return strict_json(self.executor.run(rpc_command(self.client, command, self.state, port), limit=65))

    def snapshot(self, name):
        require(name in ("park.json", "approved.json", "completed.json"))
        return private_json(self.state / name)

    def restart(self):
        old, peer = self.component("host"), self.component("harness")
        self.kube("delete", "pod/" + old["metadata"]["name"], "--wait=true", "--timeout=120s")
        until = time.monotonic() + min(180, self.deadlines.remaining())
        while True:
            require(time.monotonic() < until, "replacement readiness expired")
            self.deadlines.remaining()
            selector = ",".join(k + "=" + v for k, v in self.labels["host"].items())
            pods = self.get("pods", "-l", selector)["items"]
            replacements = [p for p in pods if p["metadata"]["uid"] != old["metadata"]["uid"] and ready(p)]
            require(len(replacements) <= 1)
            if replacements:
                check_restart(old, replacements[0], peer, self.component("harness"), self.marker())
                return
            time.sleep(.1)

    def fence(self, cleanup=False):
        if not self.owned:
            return
        # Attempt both even if one scale request fails. No writer is restarted.
        failed = False
        for name in self.deployments.values():
            try:
                self.kube("scale", "deployment/" + name, "--replicas=0", cleanup=cleanup)
            except (ValueError, OSError):
                failed = True
        require(not failed, "source fencing failed")
        seconds = min(120, self.deadlines.remaining(cleanup))
        self.kube("wait", "--for=delete", "pods", "-l", "app.kubernetes.io/instance=" + RELEASE, f"--timeout={seconds:.3f}s", cleanup=cleanup)
        if not cleanup:
            self.assert_fenced()

    def assert_fenced(self):
        check_fence([self.get("deployment/" + name) for name in self.deployments.values()], self.get("pods")["items"])

    def backup_args(self, command, namespace):
        return [sys.executable, "-B", str(ROOT / "ops/backup/backup.py"), command, "--context", CONTEXT,
            "--kubeconfig", str(self.kubeconfig), "--namespace", namespace, "--pvc", PVC, "--subpath", self.subpath, "--image", self.helper]

    def backup(self):
        self.assert_fenced()
        require(not self.archive.exists() and not self.archive.is_symlink(), "archive must be fresh")
        records = json_records(self.executor.run([*self.backup_args("backup", NAMESPACE), "--release", RELEASE, "--output", str(self.archive)]))
        require(len(records) == 1)
        result = records[0]
        require(result.get("backup") == str(self.archive) and hex_digest(result.get("sha256")))
        with self.archive.open("rb") as archive:
            require(hashlib.file_digest(archive, "sha256").hexdigest() == result["sha256"], "archive transfer digest mismatch")
        require(set(result.get("source", {}).get("replicas", {})) == set(self.deployments.values()))
        require(all(type(v) is int and v == 0 for v in result["source"]["replicas"].values()))
        self.assert_fenced()

    def replay(self, completed, final):
        self.nodes_ready()
        self.assert_fenced()
        recovery = "nightly-recovery-" + self.subpath.removeprefix("nightly-")
        raw = self.executor.run([*self.backup_args("restore", recovery), "--archive", str(self.archive), "--session", completed["session"],
            "--storage-class", STORAGE_CLASS, "--size", "1Gi"])
        lines = json_records(raw)
        proofs = [p for p in lines if "replay" in p]
        require(len(proofs) == 1)
        check_replay(proofs[0], completed)
        restores = [p for p in lines if p.get("restore") == "verified"]
        require(len(restores) == 1 and restores[0] == {"restore": "verified", "namespace": recovery, "pvc": PVC,
            "session": completed["session"], "workloads_started": False})
        require(sum(p == {"socket_denial": "verified"} for p in lines) == 2, "missing effective recovery socket denial")
        # Read restored inventories with the same production fixture, read-only
        # PVC and socket-denying profile. The backup tool has already checked
        # hashes before/after replay; bind its result to pre-backup evidence too.
        reader = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "nightly-evidence"}, "spec": {
            "restartPolicy": "Never", "automountServiceAccountToken": False, "enableServiceLinks": False,
            "nodeSelector": {"kubernetes.io/os": "linux", "kubernetes.io/arch": "amd64"},
            "containers": [{"name": "evidence", "image": self.helper,
                "securityContext": dict(netpolicy.SECURITY, seccompProfile={"type": "Localhost", "localhostProfile": node_profile.FILENAME}),
                "command": ["/session-fixture", "evidence", "--scenario", "v2", "--data", "/volume/" + self.subpath],
                "volumeMounts": [{"name": "data", "mountPath": "/volume", "readOnly": True}]}],
            "volumes": [{"name": "data", "persistentVolumeClaim": {"claimName": PVC, "readOnly": True}}]}}
        self.create(reader, namespace=recovery)
        self.wait("pod/nightly-evidence", "jsonpath={.status.phase}=Succeeded", namespace=recovery)
        restored = strict_json(self.kube("logs", "pod/nightly-evidence", "-c", "evidence", namespace=recovery))
        check_evidence(restored, 1, 1)
        require(restored == final, "restored evidence differs from final source inventory")
        self.kube("delete", "pod/nightly-evidence", "--wait=true", "--timeout=120s", namespace=recovery)
        self.assert_fenced()

    def cleanup(self):
        # This is only a source fence. Recovery/bootstrap objects on failure
        # remain for the workflow's bounded whole-cluster teardown.
        self.fence(cleanup=True)


def run_scenario(api):
    try:
        api.phase("preflight")
        api.preflight()
        api.phase("install")
        api.install()
        api.phase("network-dormant")
        records = api.network("dormant")
        api.enable()
        api.phase("network-live")
        records += api.network("live")
        check_evidence(api.evidence(), 0, 0)
        api.phase("park")
        parked = api.rpc("park")
        require(parked == api.snapshot("park.json"))
        require(isinstance(parked.get("session"), str) and parked["session"])
        baseline = check_evidence(api.evidence(), 1, 0)
        api.phase("restart")
        api.restart()
        require(api.rpc("check-parked") == {"session": parked["session"], "parked": True})
        after_restart = check_evidence(api.evidence(), 1, 0)
        require(after_restart == baseline, "restart altered parked evidence")
        api.phase("approve")
        require(api.rpc("approve") == {"session": parked["session"], "approved": True})
        require(check_evidence(api.evidence(), 1, 0) == baseline, "approve performed an effect")
        api.phase("continue")
        continued = api.rpc("continue")
        final = check_evidence(api.evidence(), 1, 1)
        same_ledger(baseline, final)
        completed = api.snapshot("completed.json")
        require(continued == {"session": parked["session"], "completed": True, "artifact": completed["artifact"]})
        require(completed["session"] == parked["session"] and completed["pending"] == parked["pending"] and completed["draft"] == parked["draft"])
        require(final["artifacts"][0]["name"] == completed["artifact"])
        require(integer(completed.get("headSeq"), 1) and hex_digest(completed.get("headHash")))
        require(integer(completed.get("approvalSeq"), 1) and completed["headSeq"] > completed["approvalSeq"] > parked["pending"]["requestSeq"])
        api.phase("backup")
        api.fence()
        api.assert_fenced()
        api.backup()
        api.assert_fenced()
        api.phase("replay")
        api.replay(completed, final)
        api.assert_fenced()
        proof = {"version": 1, "profile": "aks", "model": "real", "approval": "simulated", "entra": "not-run",
            "modelCalls": 1, "fakeModelCalls": 0, "published": 1, "receipts": 1, "artifacts": 1,
            "restartVerified": True, "markerVerified": True, "networkVerified": True,
            "replay": {"completed": True, "providerCalls": 0, "executorCalls": 0, "coverageComplete": True, "unchanged": True}}
        return proof, records
    finally:
        primary = sys.exc_info()[1]
        failed_stage = api.phase_name if hasattr(api, "phase_name") and primary is not None else None
        # Keep the primary context on the Scenario, before cleanup resets phase
        # and operation. Cleanup exceptions retain their existing precedence.
        if primary is not None:
            api.diagnostics = failure_diagnostics(api, primary)
        api.phase("cleanup")
        try:
            api.cleanup()
        except (Exception, KeyboardInterrupt) as error:
            api.cleanup_status = "failed"
            if primary is None:
                api.diagnostics = failure_diagnostics(api, error)
            api.diagnostics["cleanup"] = "failed"
            if failed_stage is not None and isinstance(error, (ValueError, OSError, KeyboardInterrupt)):
                print("aks-nightly: cleanup also failed after stage=" + failed_stage, file=sys.stderr)
            raise
        api.cleanup_status = "succeeded"
        if primary is not None:
            api.diagnostics["cleanup"] = "succeeded"
        if failed_stage is not None:
            api.phase_name = failed_stage


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", type=Path, required=True)
    parser.add_argument("--public-dir", type=Path, required=True)
    parser.add_argument("--client", type=Path, required=True)
    parser.add_argument("--chart", type=Path, default=ROOT / "charts/aks-durable-agents")
    parser.add_argument("--variant", choices=("no-sandbox", "substrate-gvisor"), default="no-sandbox")
    for option in ("source", "image-map", "tools"):
        parser.add_argument("--substrate-" + option, type=Path)
    args = parser.parse_args(argv)
    os.umask(0o077)
    stage = "preflight"
    api = None
    public_ready = False
    try:
        private_directory(args.workdir)
        require(args.public_dir.is_absolute() and args.public_dir.resolve() == args.public_dir)
        require(args.public_dir != args.workdir and args.public_dir not in args.workdir.parents and args.workdir not in args.public_dir.parents, "private/public directories must be disjoint")
        private_directory(args.public_dir)
        require(not list(args.public_dir.iterdir()), "public output directory must be empty")
        public_ready = True
        native_inputs = (args.substrate_source, args.substrate_image_map, args.substrate_tools)
        if args.variant == "substrate-gvisor":
            require(all(path is not None for path in native_inputs), "explicit prepared Substrate inputs required")
            adapter = local_module("aks_actor_scenario", HERE / "substrate_session.py")
            api = adapter.SubstrateScenario(args.workdir, args.client, args.chart, os.environ, *native_inputs)
            proof, network = adapter.run(api)
        else:
            require(all(path is None for path in native_inputs), "Substrate inputs require explicit variant")
            api = Scenario(args.workdir, args.client, args.chart, os.environ)
            proof, network = run_scenario(api)
        timings = api.timings()
        # No permissive fallback: sibling validator is mandatory at publication.
        validator = local_module("aks_safe_proof", HERE / ("substrate_proof.py" if args.variant == "substrate-gvisor" else "proof.py"))
        proof = validator.validate(proof)
        network = validator.validate_network(network)
        timings = validator.validate_timings(timings)
        write_json(args.public_dir / "proof.json", proof)
        write_json(args.public_dir / "network-proof.json", network)
        write_json(args.public_dir / "timings.json", timings)
    except (Exception, KeyboardInterrupt) as error:
        stage = api.phase_name if api is not None else stage
        print("aks-nightly: failed stage=" + stage, file=sys.stderr)
        # Diagnostics are best effort, never a replacement failure or an excuse
        # to write into a directory that failed the public/private boundary.
        try:
            if public_ready:
                validator = local_module("aks_safe_proof", HERE / "proof.py")
                diagnostics = getattr(api, "diagnostics", None) or failure_diagnostics(api, error)
                write_json(args.public_dir / "diagnostics.json", validator.validate_diagnostics(diagnostics))
        except (Exception, KeyboardInterrupt):
            pass
        # Independent best effort: neither optional writer can suppress the
        # original diagnostic or change the failed return status.
        try:
            if public_ready and api is not None and api.rollout_status is not None:
                validator = local_module("aks_safe_proof", HERE / "proof.py")
                write_json(args.public_dir / "rollout-status.json", validator.validate_rollout_status(api.rollout_status))
        except (Exception, KeyboardInterrupt):
            pass
        return 1
    return 0


if __name__ == "__main__":
    # Raise into finally on cancellation so every external process group is
    # killed and source fencing is attempted within the preserved hard deadline.
    def cancelled(signum, frame):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, cancelled)
    sys.exit(main())
