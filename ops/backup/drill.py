#!/usr/bin/env python3
"""Destructive only to its own kind cluster: local fictional journal backup drill."""
import argparse
import json
import os
import re
import selectors
import shutil
import socket
import subprocess
import sys
import tempfile
import uuid
from contextlib import contextmanager
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CHART = REPO / "charts/aks-durable-agents"
BACKUP = REPO / "ops/backup/backup.py"
PROFILE = REPO / "ops/backup/no-network.json"
BASE = "python:3.13-alpine@sha256:79e7a9b9ff1cbceff819f856fb374477792a5967759d94df266de7b7b4120e6f"


def run(args, *, input=None, env=None, check=True):
    print("+", " ".join(map(str, args)), flush=True)
    result = subprocess.run(list(map(str, args)), input=input, capture_output=True, env=env, cwd=REPO, check=False)
    if check and result.returncode:
        raise RuntimeError(f"{args[0]} exited {result.returncode}: {result.stderr.decode(errors='replace')} {result.stdout.decode(errors='replace')}")
    return result


def save(path, data):
    path = Path(path)
    path.write_bytes(data if isinstance(data, bytes) else data.encode())
    path.chmod(0o600)


def parsed(result):
    return json.loads(result.stdout)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


@contextmanager
def forward(kubectl, pod):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    args = kubectl + ["port-forward", "--address=127.0.0.1", "pod/" + pod, f"{port}:8080"]
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        require(selector.select(timeout=15), "host port-forward did not start")
        line = process.stdout.readline()
        require(b"Forwarding from 127.0.0.1:" in line and process.poll() is None, f"host port-forward failed: {line!r}")
        yield f"127.0.0.1:{port}"
    finally:
        process.terminate()
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, default=Path(os.environ.get("ADA_FIXTURE_BINARY", "")), help="absolute path to reviewed session-fixture v2 binary")
    parser.add_argument("--client", type=Path, default=Path(os.environ.get("ADA_NATIVE_BINARY", "")), help="absolute path to reviewed sessions-rpc binary")
    parser.add_argument("--evidence", required=True, type=Path, help="new private directory outside the Git checkout")
    a = parser.parse_args()
    for name, path in (("fixture", a.fixture), ("client", a.client)):
        if not path.is_absolute() or not path.is_file():
            parser.error(f"--{name} must be an absolute existing binary path")
    evidence = a.evidence.resolve()
    if evidence.is_relative_to(REPO) or REPO.is_relative_to(evidence) or evidence.exists():
        parser.error("--evidence must be a new directory outside the project checkout")
    evidence.mkdir(mode=0o700, parents=True)
    evidence.chmod(0o700)
    lane = "backup-drill-" + uuid.uuid4().hex[:10]
    release, namespace, claim, subpath = "drill", "backup-drill", "sessions-data", "drill-v2"
    recovery = "recover-" + uuid.uuid4().hex[:10]
    print(f"Evidence: {evidence}; kind cluster: {lane}", flush=True)
    with tempfile.TemporaryDirectory(prefix="backup-drill-") as temp:
        work = Path(temp)
        kubeconfig = work / "kubeconfig"
        context = "kind-" + lane
        env = dict(os.environ, KUBECONFIG=str(kubeconfig))
        base_k = ["kubectl", "--context", context, "--kubeconfig", str(kubeconfig)]
        k = base_k + ["--namespace", namespace]
        chart_values = json.loads((CHART / "tests/proof-values.yaml").read_text())
        chart_values["model"]["endpoint"] = "https://offline-drill.invalid/openai/v1/"
        chart_values["model"]["deployment"] = "offline-drill"
        chart_values["model"]["policy"]["runID"] = lane
        chart_values["persistence"] = {"existingClaim": claim, "storageClass": "standard", "subPath": subpath, "size": "1Gi"}
        chart_values["workloads"] = {"enabled": True}
        binary = work / "drillhost-build"
        run(["go", "build", "-o", binary, "./ops/backup/drillhost"], env=dict(env, CGO_ENABLED="0"))
        for src, dst in ((binary, "host"), (a.fixture, "session-fixture"), (a.client, "sessions-rpc"), (BACKUP, "backup.py")):
            shutil.copy2(src, work / dst)
        save(work / "Dockerfile", f"FROM {BASE}\nCOPY --chmod=0555 host /host\nCOPY --chmod=0555 session-fixture /session-fixture\nCOPY --chmod=0555 sessions-rpc /sessions-rpc\nCOPY --chmod=0444 backup.py /backup.py\nUSER 65532:65532\nENV PYTHONDONTWRITEBYTECODE=1\n")
        tag = f"local/backup-drill:{lane}"
        run(["docker", "build", "--pull=false", "--network=none", "-t", tag, work])
        save(evidence / "versions.txt", b"".join(run(cmd).stdout for cmd in (["kind", "version"], ["kubectl", "version", "--client"], ["helm", "version", "--short"], ["go", "version"], ["docker", "version", "--format", "{{.Server.Version}}"])))
        # Never reuse a pre-existing name, even if a UUID accidentally collides.
        require(lane not in run(["kind", "get", "clusters"]).stdout.decode().splitlines(), "kind cluster name already exists")
        created = True
        try:
            run(["kind", "create", "cluster", "--name", lane, "--kubeconfig", kubeconfig, "--image", "kindest/node:v1.32.2"], env=env)
            node = lane + "-control-plane"
            run(["docker", "exec", node, "mkdir", "-p", "/var/lib/kubelet/seccomp"])
            run(["docker", "cp", PROFILE, node + ":/var/lib/kubelet/seccomp/ops-backup-no-network.json"])
            run(["kind", "load", "docker-image", tag, "--name", lane], env=env)
            # Docker's local image ID is not a registry digest. Inspect containerd's
            # actual manifest digest on the lane node after loading and tag it there.
            images = run(["docker", "exec", node, "ctr", "-n", "k8s.io", "images", "ls", "--quiet"]).stdout.decode().splitlines()
            loaded_tag = next((name for name in images if name == tag or name == "docker.io/" + tag), None)
            require(loaded_tag is not None, f"kind node did not load the drill image: {images!r}")
            table = run(["docker", "exec", node, "ctr", "-n", "k8s.io", "images", "ls"]).stdout.decode().splitlines()
            record = next((line.split() for line in table[1:] if line.split() and line.split()[0] == loaded_tag), [])
            digest = record[2] if len(record) >= 3 else ""
            require(re.fullmatch(r"sha256:[0-9a-f]{64}", digest), "containerd did not report a manifest digest")
            pinned = "docker.io/local/backup-drill@" + digest
            run(["docker", "exec", node, "ctr", "-n", "k8s.io", "images", "tag", loaded_tag, pinned])
            save(evidence / "images.json", json.dumps({"base": BASE, "source_tag": tag, "node_manifest": digest, "chart_image": pinned}, indent=2))
            chart_values["image"] = {"host": {"repository": "docker.io/local/backup-drill", "digest": digest, "includesHealthProbe": True}, "harness": {"repository": "docker.io/local/backup-drill", "digest": digest}}
            values = work / "values.json"
            save(values, json.dumps(chart_values))
            helm = ["helm", "--kube-context", context, "--kubeconfig", str(kubeconfig)]
            save(evidence / "rendered.yaml", run(helm + ["template", release, CHART, "--namespace", namespace, "--kube-version", "1.37.0", "-f", values], env=env).stdout)
            run(base_k + ["create", "namespace", namespace], env=env)
            pvc = {"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": claim}, "spec": {"accessModes": ["ReadWriteOnce"], "storageClassName": "standard", "resources": {"requests": {"storage": "1Gi"}}}}
            run(k + ["create", "-f", "-"], input=json.dumps(pvc).encode(), env=env)
            prepare = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "prepare"}, "spec": {"restartPolicy": "Never", "initContainers": [{"name": "ownership", "image": pinned, "command": ["sh", "-c", "chown 65532:65532 /volume && chmod 0700 /volume && mkdir /volume/drill-v2 && chown 65532:65532 /volume/drill-v2 && chmod 0700 /volume/drill-v2"], "securityContext": {"runAsUser": 0, "runAsNonRoot": False}, "volumeMounts": [{"name": "data", "mountPath": "/volume"}]}], "containers": [{"name": "fixture", "image": pinned, "command": ["sh", "-c", "sleep 3600"], "securityContext": {"runAsUser": 65532, "runAsGroup": 65532}, "volumeMounts": [{"name": "data", "mountPath": "/volume"}]}], "volumes": [{"name": "data", "persistentVolumeClaim": {"claimName": claim}}]}}
            run(k + ["create", "-f", "-"], input=json.dumps(prepare).encode(), env=env)
            try:
                run(k + ["wait", "--for=condition=Ready", "pod/prepare", "--timeout=120s"], env=env)
            except RuntimeError:
                print(run(k + ["describe", "pod/prepare"], env=env, check=False).stdout.decode(), file=sys.stderr)
                raise
            save(evidence / "init.json", run(k + ["exec", "prepare", "--", "/session-fixture", "init", "--scenario", "v2", "--data", "/volume/drill-v2", "--socket", "/data/publish.sock"], env=env).stdout)
            run(k + ["exec", "prepare", "--", "sh", "-c", "umask 077; for d in daemon fixture-harness executor fake; do mkdir /volume/drill-v2/tmp-$d; done"], env=env)
            run(k + ["delete", "pod", "prepare", "--wait=true"], env=env)
            # This local kind image is Kubernetes 1.32; chart metadata requires 1.37.
            # Create the unmodified rendered workload resources, not a Helm release.
            run(k + ["create", "-f", evidence / "rendered.yaml"], env=env)
            selector = f"app.kubernetes.io/name=aks-durable-agents,app.kubernetes.io/instance={release}"
            run(k + ["rollout", "status", "deployment/drill-aks-durable-agents-harness", "--timeout=120s"], env=env)
            run(k + ["rollout", "status", "deployment/drill-aks-durable-agents-host", "--timeout=120s"], env=env)
            pods = parsed(run(k + ["get", "pods", "-l", selector, "-o", "json"], env=env))["items"]
            host_pod = next(p["metadata"]["name"] for p in pods if p["metadata"]["labels"].get("app.kubernetes.io/component") == "host")
            with forward(k, host_pod) as server:
                sequence = []
                def rpc(command, **fields):
                    payload = {"server": server, "command": command, **fields}
                    result = run([a.client], input=json.dumps(payload).encode())
                    value = parsed(result)
                    sequence.append({"command": command, "result": value})
                    return value
                created_session = rpc("create")
                uid = created_session["metadata"]["uid"]
                proposal = rpc("exec", session=uid, headSeq=0, input="Write a fictional proposal.")
                session = proposal["session"]
                last = proposal["journal"][-1]
                pending = session["pendingApproval"]
                pending["requestSeq"] = int(pending["requestSeq"])
                rpc("decide", session=uid, headSeq=int(session["lastSeq"]), headHash=last["contentHash"], pending=pending, approved=True)
                inspected = rpc("inspect", session=uid)
                session = inspected["session"]
                last = inspected["journal"][-1]
                rpc("resume", session=uid, headSeq=int(session["lastSeq"]), headHash=last["contentHash"])
            save(evidence / "session-uid.txt", uid + "\n")
            save(evidence / "rpc-sequence.json", json.dumps(sequence, indent=2))
            evidence_result = parsed(run(k + ["exec", "deployment/drill-aks-durable-agents-harness", "-c", "fixture-harness", "--", "/session-fixture", "evidence", "--scenario", "v2", "--data", "/data"], env=env))
            require(evidence_result["receiptCount"] >= 1 and evidence_result["publicationCount"] >= 1 and evidence_result["realModelCalls"] == 1, "live run did not produce durable receipt and one fake provider attempt")
            save(evidence / "source-proof.json", json.dumps(evidence_result, indent=2))
            recipe = [sys.executable, str(BACKUP)]
            flags = ["--context", context, "--kubeconfig", str(kubeconfig), "--namespace", namespace, "--release", release, "--pvc", claim, "--subpath", subpath, "--image", pinned]
            negative = run(recipe + ["backup", *flags, "--output", work / "live.tar.gz"], env=env, check=False)
            save(evidence / "negative-live.log", negative.stdout + negative.stderr)
            require(negative.returncode != 0 and b"writer Deployment must be scaled to zero" in negative.stderr and not (work / "live.tar.gz").exists(), "live-writer refusal was not proven")
            archive = evidence / "journal.tar.gz"
            backup = run(recipe + ["backup", *flags, "--output", archive, "--stop"], env=env)
            save(evidence / "backup.log", backup.stdout + backup.stderr)
            require(archive.is_file() and archive.stat().st_size > 0 and json.loads(backup.stdout.decode().strip().splitlines()[-1])["sha256"], "verified backup archive missing")
            corrupted = work / "corrupted.tar.gz"
            damaged = bytearray(archive.read_bytes())
            damaged[len(damaged) // 2] ^= 0xFF
            save(corrupted, bytes(damaged))
            restore_flags = ["--context", context, "--kubeconfig", str(kubeconfig), "--pvc", "recovered", "--subpath", subpath, "--image", pinned, "--session", uid, "--storage-class", "standard"]
            reject = run(recipe + ["restore", *restore_flags, "--namespace", recovery + "-bad", "--archive", corrupted], env=env, check=False)
            save(evidence / "negative-corrupt.log", reject.stdout + reject.stderr)
            require(reject.returncode != 0, "corrupt archive unexpectedly restored")
            absent = run(base_k + ["get", "namespace", recovery + "-bad"], env=env, check=False)
            require(absent.returncode != 0, "corrupt restore created a namespace")
            restored = run(recipe + ["restore", *restore_flags, "--namespace", recovery, "--archive", archive], env=env)
            save(evidence / "restore.log", restored.stdout + restored.stderr)
            proofs = [json.loads(line) for line in restored.stdout.decode().splitlines() if line.startswith("{")]
            replay = next((p for p in proofs if "replay" in p), {}).get("replay", {})
            require(any(p.get("socket_denial") == "verified" for p in proofs), "seccomp socket denial unproven")
            require(replay.get("completed") is True and replay.get("expected_execution_ids") and replay.get("expected_execution_ids") == replay.get("covered_execution_ids") and replay.get("provider_calls") == replay.get("executor_calls") == 0, "strict replay coverage/zero-calls unproven")
            require(any(p.get("restored_hashes") == "unchanged" for p in proofs) and any(p.get("restore") == "verified" for p in proofs), "restore hash verification incomplete")
        finally:
            if created:
                # Never delete a different cluster, even if current context changed.
                run(["kind", "delete", "cluster", "--name", lane, "--kubeconfig", kubeconfig], env=env)
        save(evidence / "summary.json", json.dumps({"passed": True, "cluster_deleted": True, "kubernetes": "1.32.2", "chart_execution": "rendered-resources-only", "cluster": lane, "source_namespace": namespace, "recovery_namespace": recovery, "session": uid, "archive": str(archive), "receipt_count": evidence_result["receiptCount"], "replay": replay}, indent=2))
        print("PASS: " + str(evidence / "summary.json"), flush=True)


if __name__ == "__main__":
    main()
