#!/usr/bin/env python3
"""Local-only owned kind proof for native Canvas producers and network policy."""
import argparse
import contextlib
import hashlib
import http.cookiejar
import json
import os
import re
import socket
import subprocess
import time
import urllib.request
import uuid
from pathlib import Path

from images import REPO, check_paths, save

CHART = REPO / "charts/aks-durable-agents"
NODE = "kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5"
CILIUM = "quay.io/cilium/cilium:v1.20.3@sha256:95cfa5c2427cc6b452c00908778d0566311f572589284af949d06a013db1a849"
OPERATOR = "quay.io/cilium/operator-generic:v1.20.3@sha256:efdd8d89d6d8f63d21a065fa2f9e17614a2b3ac9371b221af9355f63829e2dbc"
CILIUM_CHART_SHA = "0805a5273118c436c9772bb9566d87ec558d8b25cc2ce5dc32918ecdd36f2c7c"


def validate_manifest(metadata):
    entries, tags = metadata.get("entries", []), metadata.get("tags", {})
    if metadata.get("drillOnly") is not True or metadata.get("identityExercised") is not False or not 1 <= len(entries) <= 32:
        raise ValueError("only diagnostic images and a nonempty native inventory are eligible")
    if any(not tags.get(k, "").startswith("local/canvas-drill-" + suffix + ":") for k, suffix in (("host", "host"), ("producer", "producer"))):
        raise ValueError("not a locally built diagnostic image")
    ids, ports = set(), set()
    for entry in entries:
        identity, port = entry.get("id", ""), entry.get("port")
        if not re.fullmatch(r"bundle-v4-[0-9a-f]{64}", identity) or type(port) is not int or not 1 <= port <= 65535 or port == 8081 or identity in ids or port in ports:
            raise ValueError("native inventory must have exact unique identities and ports")
        ids.add(identity)
        ports.add(port)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run(args, *, input=None, check=True, timeout=300):
    print("+", " ".join(map(str, args)), flush=True)
    try:
        result = subprocess.run(list(map(str, args)), input=input, cwd=REPO, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        message = f"timed out after {timeout}s"
        if not check:
            return subprocess.CompletedProcess(error.cmd, 124, error.stdout or b"", (error.stderr or b"") + b"\n" + message.encode())
        raise RuntimeError(f"{message}: {' '.join(map(str, args))}") from error
    if check and result.returncode:
        raise RuntimeError(f"exit {result.returncode}: {result.stderr.decode(errors='replace')} {result.stdout.decode(errors='replace')}")
    return result


def parsed(args):
    return json.loads(run(args).stdout)


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def wait_port(port, process):
    for _ in range(150):
        require(process.poll() is None, "local forward/engine exited before readiness; inspect evidence log")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("local forward/engine did not bind")


@contextlib.contextmanager
def process(args, log):
    with log.open("wb") as output:
        child = subprocess.Popen(list(map(str, args)), stdout=output, stderr=subprocess.STDOUT, cwd=REPO)
        try:
            yield child
        finally:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()


def verify_policy_drops(probes, drops):
    # Fail closed on format drift in the pinned Cilium monitor output.
    for probe in probes:
        if probe["expected"] != "denied":
            continue
        flow = re.compile(rf"\s{re.escape(probe['source'])}:\d+ -> {re.escape(probe['target'])} tcp\b")
        require(any("Policy denied" in line and flow.search(line) for line in drops.splitlines()),
                f"missing policy drop: {probe['source']} -> {probe['target']}")


def verify_initial_counters(counters):
    require(counters["http"] == 0 and counters["credentials"] == 0 and counters["attempts"] == [],
            "initial counters must be empty")


def verify_restarted_pods(before, after):
    for role in ("host", "harness"):
        require(before[role]["metadata"]["uid"] != after[role]["metadata"]["uid"],
                f"{role} pod was not replaced")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--canvas", type=Path, required=True)
    parser.add_argument("--kind", default="kind", help="kind v0.33.0 executable; never replaces a global installation")
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--cilium-chart", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    kind = args.kind
    require(run([kind, "version"]).stdout.decode().startswith("kind v0.33.0 "), "use kind v0.33.0 for the pinned Kubernetes 1.37 node")
    canvas, artifacts, evidence = args.canvas.resolve(), args.artifacts.resolve(), args.evidence.absolute()
    check_paths(canvas, evidence)
    metadata = json.loads((artifacts / "images.json").read_text())
    validate_manifest(metadata)
    definition = Path(metadata["definition"])
    require(hashlib.sha256(definition.read_bytes()).hexdigest() == metadata["definitionSHA256"], "definition changed after archive export")
    require(hashlib.sha256(args.cilium_chart.read_bytes()).hexdigest() == CILIUM_CHART_SHA, "Cilium chart digest mismatch")
    for name, digest in metadata["binarySHA256"].items():
        require(re.fullmatch(r"[a-z-]+", name) and hashlib.sha256((artifacts / "bin" / name).read_bytes()).hexdigest() == digest, "qualification binary mismatch")
    evidence.mkdir(mode=0o700, parents=True)
    cluster = "canvas-proof-" + uuid.uuid4().hex[:10]
    kubeconfig = evidence / "kubeconfig"
    base = ["kubectl", "--context", "kind-" + cluster, "--kubeconfig", str(kubeconfig)]
    k = base + ["--namespace", "canvas-proof"]
    helm = ["helm", "--kube-context", "kind-" + cluster, "--kubeconfig", str(kubeconfig)]
    require(cluster not in run([kind, "get", "clusters"]).stdout.decode().splitlines(), "refuse existing cluster")
    save(evidence / "ownership.json", {"cluster": cluster, "context": "kind-" + cluster, "node": NODE})
    save(evidence / "kind.json", {"kind": "Cluster", "apiVersion": "kind.x-k8s.io/v1alpha4", "nodes": [{"role": "control-plane"}], "networking": {"disableDefaultCNI": True}})
    created = True
    try:
        run([kind, "create", "cluster", "--name", cluster, "--kubeconfig", kubeconfig, "--image", NODE, "--config", evidence / "kind.json"])
        node = cluster + "-control-plane"
        for image in (CILIUM, OPERATOR):
            # Vendor digest references must retain their canonical registry name.
            # Docker archive import can leave a dangling import-date CRI alias.
            run(["docker", "exec", node, "ctr", "-n", "k8s.io", "images", "pull", "--platform", "linux/amd64", image])
        run(helm + ["install", "cilium", args.cilium_chart, "--namespace", "kube-system", "--set", "ipam.mode=kubernetes", "--set", "operator.replicas=1", "--set", "kubeProxyReplacement=false", "--set", "cgroup.autoMount.enabled=false", "--set", "cgroup.hostRoot=/sys/fs/cgroup", "--set", "envoy.enabled=false", "--set", "l7Proxy=false", "--wait", "--timeout", "180s"])
        run(base + ["wait", "--for=condition=Ready", "nodes", "--all", "--timeout=120s"])
        pinned = {}
        node = cluster + "-control-plane"
        for role, tag in metadata["tags"].items():
            run([kind, "load", "docker-image", tag, "--name", cluster])
            table = run(["docker", "exec", node, "ctr", "-n", "k8s.io", "images", "ls"]).stdout.decode().splitlines()
            record = next((line.split() for line in table[1:] if line.split()[0] in (tag, "docker.io/" + tag)), [])
            require(len(record) > 2 and re.fullmatch(r"sha256:[0-9a-f]{64}", record[2]), "node manifest digest unavailable")
            repository = "docker.io/" + tag.split(":")[0]
            pinned[role] = {"repository": repository, "digest": record[2]}
            run(["docker", "exec", node, "ctr", "-n", "k8s.io", "images", "tag", record[0], repository + "@" + record[2]])
        save(evidence / "images.json", {"built": metadata, "nodeManifests": pinned, "cilium": CILIUM, "operator": OPERATOR, "chartSHA256": CILIUM_CHART_SHA})
        values = json.loads((CHART / "tests/default-inputs.yaml").read_text())
        values["auth"] = {"mode": "off", "trustedNetwork": True}
        values["image"] = {"host": {**pinned["host"], "includesHealthProbe": True}, "harness": pinned["producer"]}
        values["model"]["endpoint"] = "https://canvas-fake.invalid/openai/v1/"
        values["model"]["deployment"] = "gpt-5.6-terra"
        values["model"]["policy"]["runID"] = cluster
        values["persistence"] = {"existingClaim": "data", "subPath": "native-v1", "storageClass": "standard"}
        values["workloads"] = {"enabled": False}
        values["harness"] = {"native": {"enabled": True, "entries": metadata["entries"]}}
        save(evidence / "values.json", values)
        run(base + ["create", "namespace", "canvas-proof"])
        run(k + ["create", "-f", "-"], input=json.dumps({"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": "data"}, "spec": {"accessModes": ["ReadWriteOnce"], "storageClassName": "standard", "resources": {"requests": {"storage": "1Gi"}}}}).encode())
        run(helm + ["install", "drill", CHART, "--namespace", "canvas-proof", "-f", evidence / "values.json"])
        host_image = pinned["host"]["repository"] + "@" + pinned["host"]["digest"]
        mount = [{"name": "data", "mountPath": "/volume"}]
        prep = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "prepare"}, "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False, "initContainers": [{"name": "ownership", "image": host_image, "command": ["sh", "-c", "chown 65532:65532 /volume && chmod 0700 /volume"], "securityContext": {"runAsUser": 0}, "volumeMounts": mount}], "containers": [{"name": "prepare", "image": host_image, "command": ["python3", "-c", "import os,shutil; os.mkdir('/volume/native-v1',0o700); [os.mkdir('/volume/native-v1/'+n,0o700) for n in ('tmp-daemon','tmp-producer')]; shutil.copytree('/seed/producers','/volume/native-v1/producers')"], "securityContext": {"runAsUser": 65532, "runAsGroup": 65532}, "volumeMounts": mount}], "volumes": [{"name": "data", "persistentVolumeClaim": {"claimName": "data"}}]}}
        run(k + ["create", "-f", "-"], input=json.dumps(prep).encode())
        run(k + ["wait", "--for=jsonpath={.status.phase}=Succeeded", "pod/prepare", "--timeout=120s"])
        run(k + ["delete", "pod", "prepare", "--wait=true"])
        run(helm + ["upgrade", "drill", CHART, "--namespace", "canvas-proof", "-f", evidence / "values.json", "--set", "workloads.enabled=true"])
        deployments = {"host": "drill-aks-durable-agents-host", "producer": "drill-aks-durable-agents-harness"}
        for deployment in deployments.values():
            run(k + ["rollout", "status", "deployment/" + deployment, "--timeout=120s"])

        def pods():
            items = parsed(k + ["get", "pods", "-l", "app.kubernetes.io/instance=drill", "-o", "json"])["items"]
            found = {p["metadata"]["labels"]["app.kubernetes.io/component"]: p for p in items if not p["metadata"].get("deletionTimestamp")}
            require(found["host"]["spec"]["nodeName"] == found["harness"]["spec"]["nodeName"], "placement split across nodes")
            return found

        current = pods()
        before_pods = current
        save(evidence / "pods-before.json", before_pods)
        # A live sink on private port 443 and a live host-pod listener prevent
        # closed-port failures being mistaken for policy enforcement.
        sink = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "outside"}, "spec": {"automountServiceAccountToken": False, "containers": [{"name": "probe", "image": host_image, "command": ["/netprobe", "listen", "0.0.0.0:443"], "securityContext": {"runAsUser": 0, "allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"], "add": ["NET_BIND_SERVICE"]}}}]}}
        run(k + ["create", "-f", "-"], input=json.dumps(sink).encode())
        run(k + ["wait", "--for=condition=Ready", "pod/outside", "--timeout=120s"])
        hp, pp = current["host"]["metadata"]["name"], current["harness"]["metadata"]["name"]
        hi, pi = current["host"]["status"]["podIP"], current["harness"]["status"]["podIP"]
        sink_ip = parsed(k + ["get", "pod", "outside", "-o", "json"])["status"]["podIP"]
        run(k + ["exec", hp, "-c", "daemon", "--", "python3", "-c", "import subprocess; subprocess.Popen(['/netprobe','listen','0.0.0.0:9444'],start_new_session=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)"])
        cilium_pod = parsed(base + ["-n", "kube-system", "get", "pods", "-l", "k8s-app=cilium", "-o", "json"])["items"][0]["metadata"]["name"]
        probes = []
        with process(base + ["-n", "kube-system", "exec", cilium_pod, "--", "cilium-dbg", "monitor", "--type", "drop"], evidence / "drops.log"):
            time.sleep(1)
            for pod, container, target, expected in [
                (pp, "producer", "127.0.0.1:8081", "allowed"),
                (hp, "daemon", hi + ":9444", "allowed"),
                ("outside", "probe", sink_ip + ":443", "allowed"),
                *[(hp, "daemon", pi + ":" + str(e["port"]), "allowed") for e in metadata["entries"]],
                (hp, "daemon", pi + ":8081", "denied"),
                ("outside", "probe", pi + ":8081", "denied"),
                ("outside", "probe", pi + ":" + str(metadata["entries"][0]["port"]), "denied"),
                (pp, "producer", hi + ":9444", "denied"),
                (pp, "producer", sink_ip + ":443", "denied"),
                (hp, "daemon", sink_ip + ":443", "denied"),
            ]:
                run(k + ["exec", pod, "-c", container, "--", "/netprobe", "connect", target, expected])
                probes.append({"pod": pod, "source": {hp: hi, pp: pi, "outside": sink_ip}[pod], "target": target, "expected": expected, "matched": True})
        save(evidence / "network.json", probes)
        drops = (evidence / "drops.log").read_text()
        verify_policy_drops(probes, drops)

        def counters():
            code = "import json,sqlite3,pathlib,hashlib; p=pathlib.Path('/data/fake-http.jsonl'); q=pathlib.Path('/data/fake-credential.jsonl'); j=sqlite3.connect('file:/data/journal.db?mode=ro',uri=True); c=sqlite3.connect('file:/data/real-attempts.db?mode=ro',uri=True); print(json.dumps({'http':len(p.read_text().splitlines()) if p.exists() else 0,'credentials':len(q.read_text().splitlines()) if q.exists() else 0,'journalSHA256':hashlib.sha256('\\n'.join(j.iterdump()).encode()).hexdigest(),'observations':[json.loads(line) for line in p.read_text().splitlines()] if p.exists() else [],'attempts':c.execute('select id,outcome,input_tokens,output_tokens from model_attempts order by id').fetchall()}))"
            return parsed(k + ["exec", "deployment/" + deployments["host"], "-c", "daemon", "--", "python3", "-c", code])

        history = [{"stage": "before", "counters": counters()}]
        verify_initial_counters(history[0]["counters"])
        engine_state = evidence / "engine-state"
        turns = []
        for phase in ("writer", "reviewer"):
            current = pods()
            port, engine_port = free_port(), free_port()
            with process(k + ["port-forward", "--address=127.0.0.1", "pod/" + current["host"]["metadata"]["name"], f"{port}:8080"], evidence / (phase + "-forward.log")) as forward:
                wait_port(port, forward)
                cmd = [artifacts / "bin/copilot-review", "-root", canvas, "-definition", definition, "-state", engine_state, "-listen", f"127.0.0.1:{engine_port}", "-sessions-trusted-loopback", f"127.0.0.1:{port}"]
                with process(cmd, evidence / (phase + "-engine.log")) as engine:
                    wait_port(engine_port, engine)
                    url = f"http://127.0.0.1:{engine_port}"
                    browser = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

                    def request(path, value=None):
                        data = json.dumps(value).encode() if value is not None else None
                        req = urllib.request.Request(url + path, data=data, headers={"Origin": url, "Content-Type": "application/json"})
                        with browser.open(req, timeout=10) as response:
                            body = response.read()
                            return json.loads(body) if body.startswith(b"{") else None

                    def turn(agent, suffix=""):
                        created_run = request("/api/run", {"agent": agent, "role": "GM", "request": "canvas-kind-" + agent + suffix})["run"]
                        for _ in range(300):
                            state = request("/api/state")
                            result = next(r for r in state["runs"] if r["id"] == created_run)
                            if result["status"] in ("proposed", "failed", "refused", "uncertain"):
                                return result
                            time.sleep(0.1)
                        raise RuntimeError("Canvas turn did not terminate")

                    request("/")
                    result = turn(phase)
                    turns.append(result)
                    save(evidence / "turns.json", turns)
                    save(evidence / "current-counters.json", counters())
                    require(result["status"] == "proposed" and result["model"] == "gpt-5.6-terra" and result["evaluation"] == "not verified", "fake Canvas proposal not produced")
                    if phase == "writer":
                        request("/api/review", {"proposal": result["proposal"], "action": "accept", "role": "GM"})
                    else:
                        blocked = turn("writer", " third dispatch must be refused")
                        turns.append(blocked)
                        require(blocked["status"] in ("failed", "refused", "uncertain") and not blocked.get("proposal"), "budget cap admitted a third proposal")
            history.append({"stage": phase, "counters": counters()})
            require(history[-1]["counters"]["http"] == len(history) - 1 and history[-1]["counters"]["credentials"] == len(history) - 1, "provider/credential attempt count or retry mismatch")
            if phase == "writer":
                for deployment in deployments.values():
                    run(k + ["rollout", "restart", "deployment/" + deployment])
                    run(k + ["rollout", "status", "deployment/" + deployment, "--timeout=120s"])
                require(counters() == history[-1]["counters"], "restart reset model history/budget")
        require(len(history[-1]["counters"]["attempts"]) == 2 and all(row[1] == "succeeded" for row in history[-1]["counters"]["attempts"]), "durable ledger not exactly two successes")
        require(all(event["requestBytes"] < 6500 for event in history[-1]["counters"]["observations"]), "compact request lost its input-bound margin")
        require(history[-1]["counters"]["observations"][-1]["acceptedDocumentsObserved"] is True, "reviewer did not observe exact accepted writer bytes")
        save(evidence / "turns.json", turns)
        save(evidence / "counters.json", history)
        after_pods = pods()
        verify_restarted_pods(before_pods, after_pods)
        save(evidence / "pods-after.json", after_pods)
        save(evidence / "summary.json", {"passed": True, "drillOnlyImages": True, "identityExercised": False, "realModelCalls": 0, "fakeHTTPCalls": 2, "fakeCredentialCalls": 2, "hostBudgetRows": 2, "journalPreservedAcrossRestart": True, "networkDenials": 6, "cluster": cluster, "node": NODE})
    except BaseException:
        # Keep diagnosis before deleting the owned cluster; a failed timeout is
        # evidence, not permission to extend it or claim a CNI proof.
        for name, command in (
            ("failed-nodes.json", base + ["get", "nodes", "-o", "json"]),
            ("failed-pods.json", base + ["get", "pods", "-A", "-o", "json"]),
            ("failed-events.txt", base + ["get", "events", "-A", "--sort-by=.lastTimestamp"]),
            ("failed-host.log", k + ["logs", "deployment/drill-aks-durable-agents-host", "-c", "daemon", "--tail=100"]),
            ("failed-producer.log", k + ["logs", "deployment/drill-aks-durable-agents-harness", "-c", "producer", "--tail=100"]),
            ("failed-cilium.log", base + ["-n", "kube-system", "logs", "ds/cilium", "--all-containers", "--tail=100"]),
            ("failed-kubelet.log", ["docker", "exec", cluster + "-control-plane", "journalctl", "-u", "kubelet", "--no-pager", "-n", "100"]),
            ("failed-cni.txt", ["docker", "exec", cluster + "-control-plane", "ls", "-la", "/etc/cni/net.d", "/opt/cni/bin"]),
        ):
            result = run(command, check=False, timeout=30)
            (evidence / name).write_bytes(result.stdout + result.stderr)
        raise
    finally:
        # Only the UUID name reserved above; never use the current kubectl context.
        if created:
            run([kind, "delete", "cluster", "--name", cluster, "--kubeconfig", kubeconfig])
    print("PASS:", evidence / "summary.json", flush=True)


if __name__ == "__main__":
    main()
