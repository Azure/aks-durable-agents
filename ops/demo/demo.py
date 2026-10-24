#!/usr/bin/env python3
"""Disposable, fake-model kind demo. Never uses the caller's Kubernetes context."""
import datetime
import json
import os
from pathlib import Path
import re
import select
import shutil
import signal
import subprocess
import sys
import time
import uuid

import netpolicy

NODE = "kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5"
CILIUM = "quay.io/cilium/cilium:v1.20.3@sha256:95cfa5c2427cc6b452c00908778d0566311f572589284af949d06a013db1a849"
OPERATOR = "quay.io/cilium/operator-generic:v1.20.3@sha256:efdd8d89d6d8f63d21a065fa2f9e17614a2b3ac9371b221af9355f63829e2dbc"
ALPINE = "alpine:3.23@sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0"
CHART_URL = "https://helm.cilium.io/cilium-1.20.3.tgz"
CHART_SHA = "0805a5273118c436c9772bb9566d87ec558d8b25cc2ce5dc32918ecdd36f2c7c"
NAMESPACE = "agent-demo"
RELEASE = "demo"
HOST_COMPONENT = "host"


class DemoError(Exception):
    pass


class Budget:
    def __init__(self, seconds=600, reserve=45):
        self.deadline = time.monotonic() + seconds
        self.reserve = reserve

    def remaining(self, cleanup=False):
        remaining = self.deadline - time.monotonic() - (0 if cleanup else self.reserve)
        if remaining <= 0:
            raise DemoError("demo deadline reached; stopping before further mutations")
        return remaining


def confirm(word, source, budget, output=sys.stdout):
    print(f"Type {word} to {'approve the fictional change' if word == 'approve' else 'Continue and perform its one fictional effect'}: ", end="", flush=True, file=output)
    answer = bytearray()
    # Read one byte at a time: a pipe containing both answers must not lose its
    # second line to a short-lived client's buffered stdin.
    while len(answer) <= 64:
        if not select.select([source.fileno()], [], [], budget.remaining())[0]:
            raise DemoError("approval input deadline reached")
        byte = os.read(source.fileno(), 1)
        if not byte:
            raise DemoError("input closed; no further approval or Continue sent")
        if byte == b"\n":
            if answer == word.encode():
                return
            break
        answer.extend(byte)
    raise DemoError(f"expected exactly {word}; no action sent (input not logged)")


def published_images(root):
    # The chart and its pin updater deliberately share a fixed image layout.
    # Reject layout drift rather than importing a general YAML dependency.
    lines = (root / "charts/aks-durable-agents/values.yaml").read_text().splitlines()
    active, role, fields = False, None, {}
    for line in lines:
        if line == "image:":
            if active or fields:
                raise DemoError("duplicate chart image configuration")
            active = True
            continue
        if active and line and not line[0].isspace() and not line.startswith("#"):
            break
        if not active:
            continue
        child = re.fullmatch(r"  (host|harness):", line)
        if child:
            role = child[1]
        field = re.fullmatch(r'    (repository|digest): "([^"\\]*)"', line)
        if field:
            key = (role, field[1])
            if key in fields:
                raise DemoError("duplicate chart image field")
            fields[key] = field[2]
    result = {}
    for role, name in [("host", "host"), ("harness", "session-fixture")]:
        repository, digest = fields.get((role,"repository")), fields.get((role,"digest"))
        if repository != "ghcr.io/azure/aks-durable-agents/" + name or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest or ""):
            raise DemoError("chart requires published host/fixture digest pins in its standard image layout")
        result[role] = repository + "@" + digest
    return result


def loaded_manifest(table, tag):
    candidates = {tag, tag if tag.startswith("docker.io/") else "docker.io/" + tag}
    rows = [line.split() for line in table.splitlines() if line.split() and line.split()[0] in candidates]
    if len(rows) != 1 or len(rows[0]) < 3 or not re.fullmatch(r"sha256:[0-9a-f]{64}", rows[0][2]):
        raise DemoError("cannot determine loaded node manifest digest; Docker config IDs are not image digests")
    return rows[0][0], rows[0][2]


def demo_values(repository, digest, run_id):
    return {
        "image":{"host":{"repository":repository,"digest":digest,"includesHealthProbe":True}},
        "workloads":{"enabled":False},
        "auth":{"mode":"off","trustedNetwork":True},
        # Schema-only placeholder: no Azure webhook/identity is installed in kind.
        "workloadIdentity":{"clientID":"55555555-5555-5555-5555-555555555555"},
        "networkPolicy":{"enabled":True},
        "persistence":{"existingClaim":"demo-data","storageClass":"standard","subPath":"demo","size":"1Gi"},
        "model":{"endpoint":"https://fake-model.invalid/openai/v1/","deployment":"demo-model","policy":{"runID":run_id,"pricing":{"inputMicroUSDPerMillionTokens":1,"outputMicroUSDPerMillionTokens":1,"extraMicroUSDPerCall":0,"source":"https://fake-model.invalid/pricing","asOf":datetime.date.today().isoformat()}}},
    }


def offline_pod(command, image):
    read_only = command == "verify"
    return {"apiVersion":"v1","kind":"Pod","metadata":{"name":command},"spec":{
        "restartPolicy":"Never","automountServiceAccountToken":False,
        "containers":[{"name":command,"image":image,"imagePullPolicy":"IfNotPresent",
            "command":["/demo-client",command,"--data","/data"],
            "securityContext":{"runAsUser":65532,"runAsGroup":65532,"runAsNonRoot":True,
                "seccompProfile":{"type":"RuntimeDefault"},"allowPrivilegeEscalation":False,
                "readOnlyRootFilesystem":True,"capabilities":{"drop":["ALL"]}},
            "volumeMounts":[{"name":"data","mountPath":"/data","subPath":"demo","readOnly":read_only}]}],
        "volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"demo-data","readOnly":read_only}}]}}


class Runner:
    def __init__(self, directory, seconds=600, reserve=45):
        self.directory = Path(directory).resolve()
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.budget = Budget(seconds, reserve)
        self.cluster = "agent-demo-" + uuid.uuid4().hex
        self.context = "kind-" + self.cluster
        self.kubeconfig = self.directory / "kubeconfig"
        self.owned = False
        self.sequence = 0
        self.kind = "kind"
        self.started = self.phase_started = time.monotonic()
        self.phase_name = "preflight"
        self.phases = []
        self.env = dict(os.environ, KUBECONFIG=str(self.kubeconfig), KIND_EXPERIMENTAL_PROVIDER="docker")

    def step(self, name):
        now=time.monotonic()
        self.phases.append({"name":self.phase_name,"seconds":now-self.phase_started})
        self.phase_name,self.phase_started=name,now
        print(name,flush=True)

    def finish_timings(self):
        now=time.monotonic()
        self.phases.append({"name":self.phase_name,"seconds":now-self.phase_started})
        (self.directory/"timings.json").write_text(json.dumps({"elapsedSeconds":now-self.started,"phases":self.phases},indent=2)+"\n")

    def run(self, arguments, data=None, check=True, cleanup=False, label=None):
        timeout = self.budget.remaining(cleanup)
        self.sequence += 1
        print("+ " + (label or " ".join(map(str,arguments))), flush=True)
        process = subprocess.Popen(list(map(str,arguments)), stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.env, start_new_session=True)
        try:
            stdout, stderr = process.communicate(data, timeout=timeout)
        except BaseException:
            # Also stop kubectl/Docker helpers in the same process group.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            raise DemoError("command interrupted or exceeded the overall demo budget")
        finally:
            for pipe in (process.stdin, process.stdout, process.stderr):
                if pipe is not None:
                    pipe.close()
        (self.directory / f"command-{self.sequence:03}.log").write_bytes((stdout + stderr)[-2*1024*1024:])
        if check and process.returncode:
            raise DemoError(f"command failed ({process.returncode}): {arguments[0]}\n" + stderr.decode(errors="replace")[-8000:])
        return stdout

    def kube(self, *arguments, data=None, check=True):
        return self.run(["kubectl","--kubeconfig",self.kubeconfig,"--context",self.context,"--namespace",NAMESPACE,*arguments], data, check)

    def helm(self, *arguments):
        return self.run(["helm","--kubeconfig",self.kubeconfig,"--kube-context",self.context,*arguments])

    def apply(self, document):
        self.kube("apply","-f","-",data=json.dumps(document).encode())

    def create_cluster(self):
        existing = self.run([self.kind,"get","clusters"]).decode().splitlines()
        if self.cluster in existing:
            raise DemoError("generated cluster name already exists; refusing ownership")
        marker = {"cluster":self.cluster,"context":self.context}
        with (self.directory/"owner.json").open("x") as output:
            json.dump(marker,output)
        self.owned = True  # A partial kind creation must also be cleaned up.
        config = self.directory / "kind.json"
        config.write_text(json.dumps({"kind":"Cluster","apiVersion":"kind.x-k8s.io/v1alpha4","networking":{"disableDefaultCNI":True},"nodes":[{"role":"control-plane"}]}))
        self.run([self.kind,"create","cluster","--name",self.cluster,"--kubeconfig",self.kubeconfig,"--image",NODE,"--config",config,"--wait","90s"])

    def cleanup(self):
        if not re.fullmatch(r"agent-demo-[0-9a-f]{32}", self.cluster):
            raise DemoError("refusing cleanup without a generated demo cluster identity")
        if not self.owned:
            return
        marker = json.loads((self.directory/"owner.json").read_text())
        if marker != {"cluster":self.cluster,"context":self.context}:
            raise DemoError("refusing cleanup: owned cluster marker mismatch")
        self.run([self.kind,"delete","cluster","--name",self.cluster,"--kubeconfig",self.kubeconfig],cleanup=True)
        self.owned = False

    def component(self, resource, component):
        items = json.loads(self.kube("get",resource,"-l",f"app.kubernetes.io/instance={RELEASE},app.kubernetes.io/component={component}","-o","json"))["items"]
        if len(items) != 1:
            raise DemoError(f"expected one {component} {resource}, found {len(items)}")
        return items[0]

    def replace_host(self, old):
        self.kube("delete","pod",old["metadata"]["name"],"--wait=true")
        # Deletion does not change a Deployment generation: rollout status can
        # still report the old available replica. Observe the actual new UID,
        # then wait for that specific pod, without extending the 90s budget.
        deadline = time.monotonic() + min(90,self.budget.remaining())
        def remaining():
            seconds = min(deadline-time.monotonic(),self.budget.remaining())
            if seconds < 0.001:
                raise DemoError("replacement host did not appear and become Ready within its readiness budget")
            return seconds
        while True:
            timeout = remaining()
            pods = json.loads(self.kube("get","pods","-l",f"app.kubernetes.io/instance={RELEASE},app.kubernetes.io/component={HOST_COMPONENT}","-o","json",f"--request-timeout={min(10,timeout):.3f}s"))["items"]
            replacements = [pod for pod in pods if pod["metadata"]["uid"] != old["metadata"]["uid"] and not pod["metadata"].get("deletionTimestamp")]
            if len(replacements) > 1:
                raise DemoError("expected one replacement host pod, found multiple")
            if replacements:
                replacement = replacements[0]
                timeout = remaining()
                self.kube("wait","--for=condition=Ready","pod/"+replacement["metadata"]["name"],f"--timeout={timeout:.3f}s",f"--request-timeout={timeout:.3f}s")
                return replacement
            time.sleep(min(0.1,remaining()))

    def cli(self, pod, *arguments):
        return json.loads(self.kube("exec",pod,"-c","daemon","--","/demo-client",*arguments,"--data","/data"))

    def evidence(self, pod):
        return json.loads(self.kube("exec",pod,"-c","fixture-harness","--","/session-fixture","evidence","--scenario","v2","--data","/data"))


def preflight(runner):
    for command in ["docker","kind","kubectl","helm"]:
        if shutil.which(command) is None:
            raise DemoError(f"missing prerequisite: {command}")
    version = runner.run(["kind","version"]).decode()
    match = re.search(r"v0\.(\d+)\.", version)
    if not match or int(match[1]) < 33:
        raise DemoError("kind v0.33.0 or newer is required for the pinned Kubernetes 1.37 node; installed kind is not changed")
    info = json.loads(runner.run(["docker","info","--format",'{"Architecture":"{{.Architecture}}","OSType":"{{.OSType}}"}']))
    if info.get("OSType") != "linux" or info.get("Architecture") not in ["x86_64","amd64"]:
        raise DemoError("this demo currently requires a Linux/amd64 Docker backend")
    runner.run(["kubectl","version","--client","--output=json"])
    runner.run(["helm","version","--short"])


def check_effects(evidence, model, effects):
    if evidence.get("fakeModelCalls") != 0 or evidence.get("realModelCalls") != model or evidence.get("publicationCount") != effects or evidence.get("receiptCount") != effects or len(evidence.get("artifacts",[])) != effects:
        raise DemoError("model/publication/receipt inventory did not match the demo step: " + json.dumps(evidence))


def run_demo(runner, root):
    print("DEMO ONLY: fictional release-note change, deterministic local fake model, identity not exercised.\nThis is not an Azure or real cluster-change qualification.",flush=True)
    preflight(runner)
    images = published_images(root)
    # Validate the actual chart before building or allocating a cluster. Use its
    # real published host pin for this render, never a fabricated digest.
    repository, published_digest = images["host"].split("@")
    preflight_values = runner.directory / "preflight-values.json"
    preflight_values.write_text(json.dumps(demo_values(repository,published_digest,runner.cluster)))
    runner.helm("template",RELEASE,root/"charts/aks-durable-agents","--namespace",NAMESPACE,"--kube-version","1.37.0","-f",preflight_values)
    local_repository = "docker.io/local/aks-durable-agents/demo-host"
    tag = local_repository + ":" + runner.cluster
    runner.step("1. Build a separate local demo image from the published host (not for production).")
    runner.run(["docker","build","--platform","linux/amd64","--build-arg","HOST_IMAGE="+images["host"],"-f",root/"ops/demo/Dockerfile","-t",tag,root])
    chart = runner.directory / "cilium.tgz"
    # A child process puts DNS, TLS and even a trickling download under the
    # same wall-clock command deadline, not just a per-socket read timeout.
    download = """import hashlib, pathlib, sys, urllib.request
with urllib.request.urlopen(sys.argv[1], timeout=30) as response:
    raw = response.read(16*1024*1024+1)
if len(raw)>16*1024*1024 or hashlib.sha256(raw).hexdigest()!=sys.argv[2]:
    sys.exit('Cilium chart checksum/size mismatch')
pathlib.Path(sys.argv[3]).write_bytes(raw)
"""
    runner.run([sys.executable,"-c",download,CHART_URL,CHART_SHA,chart],label="download Cilium chart (bounded, SHA-256 verified)")
    runner.step("2. Create an owned kind cluster and install enforcing Cilium policies.")
    runner.create_cluster()
    runner.helm("install","cilium",chart,"--namespace","kube-system","--set","ipam.mode=kubernetes","--set","operator.replicas=1","--set","kubeProxyReplacement=false","--set","cgroup.autoMount.enabled=false","--set","cgroup.hostRoot=/sys/fs/cgroup","--set","envoy.enabled=false","--set","l7Proxy=false","--wait","--timeout","180s")
    cni = json.loads(runner.kube("get","daemonset/cilium","deployment/cilium-operator","--namespace","kube-system","-o","json"))
    cni_images = {container["image"] for item in cni["items"] for container in item["spec"]["template"]["spec"]["containers"]}
    for pin in (CILIUM, OPERATOR):
        if not cni_images.intersection({pin,pin.replace(":v1.20.3","")}):
            raise DemoError("Cilium did not use the expected digest-pinned images")
    runner.run(["kind","load","docker-image",tag,"--name",runner.cluster])
    node = runner.cluster + "-control-plane"
    table = runner.run(["docker","exec",node,"ctr","-n","k8s.io","images","ls"]).decode()
    reference, digest = loaded_manifest(table, tag)
    runner.run(["docker","exec",node,"ctr","-n","k8s.io","images","tag",reference,local_repository+"@"+digest])
    runner.apply({"apiVersion":"v1","kind":"Namespace","metadata":{"name":NAMESPACE}})
    runner.apply({"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy","metadata":{"name":"demo-default-deny"},"spec":{"podSelector":{},"policyTypes":["Ingress","Egress"]}})
    runner.apply({"apiVersion":"v1","kind":"PersistentVolumeClaim","metadata":{"name":"demo-data"},"spec":{"accessModes":["ReadWriteOnce"],"storageClassName":"standard","resources":{"requests":{"storage":"1Gi"}}}})
    volume = {"name":"data","persistentVolumeClaim":{"claimName":"demo-data"}}
    security = {"runAsUser":65532,"runAsGroup":65532,"runAsNonRoot":True,"seccompProfile":{"type":"RuntimeDefault"}}
    runner.apply({"apiVersion":"v1","kind":"Pod","metadata":{"name":"prepare"},"spec":{"restartPolicy":"Never","automountServiceAccountToken":False,"initContainers":[{"name":"ownership","image":ALPINE,"command":["/bin/sh","-ec","test ! -e /volume/demo; mkdir -m 0700 /volume/demo; chown 65532:65532 /volume/demo"],"securityContext":{"runAsUser":0,"runAsNonRoot":False,"allowPrivilegeEscalation":False,"readOnlyRootFilesystem":True,"capabilities":{"drop":["ALL"],"add":["CHOWN"]}},"volumeMounts":[{"name":"data","mountPath":"/volume"}]}],"containers":[{"name":"prepare","image":local_repository+"@"+digest,"imagePullPolicy":"IfNotPresent","command":["/demo-client","prepare","--data","/volume/demo"],"securityContext":dict(security,allowPrivilegeEscalation=False,readOnlyRootFilesystem=True,capabilities={"drop":["ALL"]}),"volumeMounts":[{"name":"data","mountPath":"/volume"}]}],"volumes":[volume]}})
    runner.kube("wait","--for=jsonpath={.status.phase}=Succeeded","pod/prepare","--timeout=90s")
    runner.kube("delete","pod","prepare","--wait=true")
    values = runner.directory / "values.json"
    values.write_text(json.dumps(demo_values(local_repository,digest,runner.cluster)))
    runner.helm("install",RELEASE,root/"charts/aks-durable-agents","--namespace",NAMESPACE,"-f",values)
    deployments = {}
    # Placement must exist before the host starts: stage the ephemeral release
    # with scale rather than racing a host against its fixture's marker.
    for component in ["harness",HOST_COMPONENT]:
        name = runner.component("deployments",component)["metadata"]["name"]
        deployments[component] = name
        runner.kube("scale","deployment/"+name,"--replicas=1")
        runner.kube("rollout","status","deployment/"+name,"--timeout=90s")
    daemon = runner.component("pods",HOST_COMPONENT)
    harness_pod = runner.component("pods","harness")
    harness = harness_pod["metadata"]["name"]
    pod = daemon["metadata"]["name"]
    check_effects(runner.evidence(harness),0,0)
    if runner.cli(pod,"counter")["modelHTTPCalls"] != 0:
        raise DemoError("unexpected model HTTP call before starting the session")
    runner.step("2b. NetworkPolicy controls and denials: effective policy must not over-allow.")
    netpolicy.run_checks(runner,images["harness"],ALPINE,daemon,harness_pod)
    check_effects(runner.evidence(harness),0,0)
    if runner.cli(pod,"counter")["modelHTTPCalls"] != 0:
        raise DemoError("network controls changed the model HTTP inventory")
    runner.step("3. Agent prepares a fictional change and parks for approval.")
    parked = runner.cli(pod,"park")
    print(parked["draft"],flush=True)
    before = runner.evidence(harness)
    check_effects(before,1,0)
    runner.step("4. Restart the host while parked; verify the same pending change survived.")
    replacement = runner.replace_host(daemon)
    pod = replacement["metadata"]["name"]
    runner.cli(pod,"check-parked")
    if runner.evidence(harness) != before or runner.cli(pod,"counter")["modelHTTPCalls"] != 1:
        raise DemoError("restart repeated inference or changed parked effects")
    runner.step("5. Approve, without continuing yet (CLI consent, not authenticated identity).")
    confirm("approve",sys.stdin,runner.budget)
    runner.cli(pod,"approve")
    if runner.evidence(harness) != before:
        raise DemoError("approval alone performed an effect")
    print("Approval recorded; effects remain zero.",flush=True)
    confirm("continue",sys.stdin,runner.budget)
    runner.cli(pod,"continue")
    check_effects(runner.evidence(harness),1,1)
    runner.step("6. Exactly one fictional publication and receipt; stop all writers.")
    for name in deployments.values():
        runner.kube("scale","deployment/"+name,"--replicas=0")
    runner.kube("wait","--for=delete","pods","-l","app.kubernetes.io/instance="+RELEASE,"--timeout=60s")
    runner.step("7. DEMO-ONLY seal: checkpoint stopped stores, preserve logical head/counters, then make no more writes. Real hosts do not do this.")
    runner.apply(offline_pod("seal",local_repository+"@"+digest))
    runner.kube("wait","--for=jsonpath={.status.phase}=Succeeded","pod/seal","--timeout=60s")
    sealed = json.loads(runner.kube("logs","seal"))
    if sealed.get("sealed") is not True or sealed.get("session") != parked["session"]:
        raise DemoError("sealing did not preserve the completed session")
    runner.kube("delete","pod","seal","--wait=true")
    runner.step("8. Replay once from a read-only mount: no model or tool calls.")
    runner.apply(offline_pod("verify",local_repository+"@"+digest))
    runner.kube("wait","--for=jsonpath={.status.phase}=Succeeded","pod/verify","--timeout=60s")
    proof = json.loads(runner.kube("logs","verify"))
    if proof.get("provider_calls")!=0 or proof.get("executor_calls")!=0 or not proof.get("completed"):
        raise DemoError("missing strict zero-call replay proof")
    (runner.directory/"proof.json").write_text(json.dumps(proof,indent=2)+"\n")
    print("Scenario checks passed: same parked session survived restart; Approve alone had zero effects; Continue made exactly one effect; strict replay made zero model/tool calls.",flush=True)


def main():
    if len(sys.argv)>1:
        if sys.argv[1:] == ["--help"]:
            print(__doc__)
            return 0
        raise DemoError("make demo takes no cluster/context overrides")
    os.umask(0o077)
    root = Path(__file__).resolve().parents[2]
    directory = root/".build/demo"/uuid.uuid4().hex
    runner = Runner(directory)
    start = time.monotonic()
    def interrupted(signum, frame):
        raise DemoError("demo interrupted; cleaning owned resources")
    previous = {sig:signal.signal(sig,interrupted) for sig in [signal.SIGINT,signal.SIGTERM]}
    failed = False
    try:
        run_demo(runner,root)
    except (DemoError,OSError,ValueError) as error:
        failed = True
        print("DEMO FAILED: "+str(error),file=sys.stderr)
        if runner.owned:
            try:
                pods = json.loads(runner.kube("get","pods","-o","json",check=False))
                runner.kube("get","events","--sort-by=.lastTimestamp",check=False)
                for pod in pods.get("items",[])[:5]:
                    runner.kube("logs",pod["metadata"]["name"],"--all-containers=true","--tail=80",check=False)
            except (DemoError,OSError,ValueError):
                pass
    finally:
        for sig in previous:
            signal.signal(sig,signal.SIG_IGN)
        try:
            if runner.owned:
                runner.step("9. Delete only this demo's owned kind cluster.")
            runner.cleanup()
        except (DemoError,OSError) as error:
            failed = True
            print(f"CLEANUP FAILED: {error}\nRemove only this owned cluster: KIND_EXPERIMENTAL_PROVIDER=docker kind delete cluster --name {runner.cluster} --kubeconfig {runner.kubeconfig}",file=sys.stderr)
        for sig,handler in previous.items():
            signal.signal(sig,handler)
        try:
            runner.finish_timings()
        except OSError as error:
            failed = True
            print(f"TIMING RECORD FAILED: {error}",file=sys.stderr)
        print(f"Elapsed including build/bootstrap/cleanup: {time.monotonic()-start:.1f}s. Evidence: {directory}",flush=True)
    if not failed:
        print("PASS: demo complete and owned cluster removed.",flush=True)
    return int(failed)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (DemoError,OSError) as error:
        print(str(error),file=sys.stderr)
        sys.exit(1)
