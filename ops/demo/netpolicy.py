"""TCP controls and effective-policy denial proofs, without data-volume access."""
import ipaddress
import json

SECURITY = {"runAsUser":65532,"runAsGroup":65532,"runAsNonRoot":True,
            "allowPrivilegeEscalation":False,"readOnlyRootFilesystem":True,
            "seccompProfile":{"type":"RuntimeDefault"},"capabilities":{"drop":["ALL"]}}


def address(value):
    ip=ipaddress.IPv4Address(value)
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast:
        raise ValueError("network proof requires a literal unicast pod IP")
    return str(ip)+":9000"


def policy_labels(pod):
    labels=pod["metadata"]["labels"]
    return {key:labels[key] for key in ("app.kubernetes.io/name","app.kubernetes.io/instance","app.kubernetes.io/component")}


def probe_job(name,labels,image,control,denial):
    def container(stage,target,expect):
        return {"name":stage,"image":image,"securityContext":SECURITY,
                "command":["/session-fixture","network-probe","--address",target,"--expect",expect]}
    return {"apiVersion":"batch/v1","kind":"Job","metadata":{"name":name},"spec":{
        "backoffLimit":0,"activeDeadlineSeconds":60,"template":{"metadata":{"labels":labels},"spec":{
            "restartPolicy":"Never","automountServiceAccountToken":False,
            "initContainers":[container("control",control,"allowed")],
            "containers":[container("denial",denial,"denied")]}}}}


def proof(raw,target,expect,case,stage):
    result=json.loads(raw)
    wanted={"address":target,"allowed":expect=="allowed","expect":expect,"tcpOnly":True}
    if result!=wanted or type(result.get("allowed")) is not bool or result.get("tcpOnly") is not True:
        raise ValueError("network probe did not produce the exact TCP control/denial proof")
    return dict(result,case=case,stage=stage)


def run_checks(runner,fixture_ref,alpine_ref,host,harness):
    peer_labels={"demo-network-peer":runner.cluster}
    source_labels=dict(policy_labels(host),**{"app.kubernetes.io/component":"network-probe"})
    harness_labels=policy_labels(harness)
    runner.apply({"apiVersion":"v1","kind":"Pod","metadata":{"name":"network-peer","labels":peer_labels},"spec":{
        "restartPolicy":"Never","automountServiceAccountToken":False,
        "containers":[{"name":"listener","image":alpine_ref,"securityContext":SECURITY,
            "command":["/bin/busybox","nc","-lk","-p","9000","-e","/bin/cat"],
            "readinessProbe":{"exec":{"command":["/bin/busybox","nc","-z","-w","1","127.0.0.1","9000"]},"periodSeconds":1}}]}})
    # The peer accepts both sources: an egress denial cannot be caused by its
    # ingress policy. The untrusted source gets the same egress rule for both
    # destinations, established before its control/denial Job is created.
    runner.apply({"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy","metadata":{"name":"network-peer-ingress"},"spec":{
        "podSelector":{"matchLabels":peer_labels},"policyTypes":["Ingress"],
        "ingress":[{"from":[{"podSelector":{}}],"ports":[{"protocol":"TCP","port":9000}]}]}})
    runner.apply({"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy","metadata":{"name":"network-source-egress"},"spec":{
        "podSelector":{"matchLabels":source_labels},"policyTypes":["Egress"],
        "egress":[{"to":[{"podSelector":{"matchLabels":peer_labels}},{"podSelector":{"matchLabels":harness_labels}}],
                   "ports":[{"protocol":"TCP","port":9000}]}]}})
    runner.kube("wait","--for=condition=Ready","pod/network-peer","--timeout=60s")
    peer=json.loads(runner.kube("get","pod/network-peer","-o","json"))
    peer_target=address(peer["status"]["podIP"])
    harness_target=address(harness["status"]["podIP"])
    records=[]
    # First prove the peer's ingress is realized from another pod. The later
    # host-egress denial must not pass merely because peer ingress was lagging.
    cases=[("network-ingress","harness-ingress",source_labels,peer_target,harness_target),
           ("network-egress","host-egress",policy_labels(host),harness_target,peer_target)]
    for name,case,labels,control,denial in cases:
        runner.apply(probe_job(name,labels,fixture_ref,control,denial))
        runner.kube("wait","--for=condition=Complete","job/"+name,"--timeout=60s")
        records.append(proof(runner.kube("logs","job/"+name,"-c","control"),control,"allowed",case,"control"))
        records.append(proof(runner.kube("logs","job/"+name,"-c","denial"),denial,"denied",case,"denial"))
    # Foreground deletion also waits for the controller-owned Job pods: they
    # must not collide with the later exact-one host lookup or writer wait.
    runner.kube("delete","job/network-egress","job/network-ingress","pod/network-peer",
                "networkpolicy/network-peer-ingress","networkpolicy/network-source-egress",
                "--cascade=foreground","--wait=true")
    (runner.directory/"network-proof.json").write_text(json.dumps(records,indent=2)+"\n")
