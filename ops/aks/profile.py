"""Single-purpose seccomp installer for the disposable, fixed two-node AKS run."""
import hashlib
import shlex

# Reviewed by the existing demo; not a mutable tag or a newly selected image.
ALPINE = "alpine:3.23@sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0"
FILENAME = "ops-backup-no-network.json"
NAMESPACE = "nightly-profile"
NAME = "nightly-profile"


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def verify_script(raw, target="/profiles/" + FILENAME):
    target = shlex.quote(target)
    return (f"test ! -L {target}; test -f {target}; "
            f"test \"$(stat -c %u:%g:%a {target})\" = 0:0:644; "
            f"test \"$(sha256sum {target} | cut -d ' ' -f 1)\" = {sha256(raw)}")


def install_script(raw, source="/source/" + FILENAME, target="/profiles/" + FILENAME):
    source, quoted = shlex.quote(source), shlex.quote(target)
    directory = shlex.quote(target.rsplit("/", 1)[0])
    return f"""set -eu
umask 022
test \"$(sha256sum {source} | cut -d ' ' -f 1)\" = {sha256(raw)}
test ! -L {quoted}
if test -e {quoted}; then
  {verify_script(raw, target)}
else
  tmp=$(mktemp {directory}/.nightly-profile.XXXXXX)
  trap 'rm -f "$tmp"' EXIT HUP INT TERM
  cat {source} > "$tmp"
  chmod 0644 "$tmp"
  test \"$(sha256sum "$tmp" | cut -d ' ' -f 1)\" = {sha256(raw)}
  mv -n "$tmp" {quoted}
  {verify_script(raw, target)}
fi
"""


def manifests(raw):
    security = {"runAsUser": 0, "runAsGroup": 0, "runAsNonRoot": False,
                "allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                "capabilities": {"drop": ["ALL"]}, "seccompProfile": {"type": "RuntimeDefault"}}
    labels = {"nightly-profile": "installer"}
    return [
        {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": NAMESPACE}},
        {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": NAME, "namespace": NAMESPACE},
         "immutable": True, "data": {FILENAME: raw.decode("utf-8")}},
        {"apiVersion": "apps/v1", "kind": "DaemonSet", "metadata": {"name": NAME, "namespace": NAMESPACE},
         "spec": {"selector": {"matchLabels": labels}, "template": {"metadata": {"labels": labels}, "spec": {
             "automountServiceAccountToken": False, "enableServiceLinks": False,
             "hostNetwork": False, "hostPID": False, "hostIPC": False,
             "nodeSelector": {"kubernetes.io/os": "linux", "kubernetes.io/arch": "amd64"},
             "containers": [{"name": "install", "image": ALPINE, "securityContext": security,
                 "command": ["/bin/sh", "-ec", install_script(raw) + "exec sleep 3600\n"],
                 "readinessProbe": {"exec": {"command": ["/bin/sh", "-ec", verify_script(raw)]}, "periodSeconds": 2},
                 "resources": {"requests": {"cpu": "10m", "memory": "16Mi"}, "limits": {"cpu": "100m", "memory": "32Mi"}},
                 "volumeMounts": [{"name": "profiles", "mountPath": "/profiles"},
                                  {"name": "source", "mountPath": "/source", "readOnly": True}]}],
             "volumes": [{"name": "profiles", "hostPath": {"path": "/var/lib/kubelet/seccomp", "type": "DirectoryOrCreate"}},
                         {"name": "source", "configMap": {"name": NAME, "defaultMode": 292}}]}}}}]


def eligible_nodes(nodes):
    result = set()
    if len(nodes) != 2:
        raise ValueError("exactly two fixed nodes required")
    for node in nodes:
        labels = node["metadata"]["labels"]
        if (labels.get("kubernetes.io/os") != "linux" or labels.get("kubernetes.io/arch") != "amd64"
                or node.get("spec", {}).get("unschedulable") or node["metadata"].get("deletionTimestamp")
                or not any(c.get("type") == "Ready" and c.get("status") == "True" for c in node["status"].get("conditions", []))):
            raise ValueError("node is not eligible and Ready")
        result.add(node["metadata"]["name"])
    if len(result) != 2:
        raise ValueError("node identity is not unique")
    return result
