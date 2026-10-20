#!/usr/bin/env python3
"""Stopped-writer backup and isolated release-notes-v2 recovery; Python stdlib only."""
import argparse
import hashlib
import io
import json
import os
import shutil
import socket
import sqlite3
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid
from contextlib import closing
from pathlib import Path, PurePosixPath

MANIFEST = ".backup-manifest.json"
PROFILE = "ops-backup-no-network.json"
TMP_DIRS = {"tmp-daemon", "tmp-fixture-harness", "tmp-executor", "tmp-fake"}


def digest(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def files(root):
    return {p.relative_to(root).as_posix(): digest(p) for p in sorted(root.rglob("*")) if p.is_file() and p.name != MANIFEST}


def validate_wal(path):
    if not path.exists() or path.stat().st_size == 0:
        return
    # SQLite can silently discard a bad WAL suffix *before* integrity_check.
    # Validate the entire stopped copy first; ambiguous/stale tails fail closed.
    # Format/checksum: https://www.sqlite.org/fileformat2.html#walformat
    with path.open("rb") as wal:
        header = wal.read(32)
        if len(header) != 32:
            raise ValueError("invalid WAL header: " + str(path))
        magic, version, size, _, salt1, salt2, sum1, sum2 = struct.unpack(">8I", header)
        if magic not in (0x377F0682, 0x377F0683) or version != 3007000 or not (512 <= size <= 65536) or size & (size - 1):
            raise ValueError("invalid WAL format: " + str(path))
        endian = "<" if magic == 0x377F0682 else ">"

        def checksum(data, sums):
            s0, s1 = sums
            for x, y in struct.iter_unpack(endian + "II", data):
                s0 = (s0 + x + s1) & 0xFFFFFFFF
                s1 = (s1 + y + s0) & 0xFFFFFFFF
            return s0, s1

        sums = checksum(header[:24], (0, 0))
        if sums != (sum1, sum2):
            raise ValueError("invalid WAL header checksum: " + str(path))
        committed = True
        while frame := wal.read(24 + size):
            if len(frame) != 24 + size:
                raise ValueError("invalid WAL truncated frame: " + str(path))
            page, commit, s1, s2, c1, c2 = struct.unpack(">6I", frame[:24])
            sums = checksum(frame[24:], checksum(frame[:8], sums))
            if not page or (s1, s2) != (salt1, salt2) or sums != (c1, c2):
                raise ValueError("invalid WAL frame checksum or salt: " + str(path))
            committed = commit != 0
        if not committed:
            raise ValueError("invalid WAL uncommitted tail: " + str(path))


def checkpoint(root):
    databases = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        with path.open("rb") as f:
            header = f.read(16)
        if header != b"SQLite format 3\x00":
            if path.suffix == ".db":
                raise ValueError("invalid SQLite header: " + str(path))
            continue
        # This routine is ONLY called on private scratch, never on a source PVC.
        rollback = Path(str(path) + "-journal")
        if rollback.exists() and rollback.stat().st_size:
            raise ValueError("nonempty rollback journal requires operator recovery: " + str(rollback))
        validate_wal(Path(str(path) + "-wal"))
        with closing(sqlite3.connect(path)) as db:
            if db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0] != 0:
                raise ValueError("SQLite checkpoint busy: " + str(path))
            if db.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
                raise ValueError("SQLite integrity check failed: " + str(path))
            db.execute("PRAGMA journal_mode=DELETE")
        databases.append(path.relative_to(root).as_posix())
    if "journal.db" not in databases:
        raise ValueError("journal.db is missing or is not SQLite")
    return databases


def snapshot(source, target):
    excluded = []
    for path in sorted(source.rglob("*")):
        rel = path.relative_to(source)
        if rel.parts[0] in TMP_DIRS:
            if len(rel.parts) == 1:
                excluded.append(rel.as_posix())
            continue
        mode = path.lstat().st_mode
        if stat.S_ISSOCK(mode):
            excluded.append(rel.as_posix())
            continue
        if path.name == MANIFEST or stat.S_ISLNK(mode):
            raise ValueError("reserved name or symlink in data: " + str(rel))
        dest = target / rel
        if stat.S_ISDIR(mode):
            dest.mkdir(mode=0o700, parents=True, exist_ok=True)
        elif stat.S_ISREG(mode):
            dest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            shutil.copyfile(path, dest)
            dest.chmod(0o600)
        else:
            raise ValueError("special file in data: " + str(rel))
    return excluded


def pack(source, output, provenance=None):
    source = Path(source)
    if source.is_symlink() or not source.is_dir():
        raise ValueError("source must be a real directory")
    with tempfile.TemporaryDirectory() as work:
        root = Path(work) / "data"
        root.mkdir(mode=0o700)
        excluded = snapshot(Path(source), root)
        raw = files(root)
        databases = checkpoint(root)
        manifest = {"version": 1, "created_unix": int(time.time()), "source": provenance or {},
                    "raw_sha256": raw, "sha256": files(root), "sqlite": databases, "excluded": excluded}
        with tarfile.open(fileobj=output, mode="w|gz") as tar:
            payload = json.dumps(manifest, sort_keys=True).encode()
            item = tarfile.TarInfo("manifest.json")
            item.mode, item.size = 0o600, len(payload)
            tar.addfile(item, io.BytesIO(payload))
            for path in sorted(root.rglob("*")):
                tar.add(path, arcname="data/" + path.relative_to(root).as_posix(), recursive=False)


def validate_manifest(root, manifest):
    if manifest.get("version") != 1 or not isinstance(manifest.get("sha256"), dict):
        raise ValueError("unsupported backup manifest")
    if files(root) != manifest["sha256"]:
        raise ValueError("backup hash mismatch or unexpected files")
    if "journal.db" not in manifest["sha256"]:
        raise ValueError("backup has no journal")


def unpack(destination, stream):
    destination = Path(destination)
    if destination.is_symlink() or not destination.is_dir() or any(destination.iterdir()):
        raise ValueError("restore destination must be a new empty directory")
    with tempfile.TemporaryDirectory() as work:
        root = Path(work) / "data"
        root.mkdir(mode=0o700)
        manifest = None
        seen = set()
        with tarfile.open(fileobj=stream, mode="r|gz") as tar:
            for item in tar:
                name = PurePosixPath(item.name)
                if item.name in seen or name.is_absolute() or ".." in name.parts or "\\" in item.name:
                    raise ValueError("unsafe or duplicate backup path")
                seen.add(item.name)
                if item.name == "manifest.json" and item.isfile():
                    if item.size > 16 * 1024 * 1024:
                        raise ValueError("manifest too large")
                    manifest = json.load(tar.extractfile(item))
                    continue
                if len(name.parts) < 2 or name.parts[0] != "data" or MANIFEST in name.parts or not (item.isfile() or item.isdir()):
                    raise ValueError("unsafe backup member")
                path = root.joinpath(*name.parts[1:])
                if item.isdir():
                    path.mkdir(mode=0o700, parents=True, exist_ok=True)
                else:
                    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    with path.open("xb") as f:
                        shutil.copyfileobj(tar.extractfile(item), f)
                    path.chmod(0o600)
        if manifest is None:
            raise ValueError("backup manifest missing")
        validate_manifest(root, manifest)
        # Integrity checks are also performed on scratch. No writes to the PVC
        # happen before the complete archive has passed validation.
        if checkpoint(root) != manifest["sqlite"]:
            raise ValueError("SQLite inventory mismatch")
        validate_manifest(root, manifest)
        shutil.copytree(root, destination, dirs_exist_ok=True)
        destination.chmod(0o700)
        for name in TMP_DIRS:
            (destination / name).mkdir(mode=0o700, exist_ok=True)
        (destination / MANIFEST).write_text(json.dumps(manifest, sort_keys=True))
        (destination / MANIFEST).chmod(0o600)


def verify(root):
    root = Path(root)
    if root.is_symlink() or stat.S_IMODE(root.stat().st_mode) != 0o700 or root.stat().st_uid != os.getuid():
        raise ValueError("unsafe restored directory owner or mode")
    for path in root.rglob("*"):
        mode = path.lstat().st_mode
        expected = 0o700 if stat.S_ISDIR(mode) else 0o600
        if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)) or stat.S_IMODE(mode) != expected or path.stat().st_uid != os.getuid():
            raise ValueError("unsafe restored file owner, type or mode: " + str(path))
    manifest = json.loads((root / MANIFEST).read_text())
    validate_manifest(root, manifest)
    return manifest


def probe():
    for family in (socket.AF_INET, socket.AF_INET6, socket.AF_UNIX):
        try:
            s = socket.socket(family)
        except PermissionError:
            continue
        else:
            s.close()
            raise ValueError("socket creation allowed: recovery isolation absent")
    print(json.dumps({"socket_denial": "verified"}), flush=True)


def replay(root, session):
    probe()
    verify(root)
    with tempfile.TemporaryDirectory() as work:
        scratch = Path(work) / "replay"
        shutil.copytree(root, scratch)
        scratch.chmod(0o700)
        for name in ("scenario.json", "instructions.txt", "real-attempts.db", "publications.db"):
            path = scratch / name
            if path.is_symlink() or not path.is_file() or path.stat().st_uid != os.getuid() or stat.S_IMODE(path.stat().st_mode) != 0o600:
                raise ValueError("missing or unsafe replay input: " + name)
        result = subprocess.run(["/session-fixture", "verify-replay", "--scenario", "v2", "--journal", str(scratch / "journal.db"),
                                 "--instructions", str(scratch / "instructions.txt"), "--session", session], check=True, capture_output=True, text=True)
        proof = json.loads(result.stdout)
        if not proof.get("completed") or proof.get("provider_calls") != 0 or proof.get("executor_calls") != 0:
            raise ValueError("strict replay did not prove zero calls")
        if not proof.get("expected_execution_ids") or proof["expected_execution_ids"] != proof.get("covered_execution_ids"):
            raise ValueError("strict replay did not cover every completed execution")
        verify(root)
        print(json.dumps({"replay": proof, "restored_hashes": "unchanged"}), flush=True)


def assert_no_consumers(pods, claim, allowed=None):
    for pod in pods:
        if pod["metadata"]["name"] == allowed or pod.get("status", {}).get("phase") in ("Succeeded", "Failed"):
            continue
        if any(v.get("persistentVolumeClaim", {}).get("claimName") == claim for v in pod["spec"].get("volumes", [])):
            raise ValueError("PVC still has a possible writer: " + pod["metadata"]["name"])


class Cluster:
    def __init__(self, args):
        self.args = args
        self.prefix = ["kubectl", "--context", args.context, "--kubeconfig", args.kubeconfig, "--namespace", args.namespace]

    def run(self, *args, **kwargs):
        return subprocess.run(self.prefix + list(args), check=True, **kwargs)

    def get(self, resource, *args):
        return json.loads(self.run("get", resource, *args, "-o", "json", capture_output=True).stdout)

    def create(self, obj):
        self.run("create", "-f", "-", input=json.dumps(obj).encode(), stdout=subprocess.DEVNULL)

    def pod(self, readonly):
        a = self.args
        name = "journal-copy-" + uuid.uuid4().hex[:10]
        security = {"runAsUser": 65532, "runAsGroup": 65532, "runAsNonRoot": True,
                    "seccompProfile": {"type": "Localhost", "localhostProfile": PROFILE}}
        # No fsGroup on the source/read-only mount: do not recursively chmod a
        # production PVC. A fresh target needs group access to its empty root.
        if not readonly:
            security["fsGroup"] = 65532
        self.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "labels": {"ops-backup": "isolated"}},
                     "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False, "enableServiceLinks": False,
                              "nodeSelector": {"kubernetes.io/arch": "amd64", "kubernetes.io/os": "linux"},
                              "securityContext": security,
                              "containers": [{"name": "copy", "image": a.image, "command": ["python3", "-c", "import time; time.sleep(3600)"],
                                              "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}},
                                              "resources": {"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"cpu": "1", "memory": "1Gi", "ephemeral-storage": "4Gi"}},
                                              "env": [{"name": "TMPDIR", "value": "/work"}, {"name": "PYTHONDONTWRITEBYTECODE", "value": "1"}],
                                              "volumeMounts": [{"name": "data", "mountPath": "/volume", "readOnly": readonly}, {"name": "work", "mountPath": "/work"}]}],
                              "volumes": [{"name": "data", "persistentVolumeClaim": {"claimName": a.pvc, "readOnly": readonly}}, {"name": "work", "emptyDir": {"sizeLimit": "4Gi"}}]}})
        try:
            self.run("wait", "--for=condition=Ready", "pod/" + name, "--timeout=120s")
        except subprocess.CalledProcessError:
            self.remove_pod(name)
            raise
        return name

    def remove_pod(self, name):
        self.run("delete", "pod", name, "--wait=true", "--timeout=120s", stdout=subprocess.DEVNULL)

    def exec(self, pod, command, **kwargs):
        return self.run("exec", "-i", pod, "--", "python3", "/backup.py", *command, **kwargs)

    def fence(self, deployments, allowed=None):
        for name in deployments:
            if self.get("deployment", name)["spec"].get("replicas", 1) != 0:
                raise ValueError("writer Deployment must be scaled to zero: " + name)
        assert_no_consumers(self.get("pods")["items"], self.args.pvc, allowed)


def backup_cluster(a):
    c = Cluster(a)
    deployments = c.get("deployments", "-l", "app.kubernetes.io/name=aks-durable-agents,app.kubernetes.io/instance=" + a.release)["items"]
    roles = {d["metadata"]["labels"].get("app.kubernetes.io/component") for d in deployments}
    if len(deployments) != 2 or roles != {"host", "harness"}:
        raise ValueError("expected exactly the chart's host and harness Deployments")
    counts = {d["metadata"]["name"]: d["spec"].get("replicas", 1) for d in deployments}
    for d in deployments:
        spec = d["spec"]["template"]["spec"]
        if not any(v.get("persistentVolumeClaim", {}).get("claimName") == a.pvc for v in spec["volumes"]):
            raise ValueError("Deployment does not use the requested PVC")
        data = [m for container in spec["containers"] for m in container.get("volumeMounts", []) if m["mountPath"] == "/data"]
        if not data or any(m.get("subPath") != a.subpath for m in data):
            raise ValueError("requested subpath differs from chart data mounts")
    for hpa in c.get("hpa")["items"]:
        if hpa["spec"]["scaleTargetRef"]["name"] in counts:
            raise ValueError("freeze/remove writer HPA before maintenance")
    host = next(d for d in deployments if d["metadata"]["labels"]["app.kubernetes.io/component"] == "host")
    policy_volume = next(v for v in host["spec"]["template"]["spec"]["volumes"] if v["name"] == "model-policy")
    policy = c.get("configmap", policy_volume["configMap"]["name"])["data"]["model-policy.json"]
    source = {"namespace": a.namespace, "release": a.release, "pvc": a.pvc, "subpath": a.subpath,
              "pvc_uid": c.get("pvc", a.pvc)["metadata"]["uid"], "replicas": counts, "helper_image": a.image,
              "model_policy": json.loads(policy),
              "images": {d["metadata"]["name"]: [x["image"] for x in d["spec"]["template"]["spec"]["containers"]] for d in deployments}}
    # Fail before stopping writers if the local output cannot be exclusively made.
    fd = os.open(a.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    pod = None
    success = False
    try:
        with os.fdopen(fd, "wb") as output:
            if a.stop:
                c.run("scale", *["deployment/" + n for n in counts], "--replicas=0")
                c.run("wait", "--for=delete", "pod", "-l", "app.kubernetes.io/name=aks-durable-agents,app.kubernetes.io/instance=" + a.release, "--timeout=120s")
            c.fence(counts)
            pod = c.pod(True)
            c.fence(counts, pod)
            c.exec(pod, ["_pack", "/volume/" + a.subpath, json.dumps(source)], stdout=output)
            c.fence(counts, pod)
        # Validate the transferred bytes locally, never operate on a live source.
        with tempfile.TemporaryDirectory() as work, open(a.output, "rb") as stream:
            unpack(Path(work), stream)
        success = True
    finally:
        if pod:
            c.remove_pod(pod)
        if not success:
            Path(a.output).unlink(missing_ok=True)
            print("Backup failed; writers are NOT automatically restarted. Inspect before recovery.", file=sys.stderr)
    if a.stop:
        for name, count in counts.items():
            c.run("scale", "deployment/" + name, "--replicas=" + str(count))
        for name, count in counts.items():
            if count:
                c.run("rollout", "status", "deployment/" + name, "--timeout=120s")
    print(json.dumps({"backup": a.output, "source": source, "sha256": digest(Path(a.output))}))


def restore_cluster(a):
    # Verify locally before creating cluster resources. New namespace/claim are
    # created, never applied over existing objects, so a typo cannot overwrite.
    with tempfile.TemporaryDirectory() as work, open(a.archive, "rb") as stream:
        unpack(Path(work), stream)
    c = Cluster(a)
    c.create({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": a.namespace}})
    c.create({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": {"name": "deny-all", "namespace": a.namespace},
              "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"], "ingress": [], "egress": []}})
    c.create({"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": a.pvc, "namespace": a.namespace},
              "spec": {"accessModes": ["ReadWriteOnce"], "storageClassName": a.storage_class, "resources": {"requests": {"storage": a.size}}}})
    pod = c.pod(False)
    try:
        c.exec(pod, ["_probe"])
        with open(a.archive, "rb") as stream:
            c.exec(pod, ["_unpack", "/volume/" + a.subpath], stdin=stream)
    finally:
        c.remove_pod(pod)
    pod = c.pod(True)
    try:
        c.exec(pod, ["_replay", "/volume/" + a.subpath, a.session])
    finally:
        c.remove_pod(pod)
    print(json.dumps({"restore": "verified", "namespace": a.namespace, "pvc": a.pvc, "session": a.session, "workloads_started": False}))


def main():
    os.umask(0o077)
    if len(sys.argv) > 1 and sys.argv[1].startswith("_"):
        command, *args = sys.argv[1:]
        if command == "_pack":
            pack(Path(args[0]), sys.stdout.buffer, json.loads(args[1]) if len(args) > 1 else {})
        elif command == "_unpack":
            dest = Path(args[0])
            dest.mkdir(mode=0o700)
            unpack(dest, sys.stdin.buffer)
        elif command == "_replay":
            replay(Path(args[0]), args[1])
        elif command == "_probe":
            probe()
        else:
            raise ValueError("unknown worker command")
        return
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("backup", "restore"):
        p = commands.add_parser(name)
        for arg in ("context", "kubeconfig", "namespace", "pvc", "subpath", "image"):
            p.add_argument("--" + arg, required=True)
        if name == "backup":
            p.add_argument("--release", required=True)
            p.add_argument("--output", required=True)
            p.add_argument("--stop", action="store_true", help="stop both writers and restart only after a verified backup")
        else:
            p.add_argument("--archive", required=True)
            p.add_argument("--session", required=True)
            p.add_argument("--storage-class", required=True)
            p.add_argument("--size", default="1Gi")
    a = parser.parse_args()
    subpath = PurePosixPath(a.subpath)
    if subpath.is_absolute() or ".." in subpath.parts or not subpath.parts or "\\" in a.subpath:
        parser.error("subpath must be a relative subtree without traversal")
    if "@sha256:" not in a.image:
        parser.error("helper image must be digest-pinned")
    (backup_cluster if a.command == "backup" else restore_cluster)(a)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, sqlite3.Error, tarfile.TarError, subprocess.CalledProcessError) as error:
        print("backup:", error, file=sys.stderr)
        sys.exit(1)
