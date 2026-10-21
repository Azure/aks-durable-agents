"""Offline tests exercise the actual manifest and bootstrap shell, never AKS."""
import copy
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent

def module():
    spec = importlib.util.spec_from_file_location("aks_node_profile", HERE / "profile.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def module_from_nightly():
    spec = importlib.util.spec_from_file_location("aks_nightly", HERE / "nightly.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.p = module()
        self.raw = (HERE.parent / "backup/no-network.json").read_bytes()

    def test_exact_profile_and_narrow_security(self):
        ns, cm, ds = self.p.manifests(self.raw)
        self.assertEqual(cm["data"][self.p.FILENAME].encode(), self.raw)
        spec = ds["spec"]["template"]["spec"]
        self.assertFalse(spec["automountServiceAccountToken"])
        for flag in ("hostNetwork", "hostPID", "hostIPC"):
            self.assertFalse(spec[flag])
        self.assertEqual(spec["nodeSelector"], {"kubernetes.io/os": "linux", "kubernetes.io/arch": "amd64"})
        hostpaths = [v["hostPath"] for v in spec["volumes"] if "hostPath" in v]
        self.assertEqual(hostpaths, [{"path": "/var/lib/kubelet/seccomp", "type": "Directory"}])
        c = spec["containers"][0]
        self.assertEqual(c["image"], self.p.ALPINE)
        self.assertEqual(c["securityContext"], {"runAsUser": 0, "runAsGroup": 0, "runAsNonRoot": False,
            "allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
            "capabilities": {"drop": ["ALL"]}, "seccompProfile": {"type": "RuntimeDefault"}})
        self.assertNotIn("serviceAccountName", spec)
        self.assertEqual(ns["metadata"]["name"], self.p.NAMESPACE)
        self.assertEqual(self.p.sha256(self.raw), hashlib.sha256(self.raw).hexdigest())

    def test_bootstrap_real_shell_atomic_idempotent_and_drift_refusal(self):
        # Root ownership is an invariant, not bypassed for a nonroot test host.
        if os.geteuid() != 0:
            self.skipTest("root-only shell; exercise exact script with offline container test")
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.json"
            source.write_bytes(self.raw)
            target = Path(tmp) / "profile.json"
            script = self.p.install_script(self.raw, str(source), str(target))
            command = ["sh", "-ec", script]
            if not shutil.which("sha256sum"):
                self.skipTest("sha256sum unavailable")
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 0)
            self.assertEqual(target.read_bytes(), self.raw)
            self.assertEqual(target.stat().st_mode & 0o777, 0o644)
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 0)
            target.write_text("drift")
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
            target.unlink()
            target.symlink_to(source)
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
            self.assertEqual(source.read_bytes(), self.raw)

    @unittest.skipUnless(os.environ.get("RUN_AKS_CONTAINER_TESTS") == "true", "explicit offline container exercise")
    def test_actual_alpine_installer_and_fresh_fixture_bootstrap(self):
        n = module_from_nightly()
        pins = n.chart_images(HERE.parent.parent)
        for image in (self.p.ALPINE, pins["harness"]):
            inspect = subprocess.run(["docker", "image", "inspect", image], capture_output=True)
            if inspect.returncode:
                self.skipTest("required pinned image absent locally; offline test never pulls")
        # Everything is inside a new Docker-managed volume; no host root mount.
        import uuid
        volume = "nightly-offline-" + uuid.uuid4().hex
        subprocess.run(["docker", "volume", "create", volume], check=True, capture_output=True)
        def run(image, command, user, caps=()):
            return subprocess.run(["docker", "run", "--pull=never", "--rm", "--network=none", "--read-only", "--cap-drop=ALL",
                "--security-opt=no-new-privileges", "--user=" + user, *caps,
                "--mount=type=volume,source=" + volume + ",target=/volume", "--entrypoint=" + command[0], image, *command[1:]], capture_output=True)
        try:
            script = "mkdir /volume/profiles; printf '%s' " + __import__('shlex').quote(self.raw.decode()) + " > /volume/source; "
            install = self.p.install_script(self.raw, "/volume/source", "/volume/profiles/profile.json")
            quoted = __import__('shlex').quote(install)
            script += install + "\n" + install + "\nprintf drift > /volume/profiles/profile.json\nif /bin/sh -ec " + quoted + "; then exit 1; fi\nrm /volume/profiles/profile.json; ln -s /volume/source /volume/profiles/profile.json\nif /bin/sh -ec " + quoted + "; then exit 1; fi\n"
            result = run(self.p.ALPINE, ["/bin/sh", "-ec", script], "0:0")
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            obj = n.prepare_manifest("nightly-12-1", pins["harness"])
            for c in obj["spec"]["initContainers"] + obj["spec"]["containers"]:
                security = c["securityContext"]
                caps = ["--cap-add=" + x for x in security["capabilities"].get("add", [])]
                result = run(c["image"], c["command"], str(security["runAsUser"]) + ":" + str(security["runAsGroup"]), caps)
                self.assertEqual(result.returncode, 0, result.stderr.decode())
            result = run(self.p.ALPINE, ["/bin/sh", "-ec", 'test "$(stat -c %u:%g:%a /volume/nightly-12-1)" = 65532:65532:700; test -d /volume/nightly-12-1/tmp-daemon; test ! -e /volume/nightly-12-1/journal.db; test ! -e /volume/nightly-12-1/real-attempts.db'], "65532:65532")
            self.assertEqual(result.returncode, 0, result.stderr.decode())
        finally:
            subprocess.run(["docker", "volume", "rm", volume], check=True, capture_output=True)

    def test_fixed_two_ready_eligible_nodes_and_no_autoscale(self):
        nodes = [{"metadata": {"name": n, "labels": {"kubernetes.io/os": "linux", "kubernetes.io/arch": "amd64"}},
                  "spec": {}, "status": {"conditions": [{"type": "Ready", "status": "True"}]}} for n in ("n1", "n2")]
        self.assertEqual(self.p.eligible_nodes(nodes), {"n1", "n2"})
        for bad in (nodes[:1], nodes + [copy.deepcopy(nodes[0])]):
            with self.assertRaises(ValueError):
                self.p.eligible_nodes(bad)
        nodes[0]["spec"]["unschedulable"] = True
        with self.assertRaises(ValueError):
            self.p.eligible_nodes(nodes)


if __name__ == "__main__":
    unittest.main()
