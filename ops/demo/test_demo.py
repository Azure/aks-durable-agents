"""Real subprocess/input tests for the disposable demo runner's safety rails."""
import gc
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import warnings

import demo


class DemoTests(unittest.TestCase):
    def test_phase_timing_records_without_extending_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            runner=demo.Runner(Path(directory))
            deadline=runner.budget.deadline
            runner.step("build")
            runner.step("cleanup")
            runner.finish_timings()
            timing=json.loads((Path(directory)/"timings.json").read_text())
            self.assertEqual([p["name"] for p in timing["phases"]],["preflight","build","cleanup"])
            self.assertTrue(all(p["seconds"]>=0 for p in timing["phases"]))
            self.assertAlmostEqual(sum(p["seconds"] for p in timing["phases"]),timing["elapsedSeconds"],places=5)
            self.assertEqual(runner.budget.deadline,deadline)

    def test_published_pins_are_read_from_actual_chart(self):
        pins = demo.published_images(Path(__file__).resolve().parents[2])
        self.assertIn("ghcr.io/azure/aks-durable-agents/host@sha256:", pins["host"])
        self.assertIn("ghcr.io/azure/aks-durable-agents/session-fixture@sha256:", pins["harness"])

    def test_empty_or_changed_pin_layout_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "charts/aks-durable-agents/values.yaml"
            target.parent.mkdir(parents=True)
            target.write_text('image:\n  host:\n    repository: ""\n    digest: ""\n')
            with self.assertRaises(demo.DemoError):
                demo.published_images(root)

    def test_pipe_keeps_separate_approve_and_continue_lines(self):
        read, write = os.pipe()
        try:
            os.write(write, b"approve\ncontinue\n")
            os.close(write)
            with os.fdopen(read, "rb", buffering=0) as source:
                demo.confirm("approve", source, demo.Budget(3, reserve=0), io.StringIO())
                demo.confirm("continue", source, demo.Budget(3, reserve=0), io.StringIO())
        finally:
            # fdopen owns the read descriptor; the writer was closed above.
            pass

    def test_wrong_or_eof_input_refuses_without_echoing_input(self):
        for content in [b"", b"not-a-secret-password\n", b"approve \n", b"x" * 100]:
            read, write = os.pipe()
            os.write(write, content)
            os.close(write)
            output = io.StringIO()
            with os.fdopen(read, "rb", buffering=0) as source:
                with self.assertRaises(demo.DemoError):
                    demo.confirm("approve", source, demo.Budget(3, reserve=0), output)
            self.assertNotIn("not-a-secret", output.getvalue())

    def test_input_deadline_is_enforced(self):
        read, write = os.pipe()
        try:
            with os.fdopen(read, "rb", buffering=0) as source:
                start = time.monotonic()
                with self.assertRaises(demo.DemoError):
                    demo.confirm("approve", source, demo.Budget(0.1, reserve=0), io.StringIO())
                self.assertLess(time.monotonic() - start, 2)
        finally:
            os.close(write)

    def test_expired_budget_refuses_before_starting_a_command(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = demo.Runner(Path(directory), seconds=0, reserve=0)
            with self.assertRaisesRegex(demo.DemoError, "deadline"):
                runner.run(["this-command-must-not-be-started"])

    def test_subprocess_deadline_terminates_work(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = demo.Runner(Path(directory), seconds=0.2, reserve=0)
            start = time.monotonic()
            with warnings.catch_warnings(record=True) as observed:
                warnings.simplefilter("always", ResourceWarning)
                with self.assertRaises(demo.DemoError):
                    runner.run([sys.executable, "-c", "import time; time.sleep(60)"])
                gc.collect()
            self.assertFalse([item for item in observed if item.category is ResourceWarning], "timed-out subprocess pipes leaked")
            self.assertLess(time.monotonic() - start, 3)

    def test_node_manifest_uses_canonical_reference_not_config_id(self):
        tag = "local/aks-durable-agents/demo-host:test"
        digest = "sha256:" + "b" * 64
        table = "REF TYPE DIGEST SIZE\n" + "docker.io/" + tag + " application/vnd.oci.image.manifest.v1+json " + digest + " 10MiB\n"
        reference, actual = demo.loaded_manifest(table, tag)
        self.assertEqual(reference, "docker.io/" + tag)
        self.assertEqual(actual, digest)
        with self.assertRaises(demo.DemoError):
            demo.loaded_manifest("sha256:"+"a"*64+" manifest "+digest, tag)

    def test_cleanup_requires_owned_cluster_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = demo.Runner(Path(directory))
            runner.cluster = "not-owned"
            with self.assertRaises(demo.DemoError):
                runner.cleanup()

    def test_replacement_waits_through_creation_gap_and_specific_pod_ready(self):
        script = '''import json, os, sys, time
from pathlib import Path
path=Path(os.environ["FAKE_KUBE_STATE"])
state=json.loads(path.read_text()); args=sys.argv[1:]
code=0
if "delete" in args:
    state["deleted"]=True
elif "rollout" in args:
    print("deployment successfully rolled out (stale status)")
elif "get" in args:
    state["queries"]+=1
    if state["queries"]==1:
        pods=[]
    elif state["queries"]==2:
        pods=[{"metadata":{"name":"old-host","uid":"old-uid"}}]
    else:
        pods=[{"metadata":{"name":"new-host","uid":"new-uid"},"status":{"conditions":[{"type":"Ready","status":"False"}]}}]
    print(json.dumps({"items":pods}))
elif "wait" in args:
    if "pod/new-host" not in args or "--for=condition=Ready" not in args:
        code=7
    else:
        time.sleep(0.05)
        state["ready"]=True
elif "exec" in args:
    state["executed"]=state["ready"]
    code=0 if state["ready"] else 8
path.write_text(json.dumps(state)); sys.exit(code)
'''
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); tool=root/"kubectl"
            tool.write_text("#!"+sys.executable+"\n"+script); tool.chmod(0o700)
            state=root/"state.json"
            state.write_text(json.dumps({"queries":0,"deleted":False,"ready":False,"executed":False}))
            runner=demo.Runner(root/"run",seconds=3,reserve=0)
            runner.env.update(FAKE_KUBE_STATE=str(state),PATH=str(root)+os.pathsep+os.environ["PATH"])
            old={"metadata":{"name":"old-host","uid":"old-uid"}}
            replacement=runner.replace_host(old)
            self.assertEqual(replacement["metadata"]["uid"],"new-uid")
            runner.kube("exec",replacement["metadata"]["name"],"--","scenario-client")
            observed=json.loads(state.read_text())
            self.assertTrue(observed["deleted"] and observed["ready"] and observed["executed"])
            self.assertGreaterEqual(observed["queries"],3)

    def test_owned_cleanup_handles_success_and_partial_create_only(self):
        script = '''import json, os, sys
from pathlib import Path
path = Path(os.environ["FAKE_KIND_STATE"])
state = json.loads(path.read_text())
args = sys.argv[1:]
state["calls"].append(args)
code = 0
if args[:2] == ["get", "clusters"]:
    print("\\n".join(state["clusters"]))
elif args[:2] == ["create", "cluster"]:
    state["clusters"].append(args[args.index("--name")+1])
    code = int(os.environ.get("FAKE_FAIL_CREATE", "0"))
elif args[:2] == ["delete", "cluster"]:
    state["clusters"].remove(args[args.index("--name")+1])
else:
    code = 9
path.write_text(json.dumps(state))
sys.exit(code)
'''
        for fail in ["0","1"]:
            with self.subTest(partial_create=fail), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                tool = root / "kind"
                tool.write_text("#!"+sys.executable+"\n"+script)
                tool.chmod(0o700)
                state = root / "state.json"
                state.write_text(json.dumps({"clusters":["unrelated"],"calls":[]}))
                runner = demo.Runner(root/"run")
                runner.kind = str(tool)
                runner.env.update(FAKE_KIND_STATE=str(state),FAKE_FAIL_CREATE=fail)
                if fail == "1":
                    with self.assertRaises(demo.DemoError):
                        runner.create_cluster()
                else:
                    runner.create_cluster()
                runner.cleanup()
                observed = json.loads(state.read_text())
                self.assertEqual(observed["clusters"],["unrelated"])
                deletion = observed["calls"][-1]
                self.assertEqual(deletion[deletion.index("--name")+1],runner.cluster)
                self.assertEqual(deletion[deletion.index("--kubeconfig")+1],str(runner.kubeconfig))
                self.assertFalse(runner.owned)

    @unittest.skipUnless(shutil.which("helm"), "Helm required for the real chart contract")
    def test_demo_values_satisfy_real_chart_before_cluster_creation(self):
        root = Path(__file__).resolve().parents[2]
        repository, digest = demo.published_images(root)["host"].split("@")
        values = demo.demo_values(repository, digest, "demo-run")
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "kubeconfig"
            config.write_text(json.dumps({"apiVersion":"v1","kind":"Config","clusters":[],"users":[],"contexts":[]}))
            config.chmod(0o600)
            result = subprocess.run(["helm","--kubeconfig",str(config),"--kube-context","demo-owned-context","template","demo",str(root/"charts/aks-durable-agents"),"--kube-version","1.37.0","-f","-"],input=json.dumps(values),capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        # Reuse the chart test suite's existing PyYAML dependency; the runner
        # itself remains stdlib-only. Check live renderer contracts, not stubs.
        import yaml
        deployments = [doc for doc in yaml.safe_load_all(result.stdout) if doc and doc.get("kind")=="Deployment"]
        by_component = {doc["metadata"]["labels"]["app.kubernetes.io/component"]:doc for doc in deployments}
        self.assertEqual(set(by_component),{"harness",demo.HOST_COMPONENT})
        host = by_component[demo.HOST_COMPONENT]
        self.assertIn("daemon",[container["name"] for container in host["spec"]["template"]["spec"]["containers"]])

    def test_runtime_manifest_keeps_policy_auth_and_dormant_workloads(self):
        values = demo.demo_values("local/demo", "sha256:" + "a"*64, "demo-run")
        self.assertTrue(values["networkPolicy"]["enabled"])
        self.assertEqual(values["auth"], {"mode":"off", "trustedNetwork":True})
        self.assertEqual(values["model"]["deployment"], "demo-model")
        self.assertFalse(values["workloads"]["enabled"])


if __name__ == "__main__":
    unittest.main()
