"""Manifest and proof contracts for the real, published TCP probe."""
import json
import tempfile
import unittest
from pathlib import Path

import netpolicy


class NetworkTests(unittest.TestCase):
    def test_probe_job_is_hardened_and_uses_same_identity_for_control_and_denial(self):
        labels={"app.kubernetes.io/name":"aks-durable-agents","app.kubernetes.io/instance":"demo","app.kubernetes.io/component":"host"}
        job=netpolicy.probe_job("egress",labels,"fixture@sha256:"+"a"*64,"10.244.0.2:9000","10.244.0.3:9000")
        self.assertEqual(job["kind"],"Job")
        self.assertEqual(job["spec"]["backoffLimit"],0)
        pod=job["spec"]["template"]
        self.assertEqual(pod["metadata"]["labels"],labels)
        spec=pod["spec"]
        self.assertEqual(spec["restartPolicy"],"Never")
        self.assertFalse(spec["automountServiceAccountToken"])
        self.assertNotIn("volumes",spec)
        for container in spec["initContainers"]+spec["containers"]:
            self.assertTrue(container["securityContext"]["readOnlyRootFilesystem"])
            self.assertEqual(container["securityContext"]["capabilities"],{"drop":["ALL"]})
            self.assertEqual(container["command"][0:2],["/session-fixture","network-probe"])
        self.assertIn("allowed",spec["initContainers"][0]["command"])
        self.assertIn("denied",spec["containers"][0]["command"])

    def test_proofs_are_literal_exact_tcp_results_not_any_command_failure(self):
        address="10.244.0.2:9000"
        for allowed in [True,False]:
            expected="allowed" if allowed else "denied"
            raw=json.dumps({"address":address,"allowed":allowed,"expect":expected,"tcpOnly":True}).encode()
            result=netpolicy.proof(raw,address,expected,"host-egress","control" if allowed else "denial")
            self.assertEqual(result["allowed"],allowed)
        for data in [{},{"address":address,"allowed":True,"expect":"denied","tcpOnly":True},{"address":"bad.invalid:9000","allowed":False,"expect":"denied","tcpOnly":True},{"address":address,"allowed":False,"expect":"denied"}]:
            with self.assertRaises(ValueError): netpolicy.proof(json.dumps(data).encode(),address,"denied","host-egress","denial")
        for bad in ["bad.invalid","127.0.0.1","0.0.0.0","::1"]:
            with self.assertRaises(ValueError): netpolicy.address(bad)

    def test_policy_targets_and_job_cleanup_precede_success_proof(self):
        class Runner:
            cluster="agent-demo-test"
            def __init__(self,path): self.directory=path; self.docs=[]; self.events=[]
            def apply(self,doc): self.docs.append(doc)
            def kube(self,*args,**kwargs):
                self.events.append(args)
                if args[:2]==("get","pod/network-peer"):
                    return json.dumps({"status":{"podIP":"10.244.0.3"}}).encode()
                if args[0]=="logs":
                    job=args[1].split("/")[1]
                    control=args[-1]=="control"
                    target=("10.244.0.2:9000" if control else "10.244.0.3:9000") if job=="network-egress" else ("10.244.0.3:9000" if control else "10.244.0.2:9000")
                    return json.dumps({"address":target,"allowed":control,"expect":"allowed" if control else "denied","tcpOnly":True}).encode()
                return b""
        labels={"app.kubernetes.io/name":"aks-durable-agents","app.kubernetes.io/instance":"demo","app.kubernetes.io/component":"host","pod-template-hash":"do-not-copy"}
        host={"metadata":{"labels":labels}}
        harness={"metadata":{"labels":dict(labels,**{"app.kubernetes.io/component":"harness"})},"status":{"podIP":"10.244.0.2"}}
        with tempfile.TemporaryDirectory() as directory:
            runner=Runner(Path(directory))
            netpolicy.run_checks(runner,"fixture@digest","alpine@digest",host,harness)
            records=json.loads((runner.directory/"network-proof.json").read_text())
        self.assertEqual(len(records),4)
        jobs=[doc for doc in runner.docs if doc["kind"]=="Job"]
        self.assertEqual(len(jobs),2)
        self.assertEqual(jobs[0]["metadata"]["name"],"network-ingress", "prove peer ingress is reachable before relying on an egress denial to it")
        self.assertTrue(all("pod-template-hash" not in job["spec"]["template"]["metadata"]["labels"] for job in jobs))
        policy=next(doc for doc in runner.docs if doc["metadata"]["name"]=="network-source-egress")
        self.assertEqual(len(policy["spec"]["egress"][0]["to"]),2)
        self.assertEqual(runner.events[-1][0],"delete")
        self.assertIn("--cascade=foreground",runner.events[-1])


if __name__=="__main__": unittest.main()
