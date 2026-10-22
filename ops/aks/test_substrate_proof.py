"""The actor profile must never be accepted as a legacy marker proof."""
import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

import proof
import substrate_proof as p

FINAL = {"version": 1, "profile": "aks-substrate", "variant": "substrate-gvisor", "case": "simulated-explicit-continue", "model": "real", "approval": "simulated", "entra": "not-run", "modelCalls": 1, "fakeModelCalls": 0, "published": 1, "receipts": 1, "artifacts": 1, "restartVerified": True, "networkVerified": True, "actorBound": True, "runtime": "gvisor", "checkpointVolumes": True, "separateExecutor": True, "guestEgress": "not-qualified", "coldRestore": "not-run", "replay": {"completed": True, "providerCalls": 0, "executorCalls": 0, "coverageComplete": True, "unchanged": True}}


class ActorPublicProofTests(unittest.TestCase):
    def test_collector_accepts_only_explicit_actor_profile_without_logs(self):
        spec = importlib.util.spec_from_file_location("actor_collector_test", Path(__file__).resolve().parents[1] / "demo/e2e.py")
        assert spec is not None and spec.loader is not None
        collector = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(collector)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "public"
            workspace.mkdir()
            records = [{"phase": phase, "case": case, "stage": stage, "passed": True} for phase in ("dormant", "live") for case in p.CASES for stage in ("control", "denial")]
            for name, value in (("proof.json", FINAL), ("network-proof.json", records), ("timings.json", {"version": 1, "phases": {"replay": 1}, "totalSeconds": 2})):
                (workspace / name).write_text(json.dumps(value))
            (workspace / "private.log").write_text("token-and-identities")
            result = collector.collect(workspace, root / "must-not-read", root / "output", root / "summary", "success", "https://github.com/Azure/aks-durable-agents/actions/runs/123", profile="aks-substrate", sha="a" * 40)
            self.assertEqual(result, 0)
            self.assertEqual(json.loads((root / "output/proof.json").read_text()), FINAL)
            self.assertFalse((root / "output/private.log").exists())
            self.assertNotIn("token-and-identities", (root / "summary").read_text())

    def test_closed_proof_requires_all_actual_invariants(self):
        self.assertEqual(p.validate(FINAL), FINAL)
        with self.assertRaises(ValueError): proof.validate(FINAL)
        for key, value in (("actorBound", False), ("runtime", "runc"), ("checkpointVolumes", False), ("modelCalls", 2), ("separateExecutor", False), ("profile", "aks"), ("version", True), ("token", "secret"), ("guestEgress", "verified")):
            changed = copy.deepcopy(FINAL)
            changed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): p.validate(changed)

    def test_requires_all_positive_and_negative_caller_probes(self):
        records = [{"phase": phase, "case": case, "stage": stage, "passed": True} for phase in ("dormant", "live") for case in ("untrusted-router", "untrusted-control", "executor-router", "executor-control", "executor-model", "host-egress") for stage in ("control", "denial")]
        self.assertEqual(p.validate_network(records), records)
        for change in (records[:-1], records + [records[0]], [dict(r, passed=False) for r in records], [dict(r, address="private") for r in records]):
            with self.assertRaises(ValueError): p.validate_network(change)


if __name__ == "__main__": unittest.main()
