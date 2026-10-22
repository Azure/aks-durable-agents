"""The actor profile must never be accepted as a legacy marker proof."""
import copy
import unittest

import proof
import substrate_proof as p

FINAL = {"version": 1, "profile": "aks-substrate", "variant": "substrate-gvisor", "case": "simulated-explicit-continue", "model": "real", "approval": "simulated", "entra": "not-run", "modelCalls": 1, "fakeModelCalls": 0, "published": 1, "receipts": 1, "artifacts": 1, "restartVerified": True, "networkVerified": True, "actorBound": True, "runtime": "gvisor", "checkpointVolumes": True, "separateExecutor": True, "guestEgress": "not-qualified", "coldRestore": "not-run", "replay": {"completed": True, "providerCalls": 0, "executorCalls": 0, "coverageComplete": True, "unchanged": True}}


class ActorPublicProofTests(unittest.TestCase):
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
