"""Closed public AKS evidence contracts; no cloud or model calls."""
import copy
import math
import unittest

import proof

GOOD = {
    "version": 1, "profile": "aks", "model": "real", "approval": "simulated", "entra": "not-run",
    "modelCalls": 1, "fakeModelCalls": 0, "published": 1, "receipts": 1, "artifacts": 1,
    "restartVerified": True, "markerVerified": True, "networkVerified": True,
    "replay": {"completed": True, "providerCalls": 0, "executorCalls": 0,
               "coverageComplete": True, "unchanged": True},
}
TIMINGS = {"version": 1, "phases": {"preflight": 0, "replay": 2.5}, "totalSeconds": 3}


def network():
    return [{"phase": phase, "case": case, "stage": stage, "passed": True}
            for phase in ("dormant", "live")
            for case in ("untrusted-ingress", "host-egress")
            for stage in ("control", "denial")]


class ProofTests(unittest.TestCase):
    def test_complete_final_proof_is_accepted(self):
        self.assertEqual(proof.validate(copy.deepcopy(GOOD)), GOOD)

    def test_every_final_field_is_required_and_closed(self):
        for key in GOOD:
            bad = copy.deepcopy(GOOD)
            del bad[key]
            with self.subTest(key=key), self.assertRaises(ValueError):
                proof.validate(bad)
        for key in GOOD["replay"]:
            bad = copy.deepcopy(GOOD)
            del bad["replay"][key]
            with self.subTest(replay=key), self.assertRaises(ValueError):
                proof.validate(bad)
        for target in ("root", "replay"):
            bad = copy.deepcopy(GOOD)
            (bad if target == "root" else bad["replay"])["draft"] = "credential"
            with self.subTest(target=target), self.assertRaises(ValueError):
                proof.validate(bad)

    def test_all_literals_and_types_are_enforced(self):
        for key, wanted in GOOD.items():
            if key == "replay":
                continue
            candidates = (None, [], {}, str(wanted), not wanted) if type(wanted) is not str else (None, 1, wanted + "-other")
            if type(wanted) is int:
                candidates += (bool(wanted), float(wanted), wanted + 1)
            if type(wanted) is bool:
                candidates += (1,)
            for value in candidates:
                if type(value) is type(wanted) and value == wanted:
                    continue
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    proof.validate(dict(copy.deepcopy(GOOD), **{key: value}))
        for key, wanted in GOOD["replay"].items():
            for value in (None, 1 if type(wanted) is bool else False, False if type(wanted) is bool else 1, 0.0):
                bad = copy.deepcopy(GOOD)
                bad["replay"][key] = value
                with self.subTest(replay=key, value=value), self.assertRaises(ValueError):
                    proof.validate(bad)
        for bad in (None, [], True, dict(GOOD, replay=[])):
            with self.assertRaises(ValueError):
                proof.validate(bad)

    def test_network_requires_exact_eight_unique_successes(self):
        self.assertEqual(proof.validate_network(network()), network())
        for mutation in (
            lambda n: n.pop(), lambda n: n.append(n[0]), lambda n: n.__setitem__(1, n[0]),
            lambda n: n[0].update(phase="other"), lambda n: n[0].update(case="harness-ingress"),
            lambda n: n[0].update(stage="other"), lambda n: n[0].update(passed=False),
            lambda n: n[0].update(passed=1), lambda n: n[0].update(address="private"),
            lambda n: n[0].pop("phase"), lambda n: n[0].update(phase=[]),
            lambda n: n.__setitem__(0, None),
        ):
            bad = network()
            mutation(bad)
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                proof.validate_network(bad)
        with self.assertRaises(ValueError):
            proof.validate_network({})

    def test_timings_closed_schema_names_and_numeric_bounds(self):
        self.assertEqual(proof.validate_timings(copy.deepcopy(TIMINGS)), TIMINGS)
        for key in TIMINGS:
            bad = copy.deepcopy(TIMINGS)
            del bad[key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                proof.validate_timings(bad)
        for bad in (None, [], dict(TIMINGS, version=True), dict(TIMINGS, version=1.0),
                    dict(TIMINGS, credential="secret"), dict(TIMINGS, phases=[]),
                    dict(TIMINGS, phases={"credential": 1})):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                proof.validate_timings(bad)
        for value in (True, False, "1", None, -1, 2700.01, math.inf, -math.inf, math.nan, 10 ** 1000):
            for key in ("totalSeconds", "phases"):
                bad = copy.deepcopy(TIMINGS)
                bad[key] = value if key == "totalSeconds" else {"replay": value}
                with self.subTest(key=key, value=str(value)), self.assertRaises(ValueError):
                    proof.validate_timings(bad)
        self.assertEqual(proof.validate_timings({"version": 1, "phases": {
            name: 2700 for name in ("preflight", "install", "network-dormant", "network-live", "park",
                                   "restart", "approve", "continue", "backup", "replay", "cleanup")},
            "totalSeconds": 2700})["totalSeconds"], 2700)


if __name__ == "__main__":
    unittest.main()
