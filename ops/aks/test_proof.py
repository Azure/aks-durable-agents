"""Closed public AKS evidence contracts; no cloud or model calls."""
import copy
import json
import math
import os
import tempfile
import unittest
from pathlib import Path

import proof

GOOD = {
    "version": 1, "profile": "aks", "model": "real", "approval": "simulated", "entra": "not-run",
    "modelCalls": 1, "fakeModelCalls": 0, "published": 1, "receipts": 1, "artifacts": 1,
    "restartVerified": True, "markerVerified": True, "networkVerified": True,
    "replay": {"completed": True, "providerCalls": 0, "executorCalls": 0,
               "coverageComplete": True, "unchanged": True},
}
TIMINGS = {"version": 1, "phases": {"preflight": 0, "replay": 2.5}, "totalSeconds": 3}
DIAGNOSTICS = {"version": 1, "phase": "install", "operation": "profile-rollout",
               "reason": "command-failed", "cleanup": "succeeded"}
INSTALL = {"version": 1, "failedStep": "workload-rollout", "resourceKind": "Deployment", "resourceName": "ate-api-server",
           "eventReasons": ["BackOff", "FailedScheduling"], "containerReasons": ["ImagePullBackOff", "other"],
           "containerStates": ["terminated", "waiting"], "exitCodes": [1, 137], "rolloutStatus": "incomplete"}


def network():
    return [{"phase": phase, "case": case, "stage": stage, "passed": True}
            for phase in ("dormant", "live")
            for case in ("untrusted-ingress", "host-egress")
            for stage in ("control", "denial")]


class ProofTests(unittest.TestCase):
    def test_diagnostics_exact_closed_enums_and_types(self):
        choices = {
            "phase": ("preflight", "install", "network-dormant", "network-live", "park", "restart",
                      "approve", "continue", "backup", "replay", "cleanup"),
            "operation": ("phase", "profile-create", "profile-rollout", "profile-verify", "profile-remove",
                          "profile-node-check", "namespace-create", "volume-create", "chart-install", "policy-check",
                          "fixture-init-create", "fixture-init-wait", "fixture-init-remove", "deployment-rollout",
                          "park-host-discovery", "park-rpc", "park-evidence-discovery", "park-evidence-exec"),
            "reason": ("deadline-exhausted", "command-timeout", "command-failed", "interrupted",
                       "invariant-failed", "io-failed", "unclassified-failure"),
            "cleanup": ("succeeded", "failed", "not-run"),
        }
        self.assertEqual(proof.validate_diagnostics(dict(DIAGNOSTICS)), DIAGNOSTICS)
        for key, values in choices.items():
            for value in values:
                candidate = dict(DIAGNOSTICS, **{key: value})
                self.assertEqual(proof.validate_diagnostics(candidate), candidate)
            for value in ("SECRET-CANARY", "", None, [], {}, 1, True, 1.0):
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    proof.validate_diagnostics(dict(DIAGNOSTICS, **{key: value}))
        for value in (True, 1.0, "1", 2, None, [], {}):
            with self.subTest(version=value), self.assertRaises(ValueError):
                proof.validate_diagnostics(dict(DIAGNOSTICS, version=value))
        for key in DIAGNOSTICS:
            bad = dict(DIAGNOSTICS)
            del bad[key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                proof.validate_diagnostics(bad)
        for bad in (None, [], True, dict(DIAGNOSTICS, error="SECRET-CANARY")):
            with self.assertRaises(ValueError):
                proof.validate_diagnostics(bad)

    def test_diagnostic_reader_reuses_all_bounded_descriptor_guards(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workspace = root / "public"
            workspace.mkdir()
            path = workspace / "diagnostics.json"
            for raw in (json.dumps(DIAGNOSTICS), json.dumps(DIAGNOSTICS, indent=2)):
                path.write_text(raw)
                self.assertEqual(proof.load_public(workspace, path.name), DIAGNOSTICS)
            for raw in ("SECRET-CANARY", b"\xff", "[" * 1500 + "]" * 1500,
                        json.dumps(DIAGNOSTICS)[:-1] + ',"version":1}',
                        json.dumps(dict(DIAGNOSTICS, reason="SECRET-CANARY")),
                        json.dumps(DIAGNOSTICS).replace('"version": 1', '"version": NaN'),
                        json.dumps(DIAGNOSTICS).replace('"version": 1', '"version": Infinity'),
                        json.dumps(DIAGNOSTICS).replace('"version": 1', '"version": 1e999'),
                        b" " * (proof.MAX_BYTES + 1)):
                path.write_bytes(raw if isinstance(raw, bytes) else raw.encode())
                with self.subTest(raw=str(raw)[:50]), self.assertRaises((ValueError, RecursionError)):
                    proof.load_public(workspace, path.name)
            path.unlink()
            with self.assertRaises(OSError):
                proof.load_public(workspace, path.name)
            secret = root / "private"
            secret.write_text(json.dumps(DIAGNOSTICS))
            for kind in ("symlink", "fifo", "directory"):
                if kind == "symlink":
                    path.symlink_to(secret)
                elif kind == "fifo":
                    os.mkfifo(path)
                else:
                    path.mkdir()
                with self.subTest(kind=kind), self.assertRaises((OSError, ValueError)):
                    proof.load_public(workspace, path.name)
                path.rmdir() if kind == "directory" else path.unlink()
            path.write_text(json.dumps(DIAGNOSTICS))
            link = root / "link"
            link.symlink_to(workspace, target_is_directory=True)
            nested = workspace / "nested"
            nested.mkdir()
            (nested / path.name).write_text(json.dumps(DIAGNOSTICS))
            for unsafe in (link, link / "nested"):
                with self.subTest(unsafe=unsafe), self.assertRaises(OSError):
                    proof.load_public(unsafe, path.name)

    def test_rollout_status_closed_controller_reason_and_count_matrix(self):
        good = {"version": 1, "controllerKind": "DaemonSet", "controllerName": "nightly-profile",
                "podReasons": ["ImagePullBackOff", "other"], "readyNodes": 0, "desiredNodes": 2}
        self.assertEqual(proof.validate_rollout_status(good), good)
        for kind, name in (("Deployment", "kaimahi-aks-durable-agents-host"),
                           ("Deployment", "kaimahi-aks-durable-agents-harness"), ("other", "other")):
            candidate = dict(good, controllerKind=kind, controllerName=name, readyNodes=None, desiredNodes=None)
            self.assertEqual(proof.validate_rollout_status(candidate), candidate)
            with self.assertRaises(ValueError):
                proof.validate_rollout_status(dict(candidate, readyNodes=0))
        reasons = ("ImagePullBackOff", "ErrImagePull", "CrashLoopBackOff", "CreateContainerConfigError",
                   "ContainerCreating", "FailedMount", "OOMKilled", "Unschedulable", "readiness probe failing", "other")
        for reason in reasons:
            proof.validate_rollout_status(dict(good, podReasons=[reason]))
        aggregate = dict(good, podReasons=sorted(reasons))
        self.assertEqual(proof.validate_rollout_status(aggregate), aggregate)
        for count in (None, 0, 2, 2147483647):
            proof.validate_rollout_status(dict(good, readyNodes=count, desiredNodes=count))
        invalid = [(key, value) for key in ("readyNodes", "desiredNodes")
                   for value in (True, False, -1, 2147483648, 2**128, 1.0, "2", [], {})]
        invalid += [("version", value) for value in (True, 1.0, 2, "1")]
        invalid += [("controllerKind", value) for value in ("Pod", "Deployment", "other", [], None)]
        invalid += [("controllerName", value) for value in ("SECRET-CANARY", "other", [], None)]
        invalid += [("podReasons", value) for value in ([], ["SECRET-CANARY"], ["other", "other"],
                     ["other", "OOMKilled"], ["ReadinessProbeFailed"], "OOMKilled", [None], [[]])]
        for key, value in invalid:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                proof.validate_rollout_status(dict(good, **{key: value}))
        for key in good:
            missing = dict(good)
            del missing[key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                proof.validate_rollout_status(missing)
        with self.assertRaises(ValueError):
            proof.validate_rollout_status(dict(good, message="SECRET-CANARY"))

    def test_install_status_closed_steps_resources_enums_and_bounded_exits(self):
        self.assertEqual(proof.validate_install_status(INSTALL), INSTALL)
        for step in proof.INSTALL_STEPS:
            proof.validate_install_status(dict(INSTALL, failedStep=step))
        for (kind, name), namespace in proof.INSTALL_RESOURCES.items():
            self.assertEqual(namespace is None, (kind, name) == ("other", "other"))
            proof.validate_install_status(dict(INSTALL, resourceKind=kind, resourceName=name))
        for kind, name in (("Job", "rustfs-bucket-init"), ("WorkerPool", "substrate-smoke"), ("WorkerPool", "substrate-sessions"),
                           ("StatefulSet", "postgres"), ("DaemonSet", "atelet"), ("Deployment", "podcertificate-controller")):
            self.assertIn((kind, name), proof.INSTALL_RESOURCES)
        proof.validate_install_status(dict(INSTALL, eventReasons=[], containerReasons=[], containerStates=[], exitCodes=[],
                                          rolloutStatus="unknown"))
        proof.validate_install_status(dict(INSTALL, exitCodes=list(range(256))))
        invalid = [("version", v) for v in (True, 1.0, 2)] + [("failedStep", v) for v in ("SECRET-CANARY", "", None, [])]
        invalid += [("resourceName", "atelet"), ("resourceKind", "Job"), ("resourceName", "pod-abc123")]
        invalid += [(key, value) for key in ("eventReasons", "containerReasons", "containerStates")
                    for value in ("BackOff", ["SECRET-CANARY"], ["other", "other"], ["z", "a"], [None], [[]], [True])]
        invalid += [("eventReasons", ["FailedScheduling", "BackOff"]), ("eventReasons", ["Failed to pull image: SECRET"]),
                    ("containerReasons", ["readiness probe failing"]), ("containerStates", ["Waiting"])]
        invalid += [("exitCodes", v) for v in ([True], [1.0], ["1"], [-1], [256], [2**64], [2, 1], [1, 1], 1, None)]
        invalid += [("rolloutStatus", v) for v in ("ready", "SECRET", None, True)]
        for key, value in invalid:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                proof.validate_install_status(dict(INSTALL, **{key: value}))
        for key in INSTALL:
            with self.subTest(missing=key), self.assertRaises(ValueError):
                proof.validate_install_status({k: v for k, v in INSTALL.items() if k != key})
        with self.assertRaises(ValueError):
            proof.validate_install_status(dict(INSTALL, message="SECRET-CANARY"))

    def test_install_status_uses_existing_bounded_reader(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "install-status.json").write_text(json.dumps(INSTALL))
            self.assertEqual(proof.load_public(root, "install-status.json"), INSTALL)
            (root / "install-status.json").write_text(json.dumps(dict(INSTALL, exitCodes=[1, 1])))
            with self.assertRaises(ValueError):
                proof.load_public(root, "install-status.json")

    def test_rollout_reader_uses_existing_descriptor_and_strict_json_guards(self):
        good = {"version": 1, "controllerKind": "DaemonSet", "controllerName": "nightly-profile",
                "podReasons": ["other"], "readyNodes": None, "desiredNodes": None}
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "rollout-status.json"
            path.write_text(json.dumps(good, indent=4))
            self.assertEqual(proof.load_public(root, path.name), good)
            for raw in ("not-json", b"\xff", "[" * 1500 + "]" * 1500,
                        json.dumps(good)[:-1] + ',"version":1}',
                        json.dumps(dict(good, message="SECRET-CANARY")),
                        json.dumps(good).replace('"readyNodes": null', '"readyNodes": NaN'),
                        b" " * (proof.MAX_BYTES + 1)):
                path.write_bytes(raw if isinstance(raw, bytes) else raw.encode())
                with self.subTest(raw=str(raw)[:40]), self.assertRaises((ValueError, RecursionError)):
                    proof.load_public(root, path.name)
            path.unlink()
            with self.assertRaises(OSError):
                proof.load_public(root, path.name)
            for kind in ("fifo", "symlink", "directory"):
                if kind == "fifo":
                    os.mkfifo(path)
                elif kind == "symlink":
                    path.symlink_to(root / "missing")
                else:
                    path.mkdir()
                with self.subTest(kind=kind), self.assertRaises((OSError, ValueError)):
                    proof.load_public(root, path.name)
                path.rmdir() if kind == "directory" else path.unlink()
            path.write_text(json.dumps(good))
            link = root / "link"
            link.symlink_to(root, target_is_directory=True)
            with self.assertRaises(OSError):
                proof.load_public(link, path.name)

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
