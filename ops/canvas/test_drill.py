"""Admission for the owned local kind proof; never contacts Kubernetes."""
import copy
import subprocess
import sys
import unittest
from unittest import mock

import drill


class DrillInputs(unittest.TestCase):
    def test_commands_have_a_default_deadline(self):
        with mock.patch.object(drill.subprocess, "run", wraps=subprocess.run) as child:
            result = drill.run([sys.executable, "-c", "print('ok')"])
        self.assertEqual(result.stdout.strip(), b"ok")
        self.assertEqual(child.call_args.kwargs.get("timeout"), 300)

    def test_command_timeout_becomes_runtime_error(self):
        expired = subprocess.TimeoutExpired(["probe"], 300)
        with mock.patch.object(drill.subprocess, "run", side_effect=expired):
            with self.assertRaisesRegex(RuntimeError, "timed out after 300s") as caught:
                drill.run(["probe"])
        self.assertIs(caught.exception.__cause__, expired)

    def test_readback_timeout_preserves_partial_output_and_continues(self):
        expired = subprocess.TimeoutExpired(["probe"], 30, output=b"partial", stderr=b"diagnostic")
        with mock.patch.object(drill.subprocess, "run", side_effect=expired) as child:
            result = drill.run(["probe"], check=False, timeout=30)
        self.assertEqual(child.call_args.kwargs["timeout"], 30)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"partial")
        self.assertIn(b"diagnostic", result.stderr)
        self.assertIn(b"timed out", result.stderr)

    def test_real_hung_child_is_terminated(self):
        with self.assertRaisesRegex(RuntimeError, "timed out after 0.05s"):
            drill.run([sys.executable, "-c", "import time; time.sleep(60)"], timeout=0.05)

    def test_every_denial_requires_its_own_policy_drop(self):
        probes = [
            {"source": "10.244.0.2", "target": "10.244.0.3:8081", "expected": "denied"},
            {"source": "10.244.0.4", "target": "10.244.0.5:443", "expected": "denied"},
            {"source": "10.244.0.2", "target": "10.244.0.3:9000", "expected": "allowed"},
        ]
        first = "xx drop (Policy denied) 10.244.0.2:52114 -> 10.244.0.3:8081 tcp SYN"
        second = "xx drop (Policy denied) 10.244.0.4:42321 -> 10.244.0.5:443 tcp SYN"
        drill.verify_policy_drops(probes, first + "\n" + second)
        for invalid in (first, second, first.replace("Policy denied", "No route") + "\n" + second,
                        first.replace("10.244.0.2:", "10.244.0.22:") + "\n" + second,
                        first + "\n" + second.replace(":443 tcp", ":4430 tcp")):
            with self.subTest(drops=invalid), self.assertRaisesRegex(RuntimeError, "missing policy drop"):
                drill.verify_policy_drops(probes, invalid)

    def test_zero_initial_state_and_both_restarted_pods_required(self):
        empty = {"http": 0, "credentials": 0, "attempts": []}
        drill.verify_initial_counters(empty)
        for key, value in (("http", 1), ("credentials", 1), ("attempts", [[1, "succeeded"]])):
            with self.subTest(key=key), self.assertRaisesRegex(RuntimeError, "initial counters"):
                drill.verify_initial_counters({**empty, key: value})
        before = {role: {"metadata": {"uid": role + "-old"}} for role in ("host", "harness")}
        after = {role: {"metadata": {"uid": role + "-new"}} for role in before}
        drill.verify_restarted_pods(before, after)
        for role in before:
            unchanged = copy.deepcopy(after)
            unchanged[role] = before[role]
            with self.subTest(role=role), self.assertRaisesRegex(RuntimeError, "pod was not replaced"):
                drill.verify_restarted_pods(before, unchanged)

    def test_only_diagnostic_images_and_exact_native_inventory(self):
        good = {"drillOnly": True, "identityExercised": False,
                "tags": {"host": "local/canvas-drill-host:x", "producer": "local/canvas-drill-producer:x"},
                "entries": [{"id": "bundle-v4-" + "a" * 64, "port": 9000}]}
        drill.validate_manifest(good)
        cases = [
            {"drillOnly": False}, {"identityExercised": True}, {"entries": []},
            {"entries": [{"id": "release-notes", "port": 9000}]},
            {"entries": [{"id": "bundle-v4-" + "a" * 64, "port": 8081}]},
            {"entries": [{"id": "bundle-v4-" + "a" * 64, "port": "9000"}]},
            {"entries": [{"id": "bundle-v4-" + "a" * 64, "port": 9000}] * 2},
            {"tags": {"host": "production/host:x", "producer": "local/canvas-drill-producer:x"}},
        ]
        for change in cases:
            with self.subTest(change=change), self.assertRaises(ValueError):
                value = copy.deepcopy(good)
                value.update(change)
                drill.validate_manifest(value)


if __name__ == "__main__":
    unittest.main()
