"""AKS reporting tests: real files and in-memory API only; never post publicly."""
import contextlib
import copy
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import e2e
from test_e2e import BOT, HUMAN, SHA, URL, FakeAPI, make_run, tracker

GOOD = {
    "version": 1, "profile": "aks", "model": "real", "approval": "simulated", "entra": "not-run",
    "modelCalls": 1, "fakeModelCalls": 0, "published": 1, "receipts": 1, "artifacts": 1,
    "restartVerified": True, "markerVerified": True, "networkVerified": True,
    "replay": {"completed": True, "providerCalls": 0, "executorCalls": 0,
               "coverageComplete": True, "unchanged": True},
}
NETWORK = [{"phase": p, "case": c, "stage": s, "passed": True}
           for p in ("dormant", "live") for c in ("untrusted-ingress", "host-egress")
           for s in ("control", "denial")]
TIMINGS = {"version": 1, "phases": {"preflight": 0, "replay": 2.5}, "totalSeconds": 3}
DIAGNOSTICS = {"version": 1, "phase": "install", "operation": "fixture-init-wait",
               "reason": "command-timeout", "cleanup": "succeeded"}
AKS_TITLE = "AKS e2e regression"
AKS_MARKER = "<!-- aks-e2e-tracking -->"
AKS_START, AKS_END = "<!-- aks-e2e-status:start -->", "<!-- aks-e2e-status:end -->"
SECRET = "CONSOLE-INJECTED-CREDENTIAL"


class AksCollectorTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.ws = self.root / "public"
        self.ws.mkdir()
        for name, value in (("proof.json", GOOD), ("network-proof.json", NETWORK), ("timings.json", TIMINGS)):
            (self.ws / name).write_text(json.dumps(value))
        self.console = self.root / "console"
        self.console.write_text(SECRET + "\nEvidence: /private/model\n")
        for name in ("command-001.log", "model.json", "journal.jsonl", ".env", "kubeconfig"):
            (self.ws / name).write_text(SECRET)
        self.dest = self.root / "artifacts"
        self.summary = self.root / "summary.md"

    def collect(self, result="success", extra=()):
        # Exercise the real entry point as a process: argparse failures are observable nonzero results.
        return subprocess.run([sys.executable, "-B", str(Path(e2e.__file__)), "collect", "--profile", "aks",
            "--workspace", str(self.ws), "--console", str(self.console), "--destination", str(self.dest),
            "--summary", str(self.summary), "--result", result, "--run-url", URL, "--sha", SHA,
            *extra], capture_output=True, text=True, timeout=10)

    def output(self):
        return "".join(p.read_text() for p in self.dest.iterdir()) + self.summary.read_text()

    def test_failure_and_cancellation_publish_only_validated_diagnostics_and_fixed_summary(self):
        for result in ("failure", "cancelled"):
            # Formatting is deliberately untrusted; published bytes must be reserialized.
            (self.ws / "diagnostics.json").write_text(json.dumps(DIAGNOSTICS, indent=4))
            run = self.collect(result=result, extra=("--stage", "teardown"))
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual((self.dest / "diagnostics.json").read_text(), json.dumps(DIAGNOSTICS, sort_keys=True) + "\n")
            self.assertEqual(json.loads((self.dest / "status.json").read_text()),
                             {"result": "failed", "stage": "teardown", "runURL": URL, "commitSHA": SHA})
            self.assertEqual(self.summary.read_text(), "# AKS e2e summary\n\n- Result: failed\n"
                + f"- Stage: teardown\n- Run: {URL}\n- Commit: {SHA}\n"
                + "- Scenario phase: install\n- Operation: fixture-init-wait\n- Reason: command-timeout\n"
                + "- Source fencing: succeeded\n- Underlying cause: not determined\n")
            self.assertNotIn(SECRET, self.output())
            self.reset_destination()

    def test_success_ignores_diagnostics_and_still_requires_every_success_proof(self):
        path = self.ws / "diagnostics.json"
        for diagnostic in (DIAGNOSTICS, dict(DIAGNOSTICS, error=SECRET)):
            path.write_text(json.dumps(diagnostic))
            run = self.collect()
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertFalse((self.dest / path.name).exists())
            self.assertNotIn("Diagnostics", self.summary.read_text())
            self.assertNotIn("Underlying cause", self.summary.read_text())
            self.reset_destination()
        path.unlink()
        os.mkfifo(path)  # Even an unsafe diagnostic is not opened on success.
        self.assertEqual(self.collect().returncode, 0)
        self.reset_destination()
        path.unlink()
        path.write_text(json.dumps(DIAGNOSTICS))
        for name in ("proof.json", "network-proof.json", "timings.json"):
            saved = (self.ws / name).read_bytes()
            (self.ws / name).unlink()
            run = self.collect()
            self.assertEqual(run.returncode, 1, run.stderr)
            self.assertFalse((self.dest / path.name).exists())
            self.assertEqual(json.loads((self.dest / "status.json").read_text())["result"], "failed")
            self.reset_destination()
            (self.ws / name).write_bytes(saved)

    def assert_diagnostics_unavailable(self):
        for result in ("failure", "cancelled"):
            run = self.collect(result=result)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertFalse((self.dest / "diagnostics.json").exists())
            self.assertTrue(self.summary.read_text().endswith("- Diagnostics: unavailable\n- Underlying cause: not determined\n"))
            self.assertNotIn(SECRET, self.output() + run.stderr)
            self.assertNotIn(str(self.ws), self.output() + run.stderr)
            self.assertEqual(set(json.loads((self.dest / "status.json").read_text())), {"result", "stage", "runURL", "commitSHA"})
            self.reset_destination()

    def test_missing_unsafe_and_malformed_diagnostics_are_unavailable(self):
        self.assert_diagnostics_unavailable()
        path = self.ws / "diagnostics.json"
        for raw in (SECRET, b"\xff", "[" * 1500 + "]" * 1500,
                    json.dumps(DIAGNOSTICS)[:-1] + ',"phase":"install"}',
                    json.dumps(dict(DIAGNOSTICS, reason=SECRET)), json.dumps(dict(DIAGNOSTICS, error=SECRET)),
                    json.dumps(dict(DIAGNOSTICS, version=True)),
                    json.dumps(DIAGNOSTICS).replace('"version": 1', '"version": NaN'),
                    json.dumps(DIAGNOSTICS).replace('"version": 1', '"version": Infinity'),
                    json.dumps(DIAGNOSTICS).replace('"version": 1', '"version": 1e999'),
                    b" " * (16 * 1024 + 1)):
            with self.subTest(raw=str(raw)[:50]):
                path.write_bytes(raw if isinstance(raw, bytes) else raw.encode())
                self.assert_diagnostics_unavailable()
        path.unlink()
        private = self.root / "private-diagnostics"
        private.write_text(json.dumps(DIAGNOSTICS))
        for kind in ("symlink", "fifo", "directory"):
            if kind == "symlink":
                path.symlink_to(private)
            elif kind == "fifo":
                os.mkfifo(path)
            else:
                path.mkdir()
            with self.subTest(kind=kind):
                self.assert_diagnostics_unavailable()
            path.rmdir() if kind == "directory" else path.unlink()
        path.write_text(json.dumps(DIAGNOSTICS))
        link = self.root / "link"
        link.symlink_to(self.ws, target_is_directory=True)
        original = self.ws
        nested = original / "nested"
        nested.mkdir()
        (nested / path.name).write_text(json.dumps(DIAGNOSTICS))
        for workspace in (link, link / "nested"):
            self.ws = workspace
            self.assert_diagnostics_unavailable()
        self.ws = original

    def test_rollout_status_requires_matching_diagnostics_and_is_reserialized_on_failure(self):
        path = self.ws / "rollout-status.json"
        for operation, kind, name, counts in (
                ("profile-rollout", "DaemonSet", "nightly-profile", (0, 2)),
                ("deployment-rollout", "Deployment", "kaimahi-aks-durable-agents-host", (None, None)),
                ("deployment-rollout", "Deployment", "kaimahi-aks-durable-agents-harness", (None, None)),
                ("profile-rollout", "other", "other", (None, None))):
            report = {"version": 1, "controllerKind": kind, "controllerName": name,
                      "podReasons": ["ImagePullBackOff", "other"], "readyNodes": counts[0], "desiredNodes": counts[1]}
            for result in ("failure", "cancelled"):
                (self.ws / "diagnostics.json").write_text(json.dumps(dict(DIAGNOSTICS, operation=operation)))
                path.write_text(json.dumps(report, indent=4))
                run = self.collect(result=result)
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual((self.dest / path.name).read_text(), json.dumps(report, sort_keys=True) + "\n")
                self.assertIn(f"Controller: {kind}/{name}", self.summary.read_text())
                self.assertIn("Pod reasons: ImagePullBackOff, other", self.summary.read_text())
                self.assertIn("Ready/desired nodes: 0/2" if kind == "DaemonSet" else "Ready/desired nodes: unknown/unknown",
                              self.summary.read_text())
                self.assertNotIn(SECRET, self.output())
                self.reset_destination()

    def test_rollout_missing_unsafe_and_mismatched_status_never_copied(self):
        path = self.ws / "rollout-status.json"
        report = {"version": 1, "controllerKind": "DaemonSet", "controllerName": "nightly-profile",
                  "podReasons": ["other"], "readyNodes": None, "desiredNodes": None}
        (self.ws / "diagnostics.json").write_text(json.dumps(dict(DIAGNOSTICS, operation="profile-rollout")))
        for raw in (None, SECRET, json.dumps(dict(report, message=SECRET)),
                    json.dumps(report)[:-1] + ',"version":1}', b" " * (16 * 1024 + 1)):
            if raw is not None:
                path.write_bytes(raw if isinstance(raw, bytes) else raw.encode())
            self.assertEqual(self.collect(result="failure").returncode, 0)
            self.assertFalse((self.dest / path.name).exists())
            self.assertIn("- Rollout status: unavailable\n", self.summary.read_text())
            self.assertNotIn(SECRET, self.output())
            self.reset_destination()
        path.unlink()
        for kind in ("fifo", "symlink"):
            os.mkfifo(path) if kind == "fifo" else path.symlink_to(self.ws / "proof.json")
            self.assertEqual(self.collect(result="cancelled").returncode, 0)
            self.assertFalse((self.dest / path.name).exists())
            self.assertIn("Rollout status: unavailable", self.summary.read_text())
            self.reset_destination()
            path.unlink()
        path.write_text(json.dumps(report))
        for operation in ("deployment-rollout", "fixture-init-wait", None):
            diagnostic = self.ws / "diagnostics.json"
            if operation is None:
                diagnostic.unlink()
            else:
                diagnostic.write_text(json.dumps(dict(DIAGNOSTICS, operation=operation)))
            self.assertEqual(self.collect(result="failure").returncode, 0)
            self.assertFalse((self.dest / path.name).exists())
            self.assertEqual("Rollout status: unavailable" in self.summary.read_text(), operation == "deployment-rollout")
            self.reset_destination()

    def test_success_does_not_read_rollout_extra_and_requires_all_three_proofs(self):
        path = self.ws / "rollout-status.json"
        os.mkfifo(path)
        for missing in (None, "proof.json", "network-proof.json", "timings.json"):
            if missing:
                saved = (self.ws / missing).read_bytes()
                (self.ws / missing).unlink()
            run = self.collect()
            self.assertEqual(run.returncode, int(missing is not None), run.stderr)
            self.assertFalse((self.dest / path.name).exists())
            self.assertNotIn("Rollout", self.summary.read_text())
            self.reset_destination()
            if missing:
                (self.ws / missing).write_bytes(saved)

    def test_only_validated_public_json_and_fixed_metadata_are_copied(self):
        run = self.collect(extra=("--stage", "finalize"))
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(sorted(p.name for p in self.dest.iterdir()),
                         ["network-proof.json", "proof.json", "status.json", "summary.md", "timings.json"])
        self.assertEqual(json.loads((self.dest / "proof.json").read_text()), GOOD)
        self.assertEqual(json.loads((self.dest / "status.json").read_text()),
                         {"result": "success", "stage": "finalize", "runURL": URL, "commitSHA": SHA})
        text = self.output()
        self.assertNotIn(SECRET, text)
        self.assertNotIn(str(self.ws), text)
        self.assertNotIn("demo-only", text.lower())
        self.assertNotIn("sealing", text.lower())
        self.assertNotIn("fake-model", text.lower())

    def test_console_is_not_opened_even_if_fifo(self):
        self.console.unlink()
        os.mkfifo(self.console)
        run = self.collect()
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertNotIn(SECRET, self.output())

    def test_invalid_proof_is_never_copied_and_success_becomes_failed(self):
        (self.ws / "proof.json").write_text(json.dumps(dict(GOOD, draft=SECRET)))
        run = self.collect()
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertNotIn("proof.json", [p.name for p in self.dest.iterdir()])
        self.assertEqual(json.loads((self.dest / "status.json").read_text()),
                         {"result": "failed", "stage": "scenario", "runURL": URL, "commitSHA": SHA})
        self.assertNotIn(SECRET, self.output() + run.stderr)

    def test_malformed_duplicate_nonfinite_unknown_and_bool_json_refused(self):
        for name, data in (
            ("proof.json", "not-json " + SECRET),
            ("proof.json", b"\xff"),
            ("proof.json", "[" * 1500 + "]" * 1500),
            ("proof.json", json.dumps(GOOD)[:-1] + ',"version":1}'),
            ("proof.json", json.dumps(GOOD).replace('"providerCalls": 0', '"providerCalls": 0, "providerCalls": 0')),
            ("proof.json", json.dumps(dict(GOOD, modelCalls=True))),
            ("proof.json", json.dumps(dict(GOOD, restartVerified=1))),
            ("proof.json", json.dumps(dict(GOOD, receipts=0))),
            ("network-proof.json", json.dumps(NETWORK[:4])),
            ("network-proof.json", json.dumps(NETWORK[:7] + [NETWORK[0]])),
            ("network-proof.json", json.dumps([dict(NETWORK[0], credential=SECRET)] + NETWORK[1:])),
            ("timings.json", '{"version":1,"phases":{"replay":NaN},"totalSeconds":3}'),
            ("timings.json", '{"version":1,"phases":{"replay":Infinity},"totalSeconds":3}'),
            ("timings.json", '{"version":1,"phases":{"replay":1,"replay":1},"totalSeconds":3}'),
            ("timings.json", '{"version":1,"phases":{},"totalSeconds":1e999}'),
            ("timings.json", json.dumps(dict(TIMINGS, phases={SECRET: 1}))),
            ("timings.json", json.dumps(dict(TIMINGS, totalSeconds=True))),
            ("timings.json", json.dumps(dict(TIMINGS, totalSeconds=2701))),
            ("timings.json", json.dumps(dict(TIMINGS, credential=SECRET))),
        ):
            with self.subTest(name=name, data=data):
                path = self.ws / name
                before = path.read_bytes()
                path.write_bytes(data if isinstance(data, bytes) else data.encode())
                run = self.collect()
                self.assertEqual(run.returncode, 1, run.stderr)
                self.assertFalse((self.dest / name).exists())
                self.assertNotIn(SECRET, self.output() + run.stderr)
                path.write_bytes(before)
                self.reset_destination()

    def reset_destination(self):
        for p in self.dest.iterdir():
            p.unlink()
        self.dest.rmdir()

    def test_symlink_directory_fifo_and_oversize_proofs_refused(self):
        path = self.ws / "proof.json"
        secret = self.root / "secret"
        secret.write_text(json.dumps(GOOD))
        for kind in ("symlink", "directory", "fifo", "oversize"):
            with self.subTest(kind=kind):
                path.unlink()
                if kind == "symlink":
                    path.symlink_to(secret)
                elif kind == "directory":
                    path.mkdir()
                elif kind == "fifo":
                    os.mkfifo(path)
                else:
                    path.write_bytes(b" " * (256 * 1024 + 1) + json.dumps(GOOD).encode())
                run = self.collect()
                self.assertEqual(run.returncode, 1, run.stderr)
                self.assertFalse((self.dest / "proof.json").exists())
                self.reset_destination()
                if kind == "directory":
                    path.rmdir()
                else:
                    path.unlink()
                path.write_text(json.dumps(GOOD))

    def test_workspace_and_ancestor_symlinks_refused(self):
        original = self.ws
        link = self.root / "link"
        link.symlink_to(original, target_is_directory=True)
        for ws in (link, link / "nested"):
            if ws.name == "nested":
                nested = original / "nested"
                nested.mkdir()
                for name, value in (("proof.json", GOOD), ("network-proof.json", NETWORK), ("timings.json", TIMINGS)):
                    (nested / name).write_text(json.dumps(value))
            self.ws = ws
            run = self.collect()
            self.assertEqual(run.returncode, 1, run.stderr)
            self.assertEqual(sorted(p.name for p in self.dest.iterdir()), ["status.json", "summary.md"])
            self.reset_destination()

    def test_failure_does_not_turn_valid_evidence_into_success(self):
        for result in ("failure", "cancelled"):
            run = self.collect(result=result)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(json.loads((self.dest / "status.json").read_text())["result"], "failed")
            self.assertNotIn(SECRET, self.output())
            self.reset_destination()

    def test_existing_required_arguments_suffice_without_optional_sha_and_stage(self):
        run = subprocess.run([sys.executable, "-B", str(Path(e2e.__file__)), "collect", "--profile", "aks",
            "--workspace", str(self.ws), "--console", str(self.console), "--destination", str(self.dest),
            "--summary", str(self.summary), "--result", "success", "--run-url", URL],
            capture_output=True, text=True, timeout=10)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(json.loads((self.dest / "status.json").read_text()),
                         {"result": "success", "stage": "scenario", "runURL": URL, "commitSHA": ""})

    def test_explicit_kind_profile_is_byte_identical_to_existing_default(self):
        workspace, _, console = make_run(self.root)
        common = ["collect", "--workspace", str(workspace), "--console", str(console),
                  "--summary", str(self.summary), "--result", "success", "--run-url", URL]
        default, explicit = self.root / "default", self.root / "explicit"
        self.assertEqual(e2e.main([*common, "--destination", str(default)]), 0)
        self.assertEqual(e2e.main([*common, "--destination", str(explicit), "--profile", "kind"]), 0)
        self.assertEqual({p.name: p.read_bytes() for p in default.iterdir()},
                         {p.name: p.read_bytes() for p in explicit.iterdir()})

    def test_no_recursive_search_and_failure_and_cancelled_still_summarize(self):
        private = self.ws / "private"
        private.mkdir()
        for name in ("proof.json", "network-proof.json", "timings.json"):
            (self.ws / name).rename(private / name)
        for result in ("failure", "cancelled", "success"):
            run = self.collect(result=result, extra=("--stage", "preflight"))
            self.assertEqual(run.returncode, 1 if result == "success" else 0, run.stderr)
            self.assertEqual(sorted(p.name for p in self.dest.iterdir()), ["status.json", "summary.md"])
            self.assertEqual(json.loads((self.dest / "status.json").read_text())["result"], "failed")
            self.assertNotIn(SECRET, self.output())
            self.reset_destination()

    def test_invalid_metadata_and_destination_refused_before_writes(self):
        for extra in (("--stage", SECRET), ("--sha", SECRET), ("--run-url", URL + "?token=" + SECRET)):
            run = self.collect(extra=extra)
            self.assertNotEqual(run.returncode, 0)
            self.assertFalse(self.dest.exists())
        self.dest.mkdir()
        (self.dest / "keep").write_text("keep")
        run = self.collect()
        self.assertEqual(run.returncode, 1)
        self.assertEqual((self.dest / "keep").read_text(), "keep")


def aks_tracker(number=1, body=None, user=BOT, title=AKS_TITLE, state="open"):
    return {"number": number, "title": title, "state": state, "user": user,
            "body": body if body is not None else AKS_MARKER + "\nhuman note\n" + AKS_START + "\nold\n" + AKS_END}


class AksTrackerTests(unittest.TestCase):
    def track(self, api, **kwargs):
        return e2e.track(api, "Azure/aks-durable-agents", 123, SHA, URL, profile="aks", **kwargs)

    def test_kind_and_aks_trackers_are_separate_both_directions(self):
        api = FakeAPI([tracker()])
        before = copy.deepcopy(api.issues[0])
        self.track(api, stage="teardown")
        self.assertEqual(api.issues[0], before)
        self.assertEqual(api.issues[1]["title"], AKS_TITLE)
        body = api.issues[1]["body"]
        self.assertIn(AKS_MARKER, body)
        self.assertIn("Stage: teardown", body)
        self.assertIn(URL, body)
        self.assertIn(SHA, body)
        self.assertNotIn(e2e.MARKER, body)
        aks_before = copy.deepcopy(api.issues[1])
        e2e.track(api, "Azure/aks-durable-agents", 123, SHA, URL)
        self.assertEqual(api.issues[1], aks_before)

    def test_strangers_wrong_marker_title_and_pull_requests_are_ignored(self):
        issues = [aks_tracker(1, user=HUMAN), aks_tracker(2, user={"login": BOT["login"], "type": "User"}),
                  aks_tracker(3, body=e2e.MARKER), aks_tracker(4, title=e2e.TITLE),
                  dict(aks_tracker(5), pull_request={})]
        before = copy.deepcopy(issues)
        api = FakeAPI(issues)
        self.track(api)
        self.assertEqual(api.issues[:5], before)
        self.assertEqual(len(api.issues), 6)

    def test_existing_status_updates_reopen_and_preserve_human_text(self):
        api = FakeAPI([aks_tracker(state="closed")])
        self.track(api, stage="wait")
        issue = api.issues[0]
        self.assertEqual(issue["state"], "open")
        self.assertIn("human note", issue["body"])
        self.assertIn("Stage: wait", issue["body"])
        self.assertNotIn("\nold\n", issue["body"])
        self.assertNotIn("comments", issue)
        self.assertEqual([c[0] for c in api.writes()], ["PATCH"])

    def test_malformed_or_ambiguous_tracker_refuses_all_writes(self):
        for issues in ([aks_tracker(body=AKS_MARKER + AKS_START)],
                       [aks_tracker(body=AKS_MARKER + AKS_END + AKS_START)],
                       [aks_tracker(body=AKS_MARKER + (AKS_START + AKS_END) * 2)],
                       [aks_tracker(1), aks_tracker(2)]):
            api = FakeAPI(issues)
            with self.subTest(issues=issues), self.assertRaises(e2e.ApiError):
                self.track(api)
            self.assertEqual(api.writes(), [])

    def test_test_mode_cannot_automatically_close_aks_tracker(self):
        api = FakeAPI([aks_tracker()])
        before = copy.deepcopy(api.issues)
        with self.assertRaises(ValueError):
            self.track(api, test=True)
        self.assertEqual(api.issues, before)
        self.assertEqual(api.calls, [])

    def test_stage_is_allowlisted_and_inputs_validated_before_lookup(self):
        for stage in ("preflight", "create", "wait", "federate", "scenario", "teardown", "finalize"):
            api = FakeAPI()
            self.track(api, stage=stage)
            self.assertIn("Stage: " + stage, api.issues[0]["body"])
            self.assertTrue(all(payload.get("state") != "closed" for _, _, payload in api.writes()))
        for stage in (SECRET, "success", "scenario\n" + SECRET):
            api = FakeAPI()
            with self.assertRaises(ValueError):
                self.track(api, stage=stage)
            self.assertEqual(api.calls, [])

    def test_cli_uses_aks_profile_and_no_close_or_comment(self):
        api = FakeAPI()
        with contextlib.redirect_stdout(io.StringIO()):
            result = e2e.main(["track", "--profile", "aks", "--repo", "Azure/aks-durable-agents",
                              "--run-id", "123", "--sha", SHA, "--run-url", URL, "--stage", "create"], api=api)
        self.assertEqual(result, 0)
        self.assertEqual(api.issues[0]["title"], AKS_TITLE)
        self.assertEqual([c[0] for c in api.writes()], ["POST"])


if __name__ == "__main__":
    unittest.main()
