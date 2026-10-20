"""Collector and tracker tests; the GitHub API is always an in-memory fake."""
import contextlib
import http.server
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest

import e2e

URL = "https://github.com/Azure/aks-durable-agents/actions/runs/123"
SHA = "a" * 40
BOT = {"login": "github-actions[bot]", "type": "Bot"}
HUMAN = {"login": "alice", "type": "User"}
GOOD_PROOF = {"completed": True, "provider_calls": 0, "executor_calls": 0, "publicationCount": 1,
              "receiptCount": 1, "artifacts": 1, "realModelCalls": 1, "modelHTTPCalls": 1,
              "fakeModelCalls": 0, "headSeq": 3, "headHash": "b" * 64, "session": "s-1"}


def network_proof():
    out = []
    for case, address in (("host-egress", "10.0.0.5:9000"), ("harness-ingress", "10.0.0.6:9000")):
        out.append({"case": case, "stage": "control", "address": address, "allowed": True, "expect": "allowed", "tcpOnly": True})
        out.append({"case": case, "stage": "denial", "address": address, "allowed": False, "expect": "denied", "tcpOnly": True})
    return out


def make_run(root, proof=GOOD_PROOF, network=None, timings=None, logs=3):
    """Create a workspace whose evidence directory mimics demo.py output."""
    workspace = Path(root) / "ws"
    evidence = workspace / ".build/demo" / ("0123456789abcdef" * 2)
    evidence.mkdir(parents=True)
    (evidence / "proof.json").write_text(json.dumps(proof))
    (evidence / "network-proof.json").write_text(json.dumps(network or network_proof()))
    (evidence / "timings.json").write_text(json.dumps(timings or {"elapsedSeconds": 12.5, "phases": [{"name": "build", "seconds": 3}]}))
    for secret in ("kubeconfig", "owner.json", "config.yaml", "journal.jsonl", "ghauth"):
        (evidence / secret).write_text("SECRET-" + secret)
    for i in range(1, logs + 1):
        (evidence / f"command-{i:03}.log").write_text(f"log {i}\n")
    console = Path(root) / "console.txt"
    console.write_text(f"hello\nElapsed 1s. Evidence: {evidence}\n")
    return workspace, evidence, console


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self.dest = self.root / "out/artifacts"
        self.summary = self.root / "summary.md"

    def run_collect(self, workspace, console, result="success"):
        return e2e.main(["collect", "--workspace", str(workspace), "--console", str(console), "--destination", str(self.dest),
                         "--summary", str(self.summary), "--result", result, "--run-url", URL])

    def names(self):
        return sorted(p.name for p in self.dest.iterdir())

    def test_success_copies_only_allowlisted_files(self):
        workspace, evidence, console = make_run(self.root)
        self.assertEqual(self.run_collect(workspace, console), 0)
        self.assertEqual(self.names(), ["command-001.log", "command-002.log", "command-003.log", "console.log",
                                        "network-proof.json", "proof.json", "summary.md", "timings.json"])
        text = self.summary.read_text()
        self.assertIn("- Result: success", text)
        self.assertIn("Provider/executor callbacks: 0/0", text)
        self.assertIn("TCP policy controls/denials: 2/2", text)
        self.assertIn("- Phase build: 3.0s", text)
        self.assertNotIn("SECRET", "".join(p.read_text() for p in self.dest.iterdir()) + text)

    def test_actual_long_phase_names_are_preserved_safely(self):
        name="7. DEMO-ONLY seal: checkpoint stopped stores, preserve logical head/counters, then make no more writes. Real hosts do not do this."
        workspace, _, console=make_run(self.root,timings={"elapsedSeconds":4,"phases":[{"name":name,"seconds":2}]})
        self.assertEqual(self.run_collect(workspace,console),0)
        self.assertIn(name,self.summary.read_text())

    def test_invalid_success_proof_fails_but_keeps_logs(self):
        bad = dict(GOOD_PROOF, realModelCalls=2)
        workspace, _, console = make_run(self.root, proof=bad)
        self.assertEqual(self.run_collect(workspace, console), 1)
        self.assertIn("command-003.log", self.names())
        self.assertIn("- Collector: success proof invalid", self.summary.read_text())

    def test_each_proof_schema_violation_is_invalid(self):
        for key, value in (("completed", False), ("provider_calls", 1), ("fakeModelCalls", 1), ("headSeq", 0),
                           ("headHash", "xyz"), ("session", 5), ("modelHTTPCalls", True)):
            self.assertFalse(e2e.valid_proof(dict(GOOD_PROOF, **{key: value})), key)
        self.assertTrue(e2e.valid_proof(GOOD_PROOF))
        net = network_proof()
        self.assertTrue(e2e.valid_network(net))
        for mutate in (lambda n: n.pop(), lambda n: n[0].update(allowed=False), lambda n: n[1].update(allowed=True),
                       lambda n: n[0].update(address="10.0.0.5:80"), lambda n: n[0].pop("tcpOnly"),
                       lambda n: n[0].update(tcpOnly=False), lambda n: n[1].update(case=n[0]["case"], stage="control")):
            bad = network_proof()
            mutate(bad)
            self.assertFalse(e2e.valid_network(bad))
        self.assertFalse(e2e.valid_timings({"elapsedSeconds": "1", "phases": []}))
        self.assertFalse(e2e.valid_timings({"elapsedSeconds": 1, "phases": [{"name": "a"}]}))

    def test_failure_with_invalid_proof_is_not_a_collector_error(self):
        workspace, evidence, console = make_run(self.root)
        (evidence / "proof.json").write_text("not json")
        self.assertEqual(self.run_collect(workspace, console, "failure"), 0)
        self.assertNotIn("proof.json", self.names())

    def test_setup_failure_without_evidence_still_summarizes(self):
        workspace = self.root / "ws"
        workspace.mkdir()
        console = self.root / "console.txt"
        console.write_text("make: *** setup failed\n")
        self.assertEqual(self.run_collect(workspace, console, "failure"), 0)
        self.assertEqual(self.names(), ["console.log", "summary.md"])
        self.assertIn("- Evidence directory: not found", self.summary.read_text())
        # success claim without evidence must fail
        self.dest = self.root / "second"
        self.assertEqual(self.run_collect(workspace, console, "success"), 1)

    def test_missing_console_still_writes_summary(self):
        workspace = self.root / "ws"
        workspace.mkdir()
        self.assertEqual(self.run_collect(workspace, self.root / "absent", "cancelled"), 0)
        self.assertTrue(self.summary.exists())

    def test_evidence_outside_workspace_is_refused(self):
        workspace, evidence, console = make_run(self.root)
        other = self.root / "elsewhere" / ("f" * 32)
        other.mkdir(parents=True)
        (other / "proof.json").write_text("{}")
        console.write_text(f"Evidence: {other}\n")
        self.assertEqual(self.run_collect(workspace, console, "failure"), 0)
        self.assertEqual(self.names(), ["console.log", "summary.md"])

    def test_symlinks_are_never_followed(self):
        workspace, evidence, console = make_run(self.root)
        secret = self.root / "secret.txt"
        secret.write_text("TOP-SECRET")
        (evidence / "command-004.log").symlink_to(secret)
        (evidence / "timings.json").unlink()
        (evidence / "timings.json").symlink_to(secret)
        self.assertEqual(self.run_collect(workspace, console, "failure"), 0)
        self.assertNotIn("command-004.log", self.names())
        self.assertNotIn("timings.json", self.names())
        self.assertNotIn("TOP-SECRET", "".join(p.read_text() for p in self.dest.iterdir()))
        self.assertIn("unsafe", self.summary.read_text())

    def test_symlinked_evidence_directory_is_refused(self):
        workspace, evidence, console = make_run(self.root)
        real = evidence.with_name("real")
        evidence.rename(real)
        evidence.symlink_to(real)
        self.assertEqual(self.run_collect(workspace, console, "failure"), 0)
        self.assertEqual(self.names(), ["console.log", "summary.md"])

    def test_file_count_cap_keeps_newest_failure_log(self):
        workspace, evidence, console = make_run(self.root, logs=300)
        self.assertEqual(self.run_collect(workspace, console, "failure"), 0)
        self.assertLessEqual(len(self.names()), 256)
        self.assertEqual((self.dest / "summary.md").read_text(), self.summary.read_text())
        for name in ("command-300.log", "proof.json", "console.log"):
            self.assertIn(name, self.names())
        self.assertNotIn("command-001.log", self.names())
        self.assertIn("older command logs skipped", self.summary.read_text())

    def test_byte_cap_tail_truncates_and_never_aborts(self):
        workspace, evidence, console = make_run(self.root, logs=0)
        for i in range(1, 11):
            (evidence / f"command-{i:03}.log").write_bytes(b"x" * (3 * 1024 * 1024 - 5) + b"END%02d\n" % i)
        self.assertEqual(self.run_collect(workspace, console, "failure"), 0)
        total = sum(p.stat().st_size for p in self.dest.iterdir())
        self.assertLessEqual(total, 16 * 1024 * 1024)
        newest = self.dest / "command-010.log"
        self.assertLessEqual(newest.stat().st_size, 2 * 1024 * 1024)
        self.assertTrue(newest.read_bytes().endswith(b"END10\n"))
        self.assertIn("truncated", self.summary.read_text())

    def test_untrusted_proof_text_never_enters_summary(self):
        proof = dict(GOOD_PROOF, session="# INJECTED [x](http://evil)")
        timings = {"elapsedSeconds": 1, "phases": [{"name": "ok\n# INJECTED", "seconds": 1}, {"name": "fine", "seconds": 2}]}
        workspace, _, console = make_run(self.root, proof=proof, timings=timings)
        self.assertEqual(self.run_collect(workspace, console), 0)
        text = self.summary.read_text()
        self.assertNotIn("INJECTED", text)
        self.assertIn("- Phase fine: 2.0s", text)

    def test_existing_destination_and_bad_url_are_refused(self):
        workspace, _, console = make_run(self.root)
        self.dest.mkdir(parents=True)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(self.run_collect(workspace, console), 1)
            self.dest = self.root / "fresh"
            self.assertEqual(e2e.main(["collect", "--workspace", str(workspace), "--console", str(console), "--destination", str(self.dest),
                                       "--summary", str(self.summary), "--result", "success", "--run-url", "http://evil/x"]), 1)
        self.assertFalse(self.dest.exists())


class FakeAPI:
    """In-memory REST subset; `lose` makes a call succeed server-side but raise client-side."""

    def __init__(self, issues=None, lose=(), fail=()):
        self.issues, self.calls, self.lose, self.fail = list(issues or []), [], set(lose), set(fail)

    def request(self, method, path, payload=None):
        self.calls.append((method, path, payload))
        key = (method, path.split("?")[0].rsplit("/", 1)[-1] if method != "GET" else "GET")
        if key in self.fail:
            raise e2e.ApiError(f"{method} failed")
        result = self._handle(method, path, payload)
        if key in self.lose:
            raise e2e.ApiError("response lost")
        return result

    def _handle(self, method, path, payload):
        base = "/repos/Azure/aks-durable-agents/issues"
        if method == "GET":
            assert path.startswith(base + "?"), path
            query = dict(p.split("=") for p in path.split("?")[1].split("&"))
            assert query["state"] == "all" and query["sort"] == "created" and query["direction"] == "asc" and query["per_page"] == "100"
            page = int(query["page"])
            return self.issues[(page - 1) * 100:page * 100]
        if method == "POST" and path == base:
            issue = {"number": len(self.issues) + 1, "title": payload["title"], "body": payload["body"], "state": "open", "user": BOT}
            self.issues.append(issue)
            return dict(issue)
        number = int(path[len(base) + 1:].split("/")[0])
        issue = next(i for i in self.issues if i["number"] == number)
        if method == "POST":
            issue.setdefault("comments", []).append(payload["body"])
            return {"id": 1}
        assert method == "PATCH"
        issue.update(payload)
        return dict(issue)

    def writes(self):
        return [c for c in self.calls if c[0] != "GET"]


def tracker(number=1, body=None, state="open", user=BOT, title="Kind e2e regression"):
    return {"number": number, "title": title, "state": state, "user": user,
            "body": body if body is not None else e2e.MARKER + "\n\nhuman note\n\n" + e2e.render_block(URL, SHA)}


def track(api, test=False, url=URL, sha=SHA):
    return e2e.track(api, "Azure/aks-durable-agents", 123, sha, url, test)


class TrackerTests(unittest.TestCase):
    def test_creates_then_updates_without_comments(self):
        api = FakeAPI()
        track(api)
        self.assertEqual([c[0] for c in api.writes()], ["POST"])
        self.assertIn(e2e.MARKER, api.issues[0]["body"])
        self.assertIn(URL, api.issues[0]["body"])
        e2e.track(api, "Azure/aks-durable-agents", 124, "c" * 40, URL.replace("123", "124"), False)
        self.assertEqual(len(api.issues), 1)
        self.assertIn("runs/124", api.issues[0]["body"])
        self.assertIn("c" * 40, api.issues[0]["body"])
        self.assertNotIn("runs/123", api.issues[0]["body"])
        self.assertNotIn("comments", api.issues[0])

    def test_closed_tracker_is_reopened_and_human_text_preserved(self):
        api = FakeAPI([tracker(state="closed", body=e2e.MARKER + "\nbefore\n" + e2e.render_block("old", "0" * 40) + "\nafter\n")])
        track(api)
        issue = api.issues[0]
        self.assertEqual(issue["state"], "open")
        self.assertTrue(issue["body"].startswith(e2e.MARKER + "\nbefore\n"))
        self.assertTrue(issue["body"].endswith("\nafter\n"))
        self.assertIn(URL, issue["body"])

    def test_strangers_and_lookalikes_are_ignored_before_counting(self):
        lookalike = tracker(1, user=HUMAN)
        wrong_type = tracker(2, user={"login": "github-actions[bot]", "type": "User"})
        pr = dict(tracker(3), pull_request={})
        api = FakeAPI([lookalike, wrong_type, pr])
        track(api)
        self.assertEqual(len(api.issues), 4)  # created a new one; strangers untouched
        self.assertEqual(api.issues[0]["body"], lookalike["body"])
        beside = FakeAPI([tracker(1, user=HUMAN), tracker(2)])
        track(beside)
        self.assertEqual(len(beside.issues), 2)
        self.assertIn(URL, beside.issues[1]["body"])
        self.assertNotIn(URL, beside.issues[0]["body"].replace(e2e.render_block(URL, SHA), ""))

    def test_missing_marker_or_wrong_title_is_not_a_tracker(self):
        api = FakeAPI([tracker(1, body="no marker"), tracker(2, title="Other")])
        track(api)
        self.assertEqual(len(api.issues), 3)

    def test_pagination_finds_old_tracker(self):
        filler = [tracker(i, user=HUMAN) for i in range(1, 101)]
        api = FakeAPI(filler + [tracker(101)])
        track(api)
        self.assertEqual(len(api.issues), 101)
        self.assertIn(URL, api.issues[100]["body"])
        self.assertEqual(len([c for c in api.calls if c[0] == "GET"]), 2)

    def test_incomplete_lookup_refuses_without_writes(self):
        class Endless(FakeAPI):
            def _handle(self, method, path, payload):
                return [dict(tracker(1), pull_request={})] * 100
        api = Endless()
        with self.assertRaises(e2e.ApiError):
            track(api)
        self.assertEqual(len([c for c in api.calls if c[0] == "GET"]), 100)
        self.assertEqual(api.writes(), [])

    def test_ambiguous_trackers_and_lookup_errors_refuse(self):
        api = FakeAPI([tracker(1), tracker(2)])
        with self.assertRaises(e2e.ApiError):
            track(api)
        self.assertEqual(api.writes(), [])
        api = FakeAPI(fail={("GET", "GET")})
        with self.assertRaises(e2e.ApiError):
            track(api)
        self.assertEqual(api.writes(), [])
        with self.assertRaises(e2e.ApiError):
            track(type("Odd", (), {"request": lambda s, m, p, payload=None: {"message": "nope"}})())

    def test_lost_create_response_is_not_retried_and_next_run_finds_it(self):
        api = FakeAPI(lose={("POST", "issues")})
        with self.assertRaises(e2e.ApiError):
            track(api)
        self.assertEqual(len(api.writes()), 1)
        track(api)
        self.assertEqual(len(api.issues), 1)
        self.assertEqual([c[0] for c in api.writes()], ["POST", "PATCH"])

    def test_malformed_managed_block_is_refused(self):
        for body in (e2e.MARKER + "\n" + e2e.START + "\nno end", e2e.MARKER + "\n" + e2e.END + "\n" + e2e.START,
                     e2e.MARKER + "\n" + e2e.render_block(URL, SHA) * 2):
            api = FakeAPI([tracker(body=body)])
            with self.assertRaises(e2e.ApiError):
                track(api)
            self.assertEqual(api.writes(), [])

    def test_marker_without_block_appends_block_keeping_text(self):
        api = FakeAPI([tracker(body=e2e.MARKER + "\nhuman\n")])
        track(api)
        self.assertTrue(api.issues[0]["body"].startswith(e2e.MARKER + "\nhuman\n"))
        self.assertIn(URL, api.issues[0]["body"])

    def test_test_mode_creates_comments_and_closes_without_touching_status(self):
        api = FakeAPI()
        track(api, test=True)
        issue = api.issues[0]
        self.assertEqual(issue["state"], "closed")
        self.assertEqual(issue["comments"], ["Test run: reporting permission check. No demo was run. " + URL])
        self.assertEqual([c[0] for c in api.writes()], ["POST", "POST", "PATCH"])

    def test_test_mode_closes_existing_tracker_and_preserves_body(self):
        existing = tracker()
        before = existing["body"]
        api = FakeAPI([existing])
        track(api, test=True)
        self.assertEqual(api.issues[0]["state"], "closed")
        self.assertEqual(api.issues[0]["body"], before)
        self.assertEqual([c[0] for c in api.writes()], ["POST", "PATCH"])

    def test_test_mode_errors_propagate_without_retry(self):
        for fail in (("POST", "comments"), ("PATCH", "1"), ("POST", "issues")):
            api = FakeAPI([tracker()] if fail[1] != "issues" else [], fail={fail})
            with self.assertRaises(e2e.ApiError):
                track(api, test=True)
            self.assertEqual(len([c for c in api.writes() if (c[0], c[1].rsplit("/", 1)[-1]) == fail]), 1)

    def test_inputs_are_validated(self):
        with self.assertRaises(ValueError):
            track(FakeAPI(), sha="abc")
        with self.assertRaises(ValueError):
            track(FakeAPI(), url="https://github.com/Azure/aks-durable-agents/actions/runs/999")
        with self.assertRaises(ValueError):
            track(FakeAPI(), url="https://evil.example/Azure/aks-durable-agents/actions/runs/123")

    def test_cli_reports_errors_as_nonzero_and_never_prints_token(self):
        err = io.StringIO()
        old = os.environ.pop("GITHUB_TOKEN", None)
        try:
            with contextlib.redirect_stderr(err):
                code = e2e.main(["track", "--repo", "Azure/aks-durable-agents", "--run-id", "123", "--sha", SHA, "--run-url", URL])
        finally:
            if old is not None:
                os.environ["GITHUB_TOKEN"] = old
        self.assertEqual(code, 1)
        self.assertIn("GITHUB_TOKEN", err.getvalue())

    def test_cli_with_injected_fake(self):
        api = FakeAPI()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = e2e.main(["track", "--repo", "Azure/aks-durable-agents", "--run-id", "123", "--sha", SHA, "--run-url", URL, "--test"], api=api)
        self.assertEqual(code, 0)
        self.assertIn("https://github.com/Azure/aks-durable-agents/issues/1", out.getvalue())


class HttpApiTests(unittest.TestCase):
    def test_redirects_are_not_followed_and_secrets_not_leaked(self):
        seen = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append((self.path, self.headers.get("Authorization")))
                if self.path == "/repos/a/b":
                    self.send_response(302)
                    self.send_header("Location", "/elsewhere")
                    self.end_headers()
                else:
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b'{"leak":"SECRET-BODY"}')

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        api = e2e.GitHubAPI("fake-token-value", base=f"http://127.0.0.1:{server.server_port}")
        with self.assertRaises(e2e.ApiError) as ctx:
            api.request("GET", "/repos/a/b")
        self.assertEqual(seen, [("/repos/a/b", "Bearer fake-token-value")])
        self.assertNotIn("fake-token-value", str(ctx.exception))
        with self.assertRaises(e2e.ApiError):
            api.request("GET", "https://evil.example/x")

    def test_production_base_is_https_github(self):
        self.assertEqual(e2e.GitHubAPI("t").base, "https://api.github.com")


if __name__ == "__main__":
    unittest.main()
