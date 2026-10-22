"""Private, atomic installer evidence; no cloud commands or real credentials."""
import base64
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import quote, quote_plus

import cleanup
from substrate_evidence import Evidence


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def evidence(self, name="evidence", **kwargs):
        evidence = Evidence(self.root / name, **kwargs)
        self.addCleanup(evidence.close)
        return evidence

    def test_new_private_directory_atomic_files_and_no_reuse(self):
        evidence = self.evidence()
        directory = self.root / "evidence"
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        evidence.write_json("native-proof.json", {"status": "nativePassed"})
        self.assertEqual(json.loads((directory / "native-proof.json").read_text()), {"status": "nativePassed"})
        self.assertEqual(stat.S_IMODE((directory / "native-proof.json").stat().st_mode), 0o600)
        with self.assertRaises(ValueError):
            Evidence(directory)
        with self.assertRaises(ValueError):
            Evidence(self.root / "missing" / "evidence")
        for name in ("../outside.json", "/absolute.json", "nested/x.json", ".", "", "name\n.json"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                evidence.write_json(name, {})
        self.assertEqual(sorted(p.name for p in directory.iterdir()), ["native-proof.json"])

    def test_closed_writer_refuses_instead_of_writing_to_current_directory(self):
        evidence = self.evidence()
        evidence.close()
        original = Path.cwd()
        try:
            os.chdir(self.root)
            with self.assertRaisesRegex(ValueError, "closed"):
                evidence.write_json("after-close.json", {"status": "nativePassed"})
        finally:
            os.chdir(original)
        self.assertFalse((self.root / "after-close.json").exists())

    def test_symlink_leaf_and_ancestors_are_rejected(self):
        (self.root / "link").symlink_to(self.root, target_is_directory=True)
        for path in (self.root / "link", self.root / "link" / "new"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                Evidence(path)
        self.assertFalse((self.root / "new").exists())

    def test_symlink_followed_by_parent_component_is_not_normalized_away(self):
        nested = self.root / "resolved" / "nested"
        nested.mkdir(parents=True)
        (self.root / "link").symlink_to(nested, target_is_directory=True)
        with self.assertRaises(ValueError):
            evidence = Evidence(self.root / "link" / ".." / "evidence")
            self.addCleanup(evidence.close)
        self.assertFalse((self.root / "evidence").exists())
        self.assertFalse((self.root / "resolved" / "evidence").exists())

    def test_relative_path_and_bound_fd_survive_chdir_and_directory_rename(self):
        original = Path.cwd()
        try:
            os.chdir(self.root)
            evidence = Evidence("evidence")
            self.addCleanup(evidence.close)
            os.rename("evidence", "renamed")
            Path("evidence").mkdir()
            os.chdir("/")
            evidence.write_json("native-proof.json", {"stableIdentity": True})
        finally:
            os.chdir(original)
        self.assertTrue((self.root / "renamed/native-proof.json").exists())
        self.assertFalse((self.root / "evidence/native-proof.json").exists())

    def test_atomic_failure_keeps_old_complete_file_and_cleans_temporary(self):
        evidence = self.evidence()
        evidence.write_json("native-proof.json", {"old": True})
        with mock.patch("os.replace", side_effect=OSError("disk failed")), self.assertRaises(OSError):
            evidence.write_json("native-proof.json", {"new": True})
        self.assertEqual(json.loads((self.root / "evidence/native-proof.json").read_text()), {"old": True})
        self.assertEqual([p.name for p in (self.root / "evidence").iterdir()], ["native-proof.json"])

    def test_real_commands_log_empty_success_failure_and_timeout_without_stdout(self):
        evidence = self.evidence()
        programs = (
            ("import sys; sys.stdout.write('stdout-private'); sys.stderr.write('success diagnostic')", "success diagnostic", False),
            ("pass", "", False),
            ("import sys; sys.stderr.write('failure diagnostic'); sys.exit(4)", "failure diagnostic", True),
            ("import sys,time; sys.stderr.write('timeout diagnostic'); sys.stderr.flush(); time.sleep(60)", "timeout diagnostic", True))
        for sequence, (program, expected, fails) in enumerate(programs, 1):
            if fails:
                with self.assertRaises(cleanup.CloudError):
                    evidence.command([sys.executable, "-c", program], timeout=0.2)
            else:
                result = evidence.command([sys.executable, "-c", program], timeout=3)
                self.assertEqual(result, b"stdout-private" if sequence == 1 else b"")
            self.assertEqual((self.root / f"evidence/{sequence:04d}.stderr.txt").read_text(), expected)
        index = json.loads((self.root / "evidence/steps.json").read_text())
        self.assertEqual([row["sequence"] for row in index], [1, 2, 3, 4])
        self.assertEqual([row["status"] for row in index], ["passed", "passed", "CloudError", "CloudError"])
        for row in index:
            self.assertEqual(set(row), {"sequence", "tool", "operation", "status"})
        all_output = "".join(p.read_text() for p in (self.root / "evidence").iterdir())
        self.assertNotIn("stdout-private", all_output)
        self.assertNotIn("-c", all_output)
        for path in (self.root / "evidence").iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_only_known_tool_labels_and_native_operations_are_recorded(self):
        def run(args, *, timeout, input=None, stderr_sink=None):
            return b""
        evidence = self.evidence(run=run)
        evidence.command(["/private/sensitive-binary-name", "private-argument"], timeout=1)
        evidence.command(["/private/kubectl-ate", "--context", "private-context", "resume", "actor"], timeout=1)
        evidence.command(["/private/ate-setup", "create", "private-argument"], timeout=1)
        self.assertEqual([(s["tool"], s["operation"]) for s in evidence.steps],
                         [("external", "other"), ("kubectl-ate", "resume"), ("ate-setup", "create")])
        index = (self.root / "evidence/steps.json").read_text()
        self.assertNotIn("sensitive-binary-name", index)
        self.assertNotIn("private-argument", index)
        self.assertNotIn("private-context", index)

    def test_operation_skips_caller_option_values_even_when_they_are_verbs(self):
        def run(args, *, timeout, input=None, stderr_sink=None):
            return b""
        evidence = self.evidence(run=run)
        commands = (
            (["kubectl", "--kubeconfig", "/private/config", "--context", "delete", "get", "nodes"], "get"),
            (["kubectl", "--kubeconfig", "/private/config", "--context", "get", "delete", "pod/probe"], "delete"),
            (["kubectl-ate", "--kubeconfig", "/private/config", "--context", "resume", "create", "actor"], "create"),
            (["git", "-C", "status", "rev-parse", "HEAD"], "rev-parse"),
            (["git", "-C", "rev-parse", "status", "--porcelain"], "status"),
        )
        for command, expected in commands:
            with self.subTest(command=command):
                evidence.command(command, timeout=1)
                self.assertEqual(evidence.steps[-1]["operation"], expected)

    def test_startup_error_does_not_store_exception_path_or_arguments(self):
        evidence = self.evidence()
        with self.assertRaises(cleanup.CloudError):
            evidence.command(["/private/not-existing", "sensitive-argument"], timeout=1)
        self.assertEqual((self.root / "evidence/0001.stderr.txt").read_bytes(), b"")
        index = (self.root / "evidence/steps.json").read_text()
        self.assertNotIn("/private", index)
        self.assertNotIn("sensitive-argument", index)

    def test_environment_snapshot_and_secret_stdin_redact_raw_and_encoded_values(self):
        env_secret, stdin_secret = "env-sensitive /+value", "stdin-sensitive /+value"
        env_forms = [env_secret, quote(env_secret, safe=""), quote_plus(env_secret),
                     base64.b64encode(env_secret.encode()).decode()]
        stdin_forms = [stdin_secret, quote(stdin_secret, safe=""), quote_plus(stdin_secret),
                       base64.b64encode(stdin_secret.encode()).decode()]
        diagnostics = "\n".join(env_forms + stdin_forms + ["useful diagnostic"])
        def run(args, *, timeout, input=None, stderr_sink=None):
            assert stderr_sink is not None
            stderr_sink(diagnostics.encode())
            return b"unchanged stdout"
        for section, value in (("stringData", stdin_secret), ("data", stdin_forms[-1])):
            with mock.patch.dict(os.environ, {"MODEL_API_KEY": env_secret}):
                evidence = self.evidence("evidence-" + section, run=run)
            payload = json.dumps({"kind": "Secret", section: {"key": value}}).encode()
            self.assertEqual(evidence.command(["kubectl", "apply", "-f", "-"], timeout=1, input=payload),
                             b"unchanged stdout")
            text = (self.root / f"evidence-{section}/0001.stderr.txt").read_text()
            for form in env_forms + stdin_forms:
                self.assertNotIn(form, text)
            self.assertIn("useful diagnostic", text)

    def test_generic_redaction_controls_and_tail_boundary(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJwcml2YXRlIn0.signature"
        pem_body = "private-key-material-" * 4000
        diagnostics = ('{"client_secret":"json-sensitive","password":"password-sensitive"}\n'
                       "Authorization: Bearer auth-sensitive\nhttps://user:pass@example.test/x\n"
                       "ghp_abcdefghijklmnopqrstuvwxyz123456\n" + jwt + "\n"
                       "-----BEGIN PRIVATE KEY-----\n" + pem_body + "\n-----END PRIVATE KEY-----\n"
                       "\x1b[31m::error::visible\x00\x07\r\n")
        def run(args, *, timeout, input=None, stderr_sink=None):
            assert stderr_sink is not None
            stderr_sink(diagnostics.encode())
            return b""
        evidence = self.evidence(run=run)
        evidence.command(["kubectl", "get", "pods"], timeout=1)
        text = (self.root / "evidence/0001.stderr.txt").read_text()
        for secret in ("json-sensitive", "password-sensitive", "auth-sensitive", "user:pass", "ghp_",
                       jwt, "private-key-material", "::", "\x1b", "\x00", "\x07", "\r"):
            self.assertNotIn(secret, text)
        self.assertIn("visible", text)
        self.assertIn("[REDACTED]", text)

    def test_known_secret_crossing_tail_boundary_is_redacted_before_truncation(self):
        secret = "boundary-secret-" * 40
        diagnostics = secret + "x" * 65300
        def run(args, *, timeout, input=None, stderr_sink=None):
            assert stderr_sink is not None
            stderr_sink(diagnostics.encode())
            return b""
        with mock.patch.dict(os.environ, {"ACCESS_TOKEN": secret}):
            evidence = self.evidence(run=run)
        evidence.command(["kubectl", "get", "pods"], timeout=1)
        text = (self.root / "evidence/0001.stderr.txt").read_text()
        self.assertNotIn("boundary-secret", text)
        self.assertLessEqual(len(text.encode()), 65536)

    def test_write_failure_stops_next_normal_command_but_allows_cleanup(self):
        calls = []
        def run(args, *, timeout, input=None, stderr_sink=None):
            calls.append(args)
            assert stderr_sink is not None
            stderr_sink(b"diagnostic")
            return b"ok"
        evidence = self.evidence(run=run)
        with mock.patch.object(evidence, "write_json", side_effect=OSError("full")):
            self.assertEqual(evidence.command(["kubectl", "apply"], timeout=1), b"ok")
        self.assertTrue(evidence.write_failed)
        with self.assertRaisesRegex(cleanup.CloudError, "evidence writing failed"):
            evidence.command(["kubectl", "get"], timeout=1)
        self.assertEqual(len(calls), 1)
        evidence.cleanup_started = True
        self.assertEqual(evidence.command(["kubectl", "delete"], timeout=1), b"ok")
        self.assertEqual(len(calls), 2)

    def test_long_numeric_environment_credential_is_redacted(self):
        def run(args, *, timeout, input=None, stderr_sink=None):
            assert stderr_sink is not None
            stderr_sink(b"credential 98765432109876543210; count 12")
            return b""
        with mock.patch.dict(os.environ, {"SERVICE_API_KEY": "98765432109876543210"}):
            evidence = self.evidence(run=run)
        evidence.command(["kubectl", "get"], timeout=1)
        text = (self.root / "evidence/0001.stderr.txt").read_text()
        self.assertNotIn("98765432109876543210", text)
        self.assertIn("count 12", text)

    def test_proof_write_replaces_symlink_without_touching_its_target(self):
        evidence = self.evidence()
        outside = self.root / "outside"
        outside.write_text("untouched")
        (self.root / "evidence/native-proof.json").symlink_to(outside)
        evidence.write_json("native-proof.json", {"safe": True})
        self.assertEqual(outside.read_text(), "untouched")
        self.assertFalse((self.root / "evidence/native-proof.json").is_symlink())

    def test_runner_without_sink_events_still_gets_empty_log(self):
        def run(args, *, timeout, input=None, stderr_sink=None):
            return b"stdout-only"
        evidence = self.evidence(run=run)
        self.assertEqual(evidence.command(["kubectl", "get"], timeout=1), b"stdout-only")
        self.assertEqual((self.root / "evidence/0001.stderr.txt").read_bytes(), b"")

    def test_evidence_write_failure_preserves_primary_exception(self):
        def run(args, *, timeout, input=None, stderr_sink=None):
            assert stderr_sink is not None
            stderr_sink(b"failed")
            raise ValueError("primary failure")
        evidence = self.evidence(run=run)
        with (mock.patch.object(evidence, "write_json", side_effect=OSError("full")),
              self.assertRaisesRegex(ValueError, "primary failure")):
            evidence.command(["kubectl", "apply"], timeout=1)
        self.assertTrue(evidence.write_failed)


if __name__ == "__main__":
    unittest.main()
