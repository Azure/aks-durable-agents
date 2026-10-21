"""Report-only runner findings; checksums and execution budgets still block."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

SPEC = importlib.util.spec_from_file_location("tool_audit", Path(__file__).with_name("tool_audit.py"))
assert SPEC and SPEC.loader
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)
HASH = "65691ff77eb6fa44c908b77a1082c9f092c3b9733b5cefabec0d1104890e21a8"
LOGIN_HASH = "5160d49d0fb0d5f6fd7923058000f5fde34627a640cb4b313026992586c20ff2"
CONFIG = dict(protocol_version="v1.0.0", scanner_name="govulncheck", scanner_version="v1.9.0",
              db="https://vuln.go.dev", scan_level="symbol", scan_mode="binary")


def stream(*findings, config=None, version="go1.26.8"):
    return "\n".join(json.dumps(x, indent=2) for x in [
        {"config": CONFIG if config is None else config}, {"progress": {"message": "scanning"}},
        {"SBOM": {"go_version": version, "modules": []}},
        {"osv": {"id": "GO-2026-9999"}}, *({"finding": f} for f in findings)])


def finding(osv="GO-2026-6809", **frame):
    return {"osv": osv, "trace": [dict(module="stdlib", version="v1.26.8", **frame)]}


class AuditTests(unittest.TestCase):
    def evaluate(self, raw, tool="kubectl", digest=HASH, code=0):
        return audit.evaluate(tool, digest, raw, code)

    def test_all_advisories_are_reported_without_an_exception_list(self):
        self.assertEqual(self.evaluate(stream())["status"], "clean")
        result = self.evaluate(stream(finding(), *[finding("GO-2026-1111")] * 200, finding("GO-2099-9999")))
        self.assertEqual(result["status"], "findings")
        self.assertEqual(result["findings"], ["GO-2026-1111", "GO-2026-6809", "GO-2099-9999"])
        self.assertNotIn("excepted", result)
        raw = stream({"osv": "GO-2026-6809", "trace": [{"module": "stdlib", "version": "v1.26.6"}]}, version="go1.26.6")
        self.assertEqual(self.evaluate(raw, "kubelogin", LOGIN_HASH)["status"], "findings")

    def test_report_mode_is_not_an_integrity_or_own_code_bypass(self):
        for tool, digest in [("host", HASH), ("fixture", HASH), ("demo-client", HASH),
                             ("govulncheck", HASH), ("/tmp/kubectl", HASH), ("kubectl", "0" * 64),
                             ("kubectl", LOGIN_HASH), ("kubelogin", HASH)]:
            with self.subTest(tool=tool, digest=digest):
                self.assertEqual(self.evaluate(stream(finding()), tool, digest)["status"], "integrity-error")
        # No stdlib/package/version filtering: report every scanner finding.
        f = finding()
        f["trace"][0].update(module="external/module", package="net/http", version="v0.1.0")
        self.assertEqual(self.evaluate(stream(f))["findings"], ["GO-2026-6809"])

    def test_malformed_or_incomplete_scans_are_visible_not_clean(self):
        good = stream()
        bad = ["", "{}", good[:-1], good + "junk", good + '{"error":{"message":"secret"}}',
               good + '{"unknown":{}}', good + '{"progress":NaN}', good + '{"progress":Infinity}',
               good + '{"progress":{},"progress":{}}', good + '{"finding":{}}',
               good + '{"progress":{"message":"ok","extra":1e400}}',
               good + '{"finding":{"osv":"GO-2026-1111","trace":[]}}',
               good + '{"SBOM":{}}', good + json.dumps({"config": CONFIG}),
               good.replace('"SBOM"', '"sbom"'), good.split('\n}', 1)[1],
               good.replace('"config"', '"progress"'), " " * (32 * 1024 * 1024 + 1)]
        for key in CONFIG:
            bad.append(stream(config=dict(CONFIG, **{key: "wrong"})))
        for raw in bad:
            with self.subTest(raw=raw[:70]):
                self.assertEqual(self.evaluate(raw)["status"], "scan-error")
        self.assertEqual(self.evaluate(good, code=1)["status"], "scan-error")

    def test_cli_reports_findings_to_summary_and_artifacts_without_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("kubectl", "kubelogin"):
                (root / name).write_bytes(name.encode())
            pins = {name: (hashlib.sha256(name.encode()).hexdigest(), "v1.26.8") for name in ("kubectl", "kubelogin")}
            scanner = root / "govulncheck"
            scanner.write_text('#!/usr/bin/python3\nimport sys\nassert sys.argv[1:4] == ["-json", "-mode=binary", "-scan=symbol"]\nprint(' + repr(stream(finding(), finding("GO-2026-1111"))) + ')\n')
            scanner.chmod(0o700)
            report, summary = root / "report", root / "summary"
            with mock.patch.dict(os.environ, {"PATH": "/nonexistent"}), mock.patch.object(audit, "PINS", pins):
                with contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(audit.main(["--tools-dir", directory, "--report-dir", str(report), "--summary", str(summary)]), 0)
                results = json.loads((report / "report.json").read_text())
                self.assertEqual([x["tool"] for x in results], ["kubectl", "kubelogin"])
                self.assertTrue(all(x["findings"] == ["GO-2026-1111", "GO-2026-6809"] for x in results))
                self.assertEqual(sorted(x.name for x in report.iterdir()), ["report.json", "summary.md"])
                text = summary.read_text()
                self.assertIn("report-only", text)
                self.assertIn("GO-2026-1111", text)
                self.assertIn("::warning::", output.getvalue())
                self.assertNotIn(directory, text + output.getvalue())
                (root / "kubectl").write_bytes(b"own code")
                self.assertEqual(audit.scan_tool("kubectl", root)["status"], "integrity-error")
                (root / "kubectl").unlink()
                (root / "kubectl").symlink_to(root / "kubelogin")
                self.assertEqual(audit.scan_tool("kubectl", root)["status"], "integrity-error")

    def test_cli_scan_failure_is_reported_but_integrity_failure_blocks(self):
        for status, code in [("scan-error", 0), ("integrity-error", 1)]:
            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory:
                result = audit.decision("kubectl", status)
                with mock.patch.object(audit, "audit_tools", return_value=[result]), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(audit.main(["--tools-dir", directory, "--report-dir", directory + "/report"]), code)
                text = (Path(directory) / "report/summary.md").read_text()
                self.assertIn(status, text)
                self.assertIn("not evidence of zero vulnerabilities", text)

    def test_scanner_is_resolved_from_tool_directory_not_ambient_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "kubectl").write_bytes(b"pinned")
            scanner = root / "govulncheck"
            scanner.write_text('#!/usr/bin/python3\nprint(' + repr(stream()) + ')\n')
            scanner.chmod(0o700)
            pins = {"kubectl": (hashlib.sha256(b"pinned").hexdigest(), "v1.26.8")}
            with mock.patch.dict(os.environ, {"PATH": "/nonexistent"}), mock.patch.object(audit, "PINS", pins):
                self.assertEqual(audit.scan_tool("kubectl", root)["status"], "clean")

    def test_timeout_kills_scanner_descendants(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scanner = root / "govulncheck"
            scanner.write_text('#!/usr/bin/python3\nimport subprocess,time,pathlib\np=subprocess.Popen(["/usr/bin/sleep","30"])\npathlib.Path(' + repr(str(root / "pid")) + ').write_text(str(p.pid))\ntime.sleep(30)\n')
            scanner.chmod(0o700)
            with mock.patch.dict(os.environ, {"PATH": directory}), mock.patch.object(audit, "TIMEOUT", 0.3):
                with self.assertRaises(TimeoutError):
                    audit.run_scan(root / "kubectl")
            pid = (root / "pid").read_text()
            for _ in range(100):
                state = Path("/proc") / pid / "stat"
                if not state.exists() or state.read_text().split()[2] == "Z":
                    break
                time.sleep(0.01)
            else:
                self.fail("scanner descendant survived timeout")

    def test_scan_cap_timeout_is_report_only_but_caller_budget_expiry_propagates(self):
        with mock.patch.object(audit, "digest", return_value=HASH), mock.patch.object(audit, "run_scan", side_effect=TimeoutError):
            self.assertEqual(audit.scan_tool("kubectl", Path("/private/tools"))["status"], "scan-error")
            with self.assertRaisesRegex(TimeoutError, "budget"):
                audit.scan_tool("kubectl", Path("/private/tools"), timeout=2)

    def test_runtime_budget_is_recomputed_before_and_after_each_binary(self):
        remaining = mock.Mock(side_effect=[5, 4, 3, 2])
        with mock.patch.object(audit, "scan_tool", return_value=audit.decision("kubectl", "clean")) as scan:
            self.assertEqual(len(audit.audit_tools(Path("/private/tools"), remaining)), 2)
        self.assertEqual([c.kwargs["timeout"] for c in scan.call_args_list], [5, 3])
        self.assertEqual(remaining.call_count, 4)

    def test_cancellation_never_returns_success(self):
        with mock.patch.object(audit, "run_scan", side_effect=KeyboardInterrupt), mock.patch.object(audit, "digest", return_value=HASH):
            with self.assertRaises(KeyboardInterrupt):
                audit.scan_tool("kubectl", Path("/private/tools"))
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(audit, "audit_tools", side_effect=KeyboardInterrupt):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(audit.main(["--tools-dir", directory, "--report-dir", directory + "/report"]), 130)

    def test_digest_rechecked_after_scanning(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "kubectl").write_bytes(b"before")
            def mutate(path):
                path.write_bytes(b"after")
                return stream(), 0
            with mock.patch.object(audit, "PINS", {"kubectl": (hashlib.sha256(b"before").hexdigest(), "v1.26.8")}), mock.patch.object(audit, "run_scan", mutate):
                self.assertEqual(audit.scan_tool("kubectl", root)["status"], "integrity-error")


if __name__ == "__main__":
    unittest.main()
