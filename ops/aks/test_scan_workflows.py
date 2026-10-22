"""Scan contracts stand alone without the optional AKS scenario."""
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


class ScanWorkflowTests(unittest.TestCase):
    def workflow(self, name):
        return yaml.safe_load((ROOT / ".github/workflows" / name).read_text())

    def test_runner_tool_pins_and_binary_audit_do_not_filter_our_source_scan(self):
        tools = (ROOT / "ops/aks/tools.sh").read_text()
        self.assertIn("release/v1.37.1/bin/linux/amd64/kubectl", tools)
        self.assertIn("65691ff77eb6fa44c908b77a1082c9f092c3b9733b5cefabec0d1104890e21a8", tools)
        self.assertIn("releases/download/v0.2.21/kubelogin-linux-amd64.zip", tools)
        self.assertIn("934a2a9618e018cb9fbeb14f3e4c28416fdae815df7706df91500e41d234eb66", tools)
        self.assertIn("golang.org/x/vuln/cmd/govulncheck@v1.9.0", tools)
        self.assertNotIn("GOTOOLCHAIN=go1.27.2", tools)
        ci = self.workflow("ci.yml")
        audit = ci["jobs"]["runner_tools"]
        self.assertEqual(audit["permissions"], {"contents": "read"})
        self.assertNotIn("environment", audit)
        scripts = "\n".join(s.get("run", "") for s in audit["steps"])
        self.assertIn("bash ops/aks/tools.sh", scripts)
        self.assertIn("python3 -B ops/aks/tool_audit.py", scripts)
        self.assertNotIn("continue-on-error", str(audit))
        source = next(s["run"] for s in ci["jobs"]["go"]["steps"] if s.get("name") == "Vulnerability check")
        self.assertIn("govulncheck ./...", source)
        self.assertNotIn("tool_audit", source)
        self.assertNotIn("GO-2026-6809", source)
        self.assertNotIn("||", source)

    def test_runner_reports_have_separate_allowlisted_always_uploads(self):
        ci = self.workflow("ci.yml")["jobs"]["runner_tools"]
        self.assertIn('--report-dir "$RUNNER_TEMP/aks-tool-report"', str(ci))
        for job in (ci,):
            upload = next(s for s in job["steps"] if s.get("with", {}).get("name", "").startswith("runner-tool-scans-"))
            self.assertIn("always()", upload["if"])
            self.assertEqual(upload["with"]["if-no-files-found"], "warn")
            self.assertEqual(upload["with"]["retention-days"], 7)
            self.assertEqual(upload["with"]["path"].splitlines(), [
                "${{ runner.temp }}/aks-tool-report/report.json", "${{ runner.temp }}/aks-tool-report/summary.md"])

    def test_image_source_and_packaged_binary_scans_remain_strict(self):
        jobs = self.workflow("images.yml")["jobs"]
        for job in jobs.values():
            self.assertNotIn("continue-on-error", str(job))
            self.assertNotIn("tool_audit", str(job))
        # The source matrix has its own packaged-binary contracts; the collector builds nothing.
        for job in (jobs["validate"], jobs["publish"]):
            scripts = [s.get("run", "") for s in job["steps"]]
            self.assertTrue(any("go install golang.org/x/vuln/cmd/govulncheck@v1.9.0" in s for s in scripts))
            scan = next(i for i, s in enumerate(scripts) if "bash ops/images/vulncheck.sh" in s)
            smoke = next(i for i, s in enumerate(scripts) if "bash ops/images/smoke.sh" in s)
            self.assertGreater(scan, smoke)
        publish = jobs["publish"]["steps"]
        before_push = next(s["run"] for s in publish if s.get("name") == "Verify and build from the pinned module graph")
        self.assertIn("govulncheck ./...", before_push)
        self.assertIn("govulncheck -mode=binary .build/images/host", before_push)
        self.assertIn("govulncheck -mode=binary .build/images/session-fixture", before_push)
        self.assertNotIn("||", before_push)
        scan = next(i for i, s in enumerate(publish) if "bash ops/images/vulncheck.sh" in s.get("run", ""))
        sign = next(i for i, s in enumerate(publish) if s.get("name") == "Sign digests and record SBOMs")
        self.assertLess(scan, sign)


if __name__ == "__main__":
    unittest.main()
