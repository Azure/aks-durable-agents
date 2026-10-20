"""Static security/trigger contracts; this does not claim a hosted run occurred."""
from pathlib import Path
import unittest
import yaml


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.path=Path(__file__).resolve().parents[2]/".github/workflows/kind-e2e.yml"
        self.workflow=yaml.load(self.path.read_text(),Loader=yaml.BaseLoader)

    def test_triggers_and_test_mode(self):
        w=self.workflow
        self.assertEqual(set(w["on"]),{"schedule","workflow_dispatch"})
        option=w["on"]["workflow_dispatch"]["inputs"]["report_test"]
        self.assertEqual(option["type"],"boolean")
        self.assertEqual(option["default"],"false")
        self.assertIn("!inputs.report_test",w["jobs"]["demo"]["if"])
        condition=w["jobs"]["report"]["if"]
        for text in ["always()","!cancelled()","github.repository == 'Azure/aks-durable-agents'","github.ref == 'refs/heads/main'","workflow_dispatch","inputs.report_test","needs.demo.result == 'failure'"]:
            self.assertIn(text,condition)
        self.assertEqual(w["jobs"]["report"]["needs"],"demo")

    def test_explicit_job_permissions_and_pinned_actions(self):
        w=self.workflow
        self.assertEqual(w["permissions"],{})
        self.assertEqual(w["jobs"]["demo"]["permissions"],{"contents":"read"})
        self.assertEqual(w["jobs"]["report"]["permissions"],{"contents":"read","issues":"write"})
        install=next(step["run"] for step in w["jobs"]["demo"]["steps"] if step.get("name")=="Install checked kind and kubectl")
        self.assertIn("6129359f4e1f3848a5572ccb0b26cf28b8ca08cef38c95a765b2f64a2c961a2f",install)
        self.assertNotIn("kubectl.sha256",install)
        self.assertTrue(all("--max-time 120" in line for line in install.splitlines() if "curl " in line))
        for name,job in w["jobs"].items():
            for step in job["steps"]:
                if "uses" in step:
                    self.assertRegex(step["uses"],r"^[^@]+@[a-f0-9]{40}$")
                    if step["uses"].startswith("actions/checkout@"):
                        self.assertEqual(step["with"]["persist-credentials"],"false")
                if "GITHUB_TOKEN" in step.get("env",{}):
                    self.assertEqual(name,"report")
            self.assertNotIn("continue-on-error",job)

    def test_same_demo_safe_artifacts_and_visible_report_test(self):
        jobs=self.workflow["jobs"]
        demo=jobs["demo"]
        scenario=next(s for s in demo["steps"] if s.get("id")=="scenario")
        self.assertIn("make demo",scenario["run"])
        self.assertIn("approve\\ncontinue\\n",scenario["run"])
        self.assertNotIn("continue-on-error",scenario)
        collect=next(s for s in demo["steps"] if s.get("id")=="collect")
        self.assertEqual(collect["if"],"${{ always() }}")
        artifact=next(s for s in demo["steps"] if s.get("uses","").startswith("actions/upload-artifact@"))
        self.assertEqual(artifact["if"],"${{ always() }}")
        self.assertEqual(artifact["with"]["path"],"${{ runner.temp }}/kind-e2e-artifacts")
        self.assertNotIn(".build",artifact["with"]["path"])
        report=next(s for s in jobs["report"]["steps"] if "run" in s)
        self.assertIn("--test",report["run"])
        self.assertNotIn("continue-on-error",report)
        self.assertFalse(any("download-artifact" in s.get("uses","") for s in jobs["report"]["steps"]))


if __name__=="__main__": unittest.main()
