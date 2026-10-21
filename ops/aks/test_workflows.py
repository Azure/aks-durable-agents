"""Keep the bootstrap inert and its cleanup on trusted default-branch code."""
from pathlib import Path
import re
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]


class WorkflowTests(unittest.TestCase):
    def workflow(self, name):
        return yaml.safe_load((ROOT / ".github/workflows" / name).read_text())

    def test_dispatch_has_no_scenario_schedule_or_write_commands(self):
        workflow = self.workflow("aks-e2e.yml")
        events = workflow.get("on", workflow.get(True))
        self.assertEqual(set(events), {"workflow_dispatch"})
        text = (ROOT / ".github/workflows/aks-e2e.yml").read_text()
        for forbidden in ("aks create", "make demo", "helm ", "kubectl ", "--apply", "pull_request_target"):
            self.assertNotIn(forbidden, text)
        self.assertIn("cleanup.py validate", text)

    def test_cleanup_schedule_is_separate_and_dispatch_defaults_dry(self):
        workflow = self.workflow("aks-cleanup.yml")
        events = workflow.get("on", workflow.get(True))
        self.assertEqual(events["workflow_dispatch"]["inputs"]["dry_run"]["default"], True)
        self.assertEqual(events["schedule"], [{"cron": "7,22,37,52 * * * *"}])
        self.assertEqual(events["workflow_run"]["workflows"], ["Nightly AKS e2e"])
        job = workflow["jobs"]["cleanup"]
        self.assertEqual(job["concurrency"], {"group": "aks-nightly-mutations", "cancel-in-progress": False})
        self.assertLessEqual(job["timeout-minutes"], 10)
        script = "\n".join(s.get("run", "") for s in job["steps"])
        self.assertIn('"$EVENT_NAME" != workflow_dispatch', script)
        self.assertIn('"$DRY_RUN" == false', script)
        self.assertIn("--apply", script)

    def test_permissions_login_gating_main_checkout_and_no_untrusted_code(self):
        for name, action in (("aks-e2e.yml", "validate"), ("aks-cleanup.yml", "cleanup")):
            workflow = self.workflow(name)
            with self.subTest(name=name):
                self.assertEqual(workflow["permissions"], {})
                config = workflow["jobs"]["config"]
                self.assertEqual(config["permissions"], {"contents": "read"})
                self.assertNotIn("environment", config)
                self.assertIn("github.repository == 'Azure/aks-durable-agents'", config["if"])
                self.assertIn("github.ref == 'refs/heads/main'", config["if"])
                self.assertIn("configured", config["outputs"])
                job = workflow["jobs"][action]
                self.assertEqual(job["environment"], "nightly-aks")
                self.assertEqual(job["permissions"], {"contents": "read", "id-token": "write"})
                self.assertIn("needs.config.outputs.configured == 'true'", job["if"])
                self.assertEqual(job["needs"], "config")
                for selected in (config, job):
                    checkout = next(s for s in selected["steps"] if s.get("uses", "").startswith("actions/checkout@"))
                    self.assertEqual(checkout["with"]["ref"], "refs/heads/main")
                    self.assertFalse(checkout["with"]["persist-credentials"])
                    for step in selected["steps"]:
                        if "uses" in step:
                            self.assertRegex(step["uses"], r"@[0-9a-f]{40}$")
                uses = [s.get("uses", "") for s in job["steps"]]
                self.assertTrue(any(u.startswith("Azure/login@") for u in uses))
                text = (ROOT / ".github/workflows" / name).read_text()
                self.assertNotIn("head_sha", text)
                self.assertNotIn("download-artifact", text)
                self.assertNotIn("secrets.", text)
                self.assertIn("::add-mask::", text)
                for key in ("AZURE_CLIENT_ID", "AZURE_TENANT_ID", "AZURE_SUBSCRIPTION_ID", "AKS_BOOTSTRAP_ENABLED",
                            "AKS_RESOURCE_GROUP", "AKS_CLUSTER_NAME", "AKS_NODE_RESOURCE_GROUP",
                            "AKS_IDENTITY_RESOURCE_GROUP", "AKS_MODEL_IDENTITY_NAME"):
                    self.assertEqual(workflow["env"][key], "${{ vars." + key + " }}")

    def test_ci_runs_new_suite(self):
        workflow = self.workflow("ci.yml")
        scripts = "\n".join(s.get("run", "") for j in workflow["jobs"].values() for s in j.get("steps", []))
        self.assertIn("unittest discover -s ops/aks -p 'test_*.py'", scripts)


if __name__ == "__main__":
    unittest.main()
