"""Keep the bootstrap inert and its cleanup on trusted default-branch code."""
import subprocess
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


class WorkflowTests(unittest.TestCase):
    def workflow(self, name):
        return yaml.safe_load((ROOT / ".github/workflows" / name).read_text())

    def test_dispatch_has_no_scenario_schedule_and_defaults_to_read_only(self):
        workflow = self.workflow("aks-e2e.yml")
        events = workflow.get("on", workflow.get(True))
        self.assertEqual(set(events), {"workflow_dispatch"})
        text = (ROOT / ".github/workflows/aks-e2e.yml").read_text()
        self.assertFalse(events["workflow_dispatch"]["inputs"]["run_scenario"]["default"])
        self.assertIn("cleanup.py validate", text)
        self.assertNotIn("pull_request_target", text)
        self.assertNotIn("make demo", text)
        self.assertIn("!inputs.run_scenario", workflow["jobs"]["validate"]["if"])

    def test_scenario_gates_short_locks_and_always_teardown(self):
        workflow = self.workflow("aks-e2e.yml")
        jobs = workflow["jobs"]
        config_script = "\n".join(s.get("run", "") for s in jobs["config"]["steps"])
        for gate in ("AKS_SCENARIO_ENABLED", "AKS_BUDGET_CONFIRMED"):
            self.assertIn(gate, config_script)
        for name in ("create", "federate", "teardown"):
            self.assertEqual(jobs[name]["concurrency"], {"group": "aks-nightly-mutations", "cancel-in-progress": False})
        self.assertNotIn("concurrency", jobs["scenario"])
        self.assertNotIn("concurrency", jobs["wait"])
        self.assertIn("always()", jobs["teardown"]["if"])
        self.assertIn("always()", jobs["finalize"]["if"])
        self.assertNotIn("concurrency", jobs["finalize"])
        final_script = "\n".join(s.get("run", "") for s in jobs["finalize"]["steps"])
        self.assertIn("success", final_script)
        self.assertIn("TEARDOWN_RESULT", final_script)
        self.assertIn("aks-nightly-mutations", str(jobs))
        self.assertIn("AKS_STARTED_EPOCH", str(jobs))
        self.assertIn("WORK_DEADLINE_EPOCH", str(jobs))
        self.assertIn("HARD_DEADLINE_EPOCH", str(jobs))

    def test_scenario_checkout_is_immutable_and_public_upload_allowlisted(self):
        workflow = self.workflow("aks-e2e.yml")
        jobs = workflow["jobs"]
        for name in ("preflight", "create", "wait", "federate", "scenario", "teardown"):
            job = jobs[name]
            self.assertEqual(job["permissions"], {"contents": "read", "id-token": "write"})
            self.assertEqual(job["environment"], "nightly-aks")
            checkout = next(s for s in job["steps"] if s.get("uses", "").startswith("actions/checkout@"))
            self.assertEqual(checkout["with"]["ref"], "${{ github.sha }}")
            self.assertFalse(checkout["with"]["persist-credentials"])
        upload = next(s for s in jobs["scenario"]["steps"] if s.get("with", {}).get("name", "").startswith("aks-e2e-"))
        self.assertEqual(upload["with"]["retention-days"], 7)
        self.assertEqual(upload["with"]["path"], "${{ runner.temp }}/aks-public")
        self.assertNotIn("archive", upload["with"]["path"])
        self.assertNotIn("kubeconfig", upload["with"]["path"])
        for step in jobs["scenario"]["steps"]:
            if "uses" in step:
                self.assertRegex(step["uses"], r"@[0-9a-f]{40}$")

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

    def test_skipped_exercise_collects_fixed_failure_metadata(self):
        workflow = self.workflow("aks-e2e.yml")
        collect = next(s for s in workflow["jobs"]["scenario"]["steps"] if s.get("name", "").startswith("Collect only"))
        prefix = collect["run"].split("python3 -B ops/demo/e2e.py", 1)[0]
        for outcome in ("success", "failure", "cancelled", "skipped"):
            result = subprocess.run(["bash", "-e", "-c", prefix + '\n printf "%s" "$result"'],
                                    env={"RESULT": outcome}, capture_output=True, text=True, check=True)
            self.assertEqual(result.stdout, "failure" if outcome == "skipped" else outcome)

    def test_report_names_config_failure_and_prioritizes_unconfirmed_teardown(self):
        workflow = self.workflow("aks-e2e.yml")
        step = workflow["jobs"]["report"]["steps"][-1]
        prefix = step["run"].split("python3 -B ops/demo/e2e.py", 1)[0]
        base = {key + "_RESULT": "success" for key in ("CONFIG", "PREFLIGHT", "CREATE", "WAIT", "FEDERATE", "SCENARIO", "TEARDOWN")}
        cases = [(dict(base, CONFIG_RESULT="failure", PREFLIGHT_RESULT="skipped", TEARDOWN_RESULT="skipped", STARTED=""), "config"),
                 (dict(base, CREATE_RESULT="failure", TEARDOWN_RESULT="cancelled", STARTED="1000"), "teardown"),
                 (dict(base, SCENARIO_RESULT="failure", STARTED="1000"), "scenario")]
        for env, expected in cases:
            result = subprocess.run(["bash", "-e", "-c", prefix + '\n printf "%s" "$stage"'], env=env,
                                    capture_output=True, text=True, check=True)
            self.assertEqual(result.stdout, expected)

    def test_scenario_installs_scanned_tools_before_credentials_and_inference(self):
        scenario = self.workflow("aks-e2e.yml")["jobs"]["scenario"]
        go = next(s for s in scenario["steps"] if s.get("uses", "").startswith("actions/setup-go@"))
        self.assertEqual(go["with"], {"go-version-file": "go.mod"})
        steps = [s.get("run", "") for s in scenario["steps"]]
        tools_step = next(i for i, run in enumerate(steps) if "lifecycle.py tools" in run)
        credentials_step = next(i for i, run in enumerate(steps) if "lifecycle.py credentials" in run)
        exercise_step = next(i for i, run in enumerate(steps) if "ops/aks/nightly.py" in run)
        self.assertLess(tools_step, credentials_step)
        self.assertLess(credentials_step, exercise_step)

    def test_scenario_runner_report_upload_is_allowlisted_and_always_runs(self):
        scenario = self.workflow("aks-e2e.yml")["jobs"]["scenario"]
        upload = next(s for s in scenario["steps"] if s.get("with", {}).get("name", "").startswith("runner-tool-scans-"))
        self.assertIn("always()", upload["if"])
        self.assertEqual(upload["with"]["if-no-files-found"], "warn")
        self.assertEqual(upload["with"]["retention-days"], 7)
        self.assertEqual(upload["with"]["path"].splitlines(), [
            "${{ runner.temp }}/aks-tool-report/report.json", "${{ runner.temp }}/aks-tool-report/summary.md"])

    def test_ci_runs_new_suite(self):
        workflow = self.workflow("ci.yml")
        scripts = "\n".join(s.get("run", "") for j in workflow["jobs"].values() for s in j.get("steps", []))
        self.assertIn("unittest discover -s ops/aks -p 'test_*.py'", scripts)


if __name__ == "__main__":
    unittest.main()
