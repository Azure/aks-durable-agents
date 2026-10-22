"""Keep the bootstrap inert and its cleanup on trusted default-branch code."""
import subprocess
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


class WorkflowTests(unittest.TestCase):
    def workflow(self, name):
        return yaml.safe_load((ROOT / ".github/workflows" / name).read_text())

    def test_actor_variant_is_explicit_and_prepared_before_create(self):
        workflow = self.workflow("aks-e2e.yml")
        events = workflow.get("on", workflow.get(True))
        inputs = events["workflow_dispatch"]["inputs"]
        self.assertEqual(inputs["variant"]["default"], "no-sandbox")
        self.assertEqual(inputs["variant"]["options"], ["no-sandbox", "substrate-gvisor"])
        jobs = workflow["jobs"]
        prepared = jobs["substrate-inputs"]
        self.assertIn("needs.config.outputs.variant == 'substrate-gvisor'", prepared["if"])
        self.assertNotIn("environment", prepared)
        self.assertEqual(prepared["permissions"], {"contents": "read", "actions": "read"})
        self.assertNotIn("Azure/login", str(prepared))
        self.assertIn("substrate-inputs", jobs["create"]["needs"])
        self.assertIn("needs.preflight.result == 'success'", jobs["create"]["if"])
        self.assertIn("needs.substrate-inputs.result == 'success'", jobs["create"]["if"])
        self.assertIn("always()", jobs["create"]["if"])
        source = next(s for s in prepared["steps"] if s.get("with", {}).get("repository") == "agent-substrate/substrate")
        self.assertEqual(source["with"]["ref"], "e8d40c33f96f4b7a4984bfea7334a36ab5b45b7b")
        runs = [s.get("run", "") for s in prepared["steps"]]
        self.assertTrue(any("ops/aks/tools.sh" in run for run in runs))
        self.assertTrue(any("substrate_inputs.py prepare" in run for run in runs))
        scenario = jobs["scenario"]
        normal_tools = next(s for s in scenario["steps"] if "lifecycle.py tools" in s.get("run", ""))
        self.assertIn("!= 'substrate-gvisor'", normal_tools["if"])
        extract = next(s for s in scenario["steps"] if "filter='data'" in s.get("run", ""))
        self.assertIn("== 'substrate-gvisor'", extract["if"])
        exercise = next(s["run"] for s in scenario["steps"] if s.get("id") == "exercise")
        self.assertIn('--variant "$VARIANT"', exercise)
        self.assertIn("--substrate-image-map", exercise)
        finalize = jobs["finalize"]["steps"][0]
        self.assertIn("INPUTS_RESULT", finalize["env"])
        self.assertIn("substrate-gvisor", finalize["run"])

    def test_daily_schedule_and_read_only_manual_default(self):
        workflow = self.workflow("aks-e2e.yml")
        events = workflow.get("on", workflow.get(True))
        self.assertEqual(set(events), {"workflow_dispatch", "schedule"})
        self.assertEqual(events["schedule"], [{"cron": "43 5 * * *"}])
        text = (ROOT / ".github/workflows/aks-e2e.yml").read_text()
        self.assertFalse(events["workflow_dispatch"]["inputs"]["run_scenario"]["default"])
        self.assertIn("cleanup.py validate", text)
        self.assertNotIn("pull_request_target", text)
        self.assertNotIn("make demo", text)
        self.assertIn("needs.config.outputs.scenario == 'false'", workflow["jobs"]["validate"]["if"])

    def test_schedule_intent_reaches_cleanup_and_failure_paths(self):
        jobs = self.workflow("aks-e2e.yml")["jobs"]
        intent = "github.event_name == 'schedule' || inputs.run_scenario"
        config = next(s for s in jobs["config"]["steps"] if s.get("id") == "config")
        self.assertEqual(config["env"]["RUN_SCENARIO"], "${{ " + intent + " }}")
        self.assertIn("github.event_name == 'workflow_dispatch' && inputs.run_scenario", jobs["config"]["if"])
        for name in ("teardown", "finalize", "report"):
            condition = jobs[name]["if"]
            self.assertIn("always()", condition)
            self.assertIn("(" + intent + ")", condition)
            self.assertNotIn("needs.config.outputs", condition)
        self.assertIn("needs.create.outputs.started != ''", jobs["teardown"]["if"])
        for name in ("preflight", "create", "wait", "federate", "scenario"):
            self.assertIn("needs.config.outputs.scenario == 'true'", jobs[name]["if"])
        self.assertEqual(jobs["scenario"]["timeout-minutes"], 30)
        self.assertEqual(jobs["teardown"]["timeout-minutes"], 10)
        exercise = next(s["run"] for s in jobs["scenario"]["steps"] if s.get("id") == "exercise")
        self.assertIn("AKS_STARTED_EPOCH + 1800", exercise)
        self.assertIn("AKS_STARTED_EPOCH + 2700", exercise)

    def test_scheduled_and_manual_scenarios_keep_operator_boolean_gates(self):
        import itertools
        import tempfile
        jobs = self.workflow("aks-e2e.yml")["jobs"]
        config = next(s for s in jobs["config"]["steps"] if s.get("id") == "config")
        # Execute the actual shell gate; fake only its local configuration reader.
        script = "python3() { printf 'configured=true\\n'; }\n" + config["run"]
        keys = ("AKS_BOOTSTRAP_ENABLED", "AKS_SCENARIO_ENABLED", "AKS_BUDGET_CONFIRMED")
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "outputs"
            for event, requested in (("schedule", False), ("workflow_dispatch", True), ("workflow_dispatch", False)):
                intent = event == "schedule" or requested
                for values in itertools.product(("", "false", "true"), repeat=3):
                    with self.subTest(event=event, requested=requested, values=values):
                        output.write_text("")
                        env = dict(zip(keys, values), GITHUB_OUTPUT=str(output), RUN_SCENARIO=str(intent).lower())
                        result = subprocess.run(["bash", "-euo", "pipefail", "-c", script], env=env,
                                                capture_output=True, text=True, check=False)
                        allowed = not intent or all(v == "true" for v in values)
                        self.assertEqual(result.returncode == 0, allowed)
                        lines = output.read_text().splitlines()
                        if allowed:
                            self.assertIn("scenario=" + str(intent).lower(), lines)
                        else:
                            self.assertFalse(any(line.startswith("scenario=") for line in lines))

    def test_finalize_requires_prepaid_inputs_only_for_actor_variant(self):
        script = self.workflow("aks-e2e.yml")["jobs"]["finalize"]["steps"][0]["run"]
        base = {key + "_RESULT": "success" for key in ("CONFIG", "PREFLIGHT", "CREATE", "WAIT", "FEDERATE", "SCENARIO", "TEARDOWN")}
        for variant, inputs, allowed in (("no-sandbox", "skipped", True), ("substrate-gvisor", "skipped", False), ("substrate-gvisor", "failure", False), ("substrate-gvisor", "success", True)):
            with self.subTest(variant=variant, inputs=inputs):
                result = subprocess.run(["bash", "-euo", "pipefail", "-c", script], env=dict(base, VARIANT=variant, INPUTS_RESULT=inputs), capture_output=True, check=False)
                self.assertEqual(result.returncode == 0, allowed)

    def test_finalize_preserves_scheduled_config_failure_and_skips(self):
        job = self.workflow("aks-e2e.yml")["jobs"]["finalize"]
        script = job["steps"][0]["run"]
        keys = ("CONFIG", "PREFLIGHT", "CREATE", "WAIT", "FEDERATE", "SCENARIO", "TEARDOWN")
        for config in ("failure", "skipped", "cancelled"):
            env = {key + "_RESULT": "skipped" for key in keys}
            env["CONFIG_RESULT"] = config
            with self.subTest(config=config):
                result = subprocess.run(["bash", "-euo", "pipefail", "-c", script], env=env, capture_output=True, check=False)
                self.assertNotEqual(result.returncode, 0)

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
            expected_permissions = {"contents": "read", "id-token": "write", **({"actions": "read"} if name == "scenario" else {})}
            self.assertEqual(job["permissions"], expected_permissions)
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
