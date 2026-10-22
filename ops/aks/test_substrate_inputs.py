"""Pre-paid input selection and capability validation; no external calls."""
import copy
import unittest

import substrate_inputs as p


class InputGateTests(unittest.TestCase):
    def test_schedule_and_default_stay_no_sandbox(self):
        self.assertEqual(p.selection({"EVENT_NAME": "schedule"}), "no-sandbox")
        self.assertEqual(p.selection({"EVENT_NAME": "workflow_dispatch"}), "no-sandbox")
        self.assertEqual(p.selection({"EVENT_NAME": "schedule", "VARIANT": "substrate-gvisor"}), "no-sandbox")

    def test_actor_requires_explicit_manual_run_enablement_and_both_run_ids(self):
        good = {"EVENT_NAME": "workflow_dispatch", "VARIANT": "substrate-gvisor", "RUN_SCENARIO": "true", "AKS_SUBSTRATE_ENABLED": "true", "PUBLISH_RUN_ID": "123", "VERIFY_RUN_ID": "456"}
        self.assertEqual(p.selection(good), "substrate-gvisor")
        for change in ({"EVENT_NAME": "push"}, {"RUN_SCENARIO": "false"}, {"AKS_SUBSTRATE_ENABLED": "false"}, {"PUBLISH_RUN_ID": ""}, {"VERIFY_RUN_ID": "0"}, {"VERIFY_RUN_ID": "123;echo bad"}, {"VARIANT": "unknown"}):
            with self.subTest(change=change), self.assertRaises(ValueError): p.selection(dict(good, **change))

    def test_verified_artifact_run_is_successful_canonical_main_workflow(self):
        run = {"id": 456, "status": "completed", "conclusion": "success", "head_branch": "main", "event": "workflow_run", "path": ".github/workflows/image-pins.yml", "repository": {"full_name": "Azure/aks-durable-agents"}, "head_repository": {"full_name": "Azure/aks-durable-agents"}}
        p.verified_run(run, "456")
        for key, value in (("id", 123), ("status", "queued"), ("conclusion", "failure"), ("head_branch", "feature"), ("event", "pull_request"), ("path", ".github/workflows/untrusted.yml"), ("head_repository", {"full_name": "untrusted/fork"})):
            with self.subTest(key=key), self.assertRaises(ValueError): p.verified_run(dict(run, **{key: value}), "456")

    def test_capability_probe_overrides_image_entrypoint_once(self):
        ref = "registry.example/fixture@sha256:" + "a" * 64
        command = p.capability_command(ref)
        self.assertLess(command.index("--entrypoint"), command.index(ref))
        self.assertEqual(command[command.index(ref) + 1:], ["actor-harness", "--check"])
        self.assertIn("--network=none", command)

    def test_selected_digest_must_own_actor_entrypoint_not_just_exist(self):
        good = {"version": 1, "mode": "actor-v2", "harness": "release-notes", "protocol": "harnesswire", "port": 80, "resumability": "STATELESS_REPLAY", "descriptor": "release-v2-real-model-" + "a" * 64}
        p.actor_capability(good)
        for key, value in (("version", True), ("mode", "legacy"), ("port", 9000), ("resumability", "MEMORY"), ("descriptor", "old-image"), ("extra", "untrusted")):
            changed = copy.deepcopy(good)
            changed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): p.actor_capability(changed)


if __name__ == "__main__": unittest.main()
