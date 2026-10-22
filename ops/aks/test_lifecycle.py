"""Offline lifecycle checks: fake Azure boundary, real configuration and budgets."""
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import cleanup
from test_cleanup import ENV, GUID, NOW, Cloud, cluster, fic, tags

try:
    import lifecycle
except ImportError:
    lifecycle = None

ROOT = Path(__file__).resolve().parents[2]
PIN = "sha256:" + "a" * 64
FIXTURE = "sha256:" + "b" * 64
HELPER = "ghcr.io/azure/aks-durable-agents/backup-helper@sha256:" + "c" * 64
MANIFEST = {"version": 1, "sourceCommit": "d" * 40, "images": {
    "host": {"repository": "ghcr.io/azure/aks-durable-agents/host", "digest": PIN},
    "harness": {"repository": "ghcr.io/azure/aks-durable-agents/session-fixture", "digest": FIXTURE}}}
RECEIPT = {"version": 1, "sourceCommit": "d" * 40, "hostDigest": PIN, "image": HELPER}

# Selected Azure CLI 2.91.0 response rows; no account or resource identifiers.
AZURE_VERSIONS = {"values": [{
    "capabilities": {"supportPlan": ["KubernetesOfficial", "AKSLongTermSupport"]},
    "isDefault": None, "isPreview": None,
    "patchVersions": {"1.37.0": {"upgrades": []}}, "version": "1.37"}]}
AZURE_QUOTA: list[dict[str, object]] = [
    {"currentValue": "0", "limit": "10", "localName": "Total Regional vCPUs",
     "name": {"localizedValue": "Total Regional vCPUs", "value": "cores"}, "unit": "Count"},
    {"currentValue": "0", "limit": "10", "localName": "Standard DSv4 Family vCPUs",
     "name": {"localizedValue": "Standard DSv4 Family vCPUs", "value": "standardDSv4Family"}, "unit": "Count"}]


def environment():
    return dict(ENV, AKS_SCENARIO_ENABLED="true", AKS_BUDGET_CONFIRMED="true",
                GITHUB_RUN_ID="123", GITHUB_RUN_ATTEMPT="1", MODEL_ENDPOINT="https://example.openai.azure.com/openai/v1/",
                MODEL_DEPLOYMENT="verified-mini", MODEL_PRICE_INPUT="825000", MODEL_PRICE_OUTPUT="4950000",
                MODEL_PRICE_EXTRA="0", MODEL_PRICE_SOURCE="https://azure.microsoft.com/pricing/", MODEL_PRICE_AS_OF="2026-10-21",
                BACKUP_HELPER_IMAGE=HELPER, BACKUP_HELPER_RECEIPT=json.dumps(RECEIPT), PUBLISHED_IMAGES=json.dumps(MANIFEST))


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(lifecycle, "real lifecycle implementation is missing")
        self.env = environment()
        self.images = {k: v["repository"] + "@" + v["digest"] for k, v in MANIFEST["images"].items()}

    def config(self, env=None):
        return lifecycle.configuration(env or self.env, self.images, today=NOW.date())

    def test_tools_branch_installs_reports_findings_but_blocks_integrity_failures(self):
        import contextlib
        import io
        for status in ("clean", "findings", "scan-error", "integrity-error"):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as temp:
                clock, installed = mock.Mock(), []
                clock.remaining.return_value = 12
                tools = Path(temp) / "aks-nightly-tools"
                def install(args, *, timeout):
                    self.assertEqual(args, ["bash", str(ROOT / "ops/aks/tools.sh")])
                    self.assertEqual(timeout, 12)
                    installed.append(True)
                def audit(directory, remaining):
                    self.assertEqual(installed, [True])
                    self.assertEqual(directory, tools)
                    self.assertIs(remaining, clock.remaining)
                    self.assertEqual(os.environ["PATH"].split(os.pathsep)[0], str(tools))
                    return [lifecycle.tool_audit.decision("kubectl", status)]
                with (mock.patch.dict(os.environ, {"RUNNER_TEMP": temp, "AKS_STARTED_EPOCH": "1000"}),
                      mock.patch.object(lifecycle, "configuration", return_value=self.config()),
                      mock.patch.object(lifecycle, "rendered_images", return_value=self.images),
                      mock.patch.object(lifecycle, "Deadline", return_value=clock),
                      mock.patch.object(lifecycle, "Azure") as cloud,
                      mock.patch.object(lifecycle, "command", side_effect=install),
                      mock.patch.object(lifecycle.tool_audit, "audit_tools", side_effect=audit),
                      contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO())):
                    self.assertEqual(lifecycle.main(["tools"]), 1 if status == "integrity-error" else 0)
                    report = Path(temp) / "aks-tool-report"
                    self.assertEqual(json.loads((report / "report.json").read_text())[0]["status"], status)
                    cloud.return_value.run.assert_not_called()

    def test_tools_branch_budget_exhaustion_stops_before_second_scan(self):
        import contextlib
        import io
        clock = mock.Mock()
        clock.remaining.side_effect = [12, 3, cleanup.CloudError("expired")]
        with (mock.patch.dict(os.environ, {"RUNNER_TEMP": "/private/tools", "AKS_STARTED_EPOCH": "1000"}),
              mock.patch.object(lifecycle, "configuration", return_value=self.config()),
              mock.patch.object(lifecycle, "rendered_images", return_value=self.images),
              mock.patch.object(lifecycle, "Deadline", return_value=clock),
              mock.patch.object(lifecycle, "Azure"), mock.patch.object(lifecycle, "command"),
              mock.patch.object(lifecycle.tool_audit, "scan_tool", return_value={"status": "clean"}) as scan,
              contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO())):
            self.assertEqual(lifecycle.main(["tools"]), 1)
        self.assertEqual(scan.call_count, 1)
        self.assertEqual(scan.call_args.kwargs["timeout"], 3)

    def test_opt_in_budget_and_bootstrap_all_required(self):
        for key in ("AKS_SCENARIO_ENABLED", "AKS_BUDGET_CONFIRMED", "AKS_BOOTSTRAP_ENABLED"):
            for value in ("", "false", "TRUE"):
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    self.config(dict(self.env, **{key: value}))
        self.assertEqual(self.config()["GITHUB_RUN_ID"], "123")

    def test_model_boundary_prices_dates_and_reservation(self):
        for key, value in (("MODEL_ENDPOINT", "http://example.openai.azure.com/"),
                           ("MODEL_ENDPOINT", "https://user:pass@example.openai.azure.com/"),
                           ("MODEL_ENDPOINT", "https://example.openai.azure.com/openai/v1/?token=x"),
                           ("MODEL_PRICE_INPUT", "0"), ("MODEL_PRICE_OUTPUT", "1000000000000000000"),
                           ("MODEL_PRICE_EXTRA", "1"), ("MODEL_PRICE_AS_OF", "2026-10-22"),
                           ("MODEL_PRICE_AS_OF", "2026-01-01"), ("GITHUB_RUN_ATTEMPT", "0")):
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.config(dict(self.env, **{key: value}))

    def test_publication_binds_both_pins_and_same_source(self):
        self.config()
        bad_images = dict(self.images, harness=self.images["harness"].replace("b" * 64, "e" * 64))
        with self.assertRaises(ValueError):
            lifecycle.configuration(self.env, bad_images, today=NOW.date())
        receipt = dict(RECEIPT, sourceCommit="e" * 40)
        with self.assertRaises(ValueError):
            self.config(dict(self.env, BACKUP_HELPER_RECEIPT=json.dumps(receipt)))
        with self.assertRaises(ValueError):
            self.config(dict(self.env, PUBLISHED_IMAGES='{"version":1,"version":1}'))

    def test_immutable_budget_queue_delay_and_cleanup_reserve(self):
        clock = lifecycle.Deadline(1000, now=lambda: 1000, monotonic=lambda: 0)
        self.assertEqual(clock.remaining(), 1800)
        self.assertEqual(clock.remaining(cleanup=True), 2700)
        delayed = lifecycle.Deadline(1000, now=lambda: 2801, monotonic=lambda: 0)
        with self.assertRaises(cleanup.CloudError):
            delayed.remaining()
        self.assertEqual(delayed.remaining(cleanup=True), 899)
        with self.assertRaises(ValueError):
            lifecycle.Deadline(1001, now=lambda: 1000)

    def test_wall_clock_rollback_cannot_extend_authority(self):
        clock = lifecycle.Deadline(1000, now=mock.Mock(side_effect=[1000, 900]),
                                   monotonic=mock.Mock(side_effect=[0, 400]))
        self.assertEqual(clock.remaining(), 1400)

    def test_versions_require_stable_exact_patch_and_quota_both_limits(self):
        lifecycle.check_versions({"values": [{"version": "1.37", "isPreview": False, "patchVersions": {"1.37.0": {}}}]})
        for value in ({"values": []}, {"values": [{"version": "1.37.0", "isPreview": True}]}, None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                lifecycle.check_versions(value)
        usages = [{"name": {"value": n}, "currentValue": 4, "limit": 10} for n in ("cores", "standardDSv4Family")]
        lifecycle.check_quota(usages)
        usages[1]["limit"] = 9
        with self.assertRaises(ValueError):
            lifecycle.check_quota(usages)

    def test_versions_accept_cli_nullable_ga_flag(self):
        lifecycle.check_versions(AZURE_VERSIONS)
        row = dict(AZURE_VERSIONS["values"][0])
        del row["isPreview"]  # The corresponding raw Azure REST response omits it.
        lifecycle.check_versions({"values": [row]})

    def test_nullable_version_metadata_still_requires_nonpreview_exact_patch(self):
        row = AZURE_VERSIONS["values"][0]
        for flag in (True, 0, 1, "false", "true", [], {}):
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                lifecycle.check_versions({"values": [dict(row, isPreview=flag)]})
        with self.assertRaises(ValueError):
            lifecycle.check_versions({"values": [dict(row, patchVersions={"1.37.1": {}})]})

    def test_quota_accepts_cli_numeric_strings_and_mixed_integer_counts(self):
        lifecycle.check_quota(AZURE_QUOTA)
        lifecycle.check_quota([dict(row, currentValue=0) for row in AZURE_QUOTA])
        lifecycle.check_quota([dict(row, limit=10) for row in AZURE_QUOTA])
        lifecycle.check_quota([dict(row, currentValue="4") for row in AZURE_QUOTA])

    def test_quota_numeric_strings_preserve_both_limits_and_unique_rows(self):
        for index in (0, 1):
            rows = [dict(row) for row in AZURE_QUOTA]
            rows[index]["currentValue"] = "5"
            with self.subTest(index=index), self.assertRaises(ValueError):
                lifecycle.check_quota(rows)
        for rows in (AZURE_QUOTA[:1], AZURE_QUOTA + AZURE_QUOTA[:1]):
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                lifecycle.check_quota(rows)

    def test_quota_rejects_noncanonical_or_noninteger_counts(self):
        invalid = {
            "currentValue": (None, True, False, -1, 0.0, "", "-1", "+0", "0.0", "0e0",
                             "00", " 0", "0 ", "0\n", "０", [], {}),
            "limit": (None, True, False, -1, 20.0, "", "-20", "+20", "20.0", "2e1",
                      "020", " 20", "20 ", "20\n", "２０", [], {}),
        }
        for field, values in invalid.items():
            for value in values:
                rows = [dict(row, limit="20") for row in AZURE_QUOTA]
                rows[0][field] = value
                with self.subTest(field=field, value=value), self.assertRaisesRegex(ValueError, "invalid quota count"):
                    lifecycle.check_quota(rows)

    def test_create_is_async_bounded_fixed_size_and_tagged_before_call(self):
        config = self.config()
        cloud = mock.Mock()
        cloud.cluster.return_value = None
        cloud.fics.return_value = []
        cloud.node_group_exists.return_value = False
        cloud.account.return_value = {"id": GUID, "tenantId": GUID}
        cloud.group.return_value = {"tags": tags()}
        lifecycle.create(config, cloud, lifecycle.Deadline(NOW.timestamp(), now=lambda: NOW.timestamp()))
        args = cloud.run.call_args.args
        self.assertEqual(args[:2], ("aks", "create"))
        for item in ("--no-wait", "--no-ssh-key", "--disable-local-accounts", "--enable-azure-rbac",
                     "--enable-workload-identity", "--enable-oidc-issuer", "ada-run-id=123", "ada-run-attempt=1"):
            self.assertIn(item, args)
        self.assertEqual(args[args.index("--node-count") + 1], "2")
        self.assertEqual(args[args.index("--kubernetes-version") + 1], "1.37.0")
        self.assertNotIn("--enable-cluster-autoscaler", args)
        self.assertEqual(args[args.index("--auto-upgrade-channel") + 1], "none")
        self.assertEqual(args[args.index("--node-os-upgrade-channel") + 1], "None")

    def test_create_refuses_any_existing_cluster_fic_or_node_group(self):
        for method, result in (("cluster", cluster()), ("fics", [fic()]), ("node_group_exists", True)):
            cloud = mock.Mock()
            cloud.cluster.return_value, cloud.fics.return_value, cloud.node_group_exists.return_value = None, [], False
            cloud.account.return_value = {"id": GUID, "tenantId": GUID}
            cloud.group.return_value = {"tags": tags()}
            getattr(cloud, method).return_value = result
            with self.subTest(method=method), self.assertRaises(ValueError):
                lifecycle.create(self.config(), cloud, lifecycle.Deadline(NOW.timestamp(), now=lambda: NOW.timestamp()))
            cloud.run.assert_not_called()

    def test_timeout_kills_descendant_process_group(self):
        with tempfile.TemporaryDirectory() as work:
            pidfile = Path(work) / "child.pid"
            program = ("import subprocess,time; p=subprocess.Popen(['sleep','60']); "
                       f"open({str(pidfile)!r},'w').write(str(p.pid)); time.sleep(60)")
            with self.assertRaises(cleanup.CloudError):
                lifecycle.command([sys.executable, "-c", program], timeout=0.3)
            pid = int(pidfile.read_text())
            stat = Path(f"/proc/{pid}/stat")
            self.assertTrue(not stat.exists() or stat.read_text().split()[2] == "Z", "descendant is still running")

    def test_same_run_teardown_overrides_expiry_but_never_other_lineage(self):
        for run in (("123", "1"), ("999", "1"), ("123", "2")):
            cloud = Cloud()
            cloud.item["tags"] = tags(NOW.replace(hour=1))
            if run == ("123", "1"):
                result = cleanup.cleanup(cleanup.configuration(ENV), cloud, NOW, apply=True, owned_run=run)
                self.assertEqual(result["status"], "removed")
                self.assertEqual(cloud.deleted, ["fic", "cluster"])
            else:
                with self.assertRaises(ValueError):
                    cleanup.cleanup(cleanup.configuration(ENV), cloud, NOW, apply=True, owned_run=run)
                self.assertEqual(cloud.deleted, [])

    def test_default_sweep_does_not_gain_same_run_override(self):
        cloud = Cloud()
        cloud.item["tags"] = tags(NOW.replace(hour=1))
        self.assertEqual(cleanup.cleanup(cleanup.configuration(ENV), cloud, NOW, apply=True)["status"], "pending-unexpired")
        self.assertEqual(cloud.deleted, [])

    def test_preflight_checks_providers_versions_quota_and_public_images(self):
        cloud = mock.Mock()
        cloud.cluster.return_value, cloud.fics.return_value, cloud.node_group_exists.return_value = None, [], False
        cloud.account.return_value = {"id": GUID, "tenantId": GUID}
        cloud.group.return_value = {"tags": tags()}
        usages = [{"name": {"value": n}, "currentValue": 0, "limit": 10} for n in ("cores", "standardDSv4Family")]
        cloud.run.side_effect = ["Registered"] * 5 + [{"values": [{"version": "1.37.0"}]}, usages]
        with mock.patch.object(lifecycle, "rendered_images", return_value=self.images), mock.patch.object(lifecycle, "command") as execute:
            lifecycle.preflight(self.config(), cloud)
        self.assertEqual(execute.call_count, 3)
        for call in execute.call_args_list:
            self.assertEqual(call.args[0][:3], ["docker", "manifest", "inspect"])
            self.assertIn("@sha256:", call.args[0][-1])
        cloud.run.side_effect = ["NotRegistered"]
        with mock.patch.object(lifecycle, "command") as execute, self.assertRaises(ValueError):
            lifecycle.preflight(self.config(), cloud)
        execute.assert_not_called()

    def test_federation_binds_current_run_and_confirms_readback(self):
        cloud = Cloud()
        cloud.item["provisioningState"] = "Succeeded"
        cloud.credentials = []
        def create_fic(*args, **kwargs):
            self.assertEqual(args[:3], ("identity", "federated-credential", "create"))
            cloud.credentials = [fic()]
        cloud.run = mock.Mock(side_effect=create_fic)
        lifecycle.federate(self.config(), cloud)
        self.assertEqual(cloud.credentials, [fic()])
        self.assertEqual(cloud.run.call_count, 1)
        lifecycle.federate(self.config(), cloud)  # Matching same-run trust is idempotent.
        self.assertEqual(cloud.run.call_count, 1)
        cloud.credentials[0]["subject"] = "system:serviceaccount:other:host"
        with self.assertRaises(ValueError):
            lifecycle.federate(self.config(), cloud)
        self.assertEqual(cloud.run.call_count, 1)

    def test_federation_missing_readback_and_other_run_never_pass(self):
        cloud = Cloud()
        cloud.item["provisioningState"] = "Succeeded"
        cloud.credentials = []
        cloud.run = mock.Mock()
        with self.assertRaises(ValueError):
            lifecycle.federate(self.config(), cloud)
        self.assertEqual(cloud.run.call_count, 1)
        cloud.run.reset_mock()
        cloud.item["tags"]["ada-run-id"] = "999"
        with self.assertRaises(ValueError):
            lifecycle.federate(self.config(), cloud)
        cloud.run.assert_not_called()

    def test_partial_create_failure_still_allows_only_current_run_teardown(self):
        cloud = Cloud()
        cloud.item.update(issuer=None, provisioningState="Failed")
        cloud.item["tags"] = tags(NOW.replace(hour=1))
        cloud.credentials = []
        clock = lifecycle.Deadline(NOW.timestamp(), now=lambda: NOW.timestamp())
        self.assertEqual(lifecycle.teardown(self.config(), cloud, clock)["status"], "removed")
        self.assertEqual(cloud.deleted, ["cluster"])

    def test_failed_delete_attempts_owned_stop_but_still_fails(self):
        cloud = Cloud()
        cloud.item["provisioningState"] = "Succeeded"
        def failed_delete():
            raise cleanup.CloudError("unknown outcome")
        cloud.delete_cluster = failed_delete
        cloud.run = mock.Mock()
        clock = lifecycle.Deadline(NOW.timestamp(), now=lambda: NOW.timestamp())
        with self.assertRaises(cleanup.CloudError):
            lifecycle.teardown(self.config(), cloud, clock)
        self.assertEqual(cloud.run.call_args.args[:2], ("aks", "stop"))
        self.assertIn("--no-wait", cloud.run.call_args.args)
        self.assertNotIn("group", cloud.run.call_args.args)

    def test_mask_is_metadata_only_and_does_not_mask_boolean_literals(self):
        import contextlib
        import io
        with tempfile.TemporaryDirectory() as work:
            output = Path(work) / "github-env"
            output.touch(mode=0o600)
            env = dict(ENV, RUNNER_TEMP=work, GITHUB_ENV=str(output))
            with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(lifecycle, "Azure") as azure:
                with contextlib.redirect_stdout(io.StringIO()) as console:
                    self.assertEqual(lifecycle.main(["mask"]), 0)
            azure.assert_not_called()
            self.assertNotIn("::add-mask::true", console.getvalue())
            self.assertEqual((Path(work) / "aks-azure").stat().st_mode & 0o777, 0o700)
            self.assertIn("AZURE_CONFIG_DIR=", output.read_text())

    def test_cancel_signal_kills_command_descendants(self):
        with tempfile.TemporaryDirectory() as work:
            pidfile = Path(work) / "child.pid"
            child = f"import time,os; open({str(pidfile)!r},'w').write(str(os.getpid())); time.sleep(60)"
            wrapper = (f"import sys,signal; sys.path.insert(0,{str(ROOT / 'ops/aks')!r}); import lifecycle; "
                       "signal.signal(signal.SIGTERM,lifecycle.interrupt); "
                       f"lifecycle.command([sys.executable,'-c',{child!r}],timeout=20)")
            process = subprocess.Popen([sys.executable, "-c", wrapper], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                deadline = time.monotonic() + 3
                while not pidfile.exists() and time.monotonic() < deadline:
                    if process.poll() is not None:
                        self.fail("signal test wrapper exited before starting child")
                    time.sleep(0.02)
                self.assertTrue(pidfile.exists())
                process.send_signal(signal.SIGTERM)
                process.wait(timeout=3)
                pid = int(pidfile.read_text())
                path = Path(f"/proc/{pid}/stat")
                self.assertTrue(not path.exists() or path.read_text().split()[2] == "Z")
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=3)


if __name__ == "__main__":
    unittest.main()
