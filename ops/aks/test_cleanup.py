"""Owned-resource cleanup has no Azure dependency in these tests."""
import copy
from datetime import datetime, timedelta, timezone
import contextlib
import io
import json
import subprocess
import unittest
from unittest import mock

import cleanup

NOW = datetime(2026, 10, 21, tzinfo=timezone.utc)
GUID = "00000000-0000-4000-8000-000000000001"
ENV = {"AKS_BOOTSTRAP_ENABLED": "true", "AZURE_CLIENT_ID": GUID,
       "AZURE_TENANT_ID": GUID, "AZURE_SUBSCRIPTION_ID": GUID,
       "AKS_RESOURCE_GROUP": "nightly-test", "AKS_CLUSTER_NAME": "nightly-test",
       "AKS_NODE_RESOURCE_GROUP": "nightly-nodes", "AKS_IDENTITY_RESOURCE_GROUP": "nightly-identities",
       "AKS_MODEL_IDENTITY_NAME": "nightly-model"}
ISSUER = f"https://westus3.oic.prod-aks.azure.com/{GUID}/{GUID}/"


def tags(expiry=None):
    return {"ada-repository-id": "1426100286", "ada-purpose": "nightly-aks",
            "ada-run-id": "123", "ada-run-attempt": "1",
            "ada-expires-at": (expiry or NOW-timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")}


def cluster():
    return {"id": f"/subscriptions/{GUID}/resourceGroups/nightly-test/providers/Microsoft.ContainerService/managedClusters/nightly-test",
            "name": "nightly-test", "tags": tags(), "nodeResourceGroup": "nightly-nodes", "issuer": ISSUER}


def fic():
    return {"name": "nightly-host", "issuer": ISSUER, "subject": cleanup.HOST_SUBJECT,
            "audiences": ["api://AzureADTokenExchange"]}


class Cloud:
    def __init__(self, present=True):
        self.item = cluster() if present else None
        self.credentials = [fic()] if present else []
        self.deleted = []
        self.nodes = False
        self.linger = False
        self.change = False
        self.reads = 0

    def account(self):
        return {"id": GUID, "tenantId": GUID}

    def group(self):
        return {"tags": tags()}

    def cluster(self):
        return copy.deepcopy(self.item)

    def fics(self):
        self.reads += 1
        if self.change and self.reads > 1:
            self.credentials[0]["issuer"] = ISSUER.replace("westus3", "eastus2")
        return copy.deepcopy(self.credentials)

    def delete_cluster(self):
        self.deleted.append("cluster")
        if not self.linger:
            self.item = None

    def delete_fic(self):
        self.deleted.append("fic")
        self.credentials = []

    def node_group_exists(self):
        return self.nodes


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.config = cleanup.configuration(ENV)

    def run_cleanup(self, cloud, apply=False, **kw):
        return cleanup.cleanup(self.config, cloud, NOW, apply=apply, **kw)

    def test_unconfigured_and_partial_config(self):
        self.assertIsNone(cleanup.configuration({}))
        with self.assertRaises(ValueError):
            cleanup.configuration({"AKS_BOOTSTRAP_ENABLED": "true"})
        for key in ("AZURE_SUBSCRIPTION_ID", "AZURE_CLIENT_ID", "AKS_CLUSTER_NAME"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                cleanup.configuration(dict(ENV, **{key: "$(malicious)"}))

    def test_disabled_even_with_values_does_not_enable_cloud(self):
        self.assertIsNone(cleanup.configuration(dict(ENV, AKS_BOOTSTRAP_ENABLED="false")))
        with self.assertRaises(ValueError):
            cleanup.configuration(dict(ENV, AKS_BOOTSTRAP_ENABLED="TRUE"))

    def test_absent_is_clean_no_writes(self):
        cloud = Cloud(False)
        self.assertEqual(self.run_cleanup(cloud, True)["status"], "absent")
        self.assertEqual(cloud.deleted, [])

    def test_default_is_dry_run_and_does_not_write(self):
        cloud = Cloud()
        self.assertEqual(self.run_cleanup(cloud)["status"], "would-delete")
        self.assertEqual(cloud.deleted, [])

    def test_expired_owned_cluster_then_fic_removed(self):
        cloud = Cloud()
        result = self.run_cleanup(cloud, True)
        self.assertEqual(result["status"], "removed")
        self.assertEqual(cloud.deleted, ["fic", "cluster"])
        self.assertEqual(set(result), {"status", "dryRun"})

    def test_active_is_left_alone(self):
        cloud = Cloud()
        future = NOW+timedelta(minutes=30)
        cloud.item["tags"] = tags(future)
        self.assertEqual(self.run_cleanup(cloud, True)["status"], "pending-unexpired")
        self.assertEqual(cloud.deleted, [])

    def test_unowned_bad_expiry_or_target_is_never_deleted(self):
        changes = [("tags", {}), ("tags", dict(tags(), **{"ada-expires-at": "tomorrow"})),
                   ("name", "shared"), ("id", "/another/resource"), ("nodeResourceGroup", "shared-nodes"),
                   ("issuer", "https://attacker.example/")]
        for key, value in changes:
            cloud = Cloud()
            cloud.item[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.run_cleanup(cloud, True)
            self.assertEqual(cloud.deleted, [])

    def test_rg_or_account_mismatch_fails_before_mutation(self):
        for method, value in [("group", {"tags": {}}), ("account", {"id": "wrong", "tenantId": GUID})]:
            cloud = Cloud()
            setattr(cloud, method, lambda: value)
            with self.subTest(method=method), self.assertRaises(ValueError):
                self.run_cleanup(cloud, True)
            self.assertEqual(cloud.deleted, [])

    def test_unexpected_fics_refused_before_any_delete(self):
        for key, value in [("name", "other"), ("subject", "system:serviceaccount:other:host"),
                           ("issuer", "https://attacker.example/"),
                           ("audiences", ["other"])]:
            cloud = Cloud()
            cloud.credentials[0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.run_cleanup(cloud, True)
            self.assertEqual(cloud.deleted, [])
        cloud = Cloud()
        cloud.credentials.append(fic())
        with self.assertRaises(ValueError):
            self.run_cleanup(cloud, True)

    def test_orphan_fic_has_no_expiry_proof_and_is_never_deleted(self):
        for apply in (False, True):
            cloud = Cloud(False)
            cloud.credentials = [fic()]
            with self.subTest(apply=apply), self.assertRaises(ValueError):
                self.run_cleanup(cloud, apply)
            self.assertEqual(cloud.deleted, [])

    def test_late_delete_has_already_removed_fic_and_next_sweep_is_clean(self):
        cloud = Cloud()
        cloud.linger = True
        ticks = iter([0, 0, 5])
        result = self.run_cleanup(cloud, True, wait_seconds=2, monotonic=lambda: next(ticks), sleep=lambda _: None)
        self.assertEqual(result["status"], "pending-deleting")
        self.assertEqual(cloud.deleted, ["fic", "cluster"])
        self.assertEqual(cloud.credentials, [])
        cloud.item = None  # Azure finishes between sweeps.
        self.assertEqual(self.run_cleanup(cloud, True)["status"], "absent")

    def test_changed_fic_is_refused_before_any_delete(self):
        cloud = Cloud()
        cloud.change = True
        with self.assertRaises(ValueError):
            self.run_cleanup(cloud, True)
        self.assertEqual(cloud.deleted, [])

    def test_orphan_node_group_is_failure_not_a_delete_target(self):
        cloud = Cloud(False)
        cloud.nodes = True
        with self.assertRaises(ValueError):
            self.run_cleanup(cloud, True)
        self.assertEqual(cloud.deleted, [])

    def test_partial_failed_creation_without_fic_is_still_owned(self):
        cloud = Cloud()
        cloud.item["issuer"] = None
        cloud.item["provisioningState"] = "Failed"
        cloud.credentials = []
        self.assertEqual(self.run_cleanup(cloud, True)["status"], "removed")
        self.assertEqual(cloud.deleted, ["cluster"])

    def test_null_ids_fail_closed(self):
        cloud = Cloud()
        cloud.item["id"] = None
        with self.assertRaises(ValueError):
            self.run_cleanup(cloud, True)
        self.assertEqual(cloud.deleted, [])

    def test_cli_never_logs_raw_azure_error_or_login_when_disabled(self):
        with mock.patch.dict(cleanup.os.environ, {}, clear=True), mock.patch.object(cleanup, "Azure") as azure:
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(cleanup.main(["cleanup", "--apply"]), 0)
            azure.assert_not_called()
            self.assertEqual(json.loads(output.getvalue())["status"], "not-configured")
        with mock.patch.dict(cleanup.os.environ, ENV, clear=True):
            with mock.patch.object(cleanup.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "token-value", "private-resource-id")):
                with contextlib.redirect_stderr(io.StringIO()) as output:
                    self.assertEqual(cleanup.main(["cleanup", "--apply"]), 1)
                self.assertEqual(json.loads(output.getvalue())["status"], "failed-closed")
                self.assertNotIn("token-value", output.getvalue())
                self.assertNotIn("private-resource-id", output.getvalue())

    def test_cloud_errors_do_not_become_missing_resources(self):
        cloud = Cloud()
        def failed():
            raise cleanup.CloudError("Azure read failed")
        cloud.cluster = failed
        with self.assertRaises(cleanup.CloudError):
            self.run_cleanup(cloud, True)
        self.assertEqual(cloud.deleted, [])


if __name__ == "__main__":
    unittest.main()
