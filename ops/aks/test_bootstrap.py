"""Offline bootstrap contracts; only the subprocess boundary is replaced."""
import contextlib
import copy
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import bootstrap as b
import bootstrap_inventory as bi

TENANT = "11111111-1111-4111-8111-111111111111"
SUB = "22222222-2222-4222-8222-222222222222"
ENV = "33333333-3333-4333-8333-333333333333"
CLIENT = "44444444-4444-4444-8444-444444444444"
APP = "55555555-5555-4555-8555-555555555555"
SP = "66666666-6666-4666-8666-666666666666"
ROOT = f"/subscriptions/{SUB}"
CONFIG: dict = {"version": 1, "environmentID": ENV,
          "azure": {"tenantID": TENANT, "subscriptionID": SUB, "configDir": "/isolated/azure-test"},
          "github": {"repository": "example/agents", "repositoryID": "12345", "ownerID": "67890"},
          "nightly": {"resourceGroup": "nightly", "identityResourceGroup": "identities", "ciIdentityName": "ci",
                      "modelIdentityName": "model", "clusterName": "test-cluster", "nodeResourceGroup": "nodes"},
          "model": {"resourceGroup": "models", "accountName": "example-model", "deploymentName": "chat",
                    "location": "westus3", "version": "2026-01-01", "sku": "GlobalStandard", "capacity": 1},
          "human": {"domain": "example.onmicrosoft.com", "apiName": "test-api", "canvasName": "test-canvas",
                    "cliName": "test-cli", "canvasRedirects": ["http://localhost:5173"]}}


def arm_id(group, kind, name):
    return ROOT + f"/resourceGroups/{group}/providers/{kind}/{name}"


def markers(component="nightly"):
    return {"ada-bootstrap-environment": ENV, "ada-repository-id": "12345", "ada-bootstrap-component": component}


class Wire:
    """Live-shaped fixtures, dispatching literal GET paths rather than adapter mocks."""
    def __init__(self, existing=True):
        self.calls = []
        self.overrides = {}
        self.existing = existing
        self.groups: list[dict] = [{"id": ROOT + "/resourceGroups/" + n, "name": n, "location": "westus3", "tags": {}}
                       for n in ("nightly", "identities", "models")] if existing else []
        self.identities: list[dict] = [{"id": arm_id("identities", "Microsoft.ManagedIdentity/userAssignedIdentities", n),
                            "name": n, "location": "westus3", "properties": {"clientId": CLIENT, "principalId": SP, "tenantId": TENANT}, "tags": {}}
                           for n in ("ci", "model")] if existing else []
        self.accounts: list[dict] = [{"id": arm_id("models", "Microsoft.CognitiveServices/accounts", "example-model"),
                          "name": "example-model", "location": "westus3", "kind": "OpenAI", "tags": {},
                          "properties": {"endpoint": "https://example-model.openai.azure.com/", "disableLocalAuth": True}}] if existing else []
        self.apps: list[dict] = [{"id": APP[:-1] + str(i), "appId": CLIENT[:-1] + str(i), "displayName": name,
                      "tags": [], "notes": "PRIVATE NOTES DO NOT PRINT", "signInAudience": "AzureADMyOrg",
                      "api": {}, "spa": {"redirectUris": ["http://localhost:5173"]}, "publicClient": {}}
                     for i, name in enumerate(("test-api", "test-canvas", "test-cli"), 1)] if existing else []
        self.sps = []
        self.providers = [{"id": ROOT + "/providers/" + name, "namespace": name, "registrationState": "Registered"}
                          for name in ("Microsoft.ManagedIdentity", "Microsoft.CognitiveServices", "Microsoft.Consumption")]
        self.variables = [{"name": k, "value": v} for k, v in {
            "AZURE_CLIENT_ID": CLIENT, "AZURE_TENANT_ID": TENANT, "AZURE_SUBSCRIPTION_ID": SUB,
            "AKS_RESOURCE_GROUP": "nightly", "AKS_CLUSTER_NAME": "test-cluster", "AKS_NODE_RESOURCE_GROUP": "nodes",
            "AKS_IDENTITY_RESOURCE_GROUP": "identities", "AKS_MODEL_IDENTITY_NAME": "model",
            "MODEL_ENDPOINT": "https://example-model.openai.azure.com/openai/v1/", "MODEL_DEPLOYMENT": "chat"}.items()]
        self.variables += [{"name": "AKS_BOOTSTRAP_ENABLED", "value": "true"},
                          {"name": "AKS_SCENARIO_ENABLED", "value": "true"},
                          {"name": "AKS_BUDGET_CONFIRMED", "value": "true"}]

    def __call__(self, args, **kwargs):
        self.calls.append((args, kwargs))
        if args[:3] == ["az", "account", "show"]:
            data = self.overrides.get("account", {"id": SUB, "tenantId": TENANT, "state": "Enabled"})
        else:
            if args[0] == "az":
                self_test = args.index("--url")
                from urllib.parse import parse_qs, urlsplit
                url = args[self_test + 1]
                parsed = urlsplit(url)
                path, query = parsed.path, parse_qs(parsed.query)
            else:
                from urllib.parse import parse_qs, urlsplit
                url = args[args.index("GET") + 1]
                parsed = urlsplit(url)
                path, query = parsed.path, parse_qs(parsed.query)
            if url in self.overrides:
                data = self.overrides[url]
            elif path in self.overrides:
                data = self.overrides[path]
            elif path == ROOT + "/resourcegroups":
                data = {"value": self.groups}
            elif path == ROOT + "/resources":
                data = {"value": self.identities + self.accounts}
            elif path.endswith("/userAssignedIdentities"):
                data = {"value": self.identities}
            elif path == ROOT + "/providers/Microsoft.CognitiveServices/accounts":
                data = {"value": self.accounts}
            elif path.endswith("/deployments"):
                data = {"value": [{"id": self.accounts[0]["id"] + "/deployments/chat", "name": "chat",
                                    "sku": {"name": "GlobalStandard", "capacity": 1},
                                    "properties": {"model": {"name": "test-model", "version": "2026-01-01"}}}]}
            elif path == ROOT + "/providers":
                data = {"value": self.providers}
            elif path.startswith(ROOT + "/"):
                data = {"value": []}
            elif path == "/v1.0/organization":
                if "$top" in query:
                    raise AssertionError("Organization supports the selected singleton metadata, not a user-style scan")
                data = {"value": [{"id": TENANT, "verifiedDomains": [{"name": "example.onmicrosoft.com", "isDefault": True, "isInitial": True, "type": "Managed", "capabilities": "Email, OfficeCommunicationsOnline"}]}]}
            elif path == "/v1.0/applications":
                data = {"value": self.apps}
            elif path == "/v1.0/servicePrincipals":
                data = {"value": self.sps}
            elif path == "/v1.0/users":
                data = {"value": [{"id": SP, "userType": "Member", "accountEnabled": True,
                                    "userPrincipalName": "PRIVATE-UPN@example.invalid"}]}
            elif path.startswith("/v1.0/"):
                data = {"value": []}
            elif path == "/repos/example/agents":
                data = {"id": 12345, "full_name": "example/agents", "owner": {"id": 67890}, "default_branch": "main"}
            elif path.endswith("/actions/oidc/customization/sub"):
                data = {"use_default": True, "use_immutable_subject": True}
            elif path == "/repos/example/agents/environments":
                data = {"total_count": 1, "environments": [{"id": 17, "name": "nightly-aks",
                        "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True}, "protection_rules": [{"id": 19, "node_id": "synthetic", "type": "branch_policy"}]}]}
            elif path.endswith("/deployment-branch-policies"):
                data = {"total_count": 1, "branch_policies": [{"id": 18, "name": "main", "type": "branch"}]}
            elif path == "/repos/example/agents/actions/variables":
                data = {"total_count": len(self.variables), "variables": self.variables}
            elif path.endswith(("/secrets", "/organization-secrets")):
                data = {"total_count": 0, "secrets": []}
            elif path.endswith("/variables"):
                data = {"total_count": 0, "variables": []}
            else:
                raise AssertionError("Unexpected request: " + url)
        if isinstance(data, Exception):
            raise data
        if isinstance(data, subprocess.CompletedProcess):
            return data
        return subprocess.CompletedProcess(args, 0, json.dumps(data), "")


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "config.json"
        self.config = copy.deepcopy(CONFIG)
        self.config["azure"]["configDir"] = self.tmp.name

    def load(self, config=None):
        self.path.write_text(json.dumps(config or self.config))
        return b.load_config(self.path)

    def run_cli(self, wire, command=None):
        self.path.write_text(json.dumps(self.config))
        out, err = io.StringIO(), io.StringIO()
        args = ([command] if command else []) + ["--config", str(self.path)]
        with mock.patch("subprocess.run", side_effect=wire), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = b.main(args)
        return code, out.getvalue(), err.getvalue()

    def test_closed_config_and_synthetic_example(self):
        self.assertEqual(self.load()["github"]["repositoryID"], "12345")
        example = json.loads(Path(__file__).with_name("bootstrap.example.json").read_text())
        example["azure"]["configDir"] = self.tmp.name
        self.assertEqual(self.load(example)["github"]["repository"], "example/agents")
        changes = [("azure", "password", "secret"), ("azure", "configDir", ".azure"), ("azure", "configDir", "/nonexistent/azure-profile"),
                   ("azure", "configDir", str(Path.home() / ".azure")), ("azure", "tenantID", "no"),
                   ("github", "repository", "https://user:pass@example.com/x"), ("github", "repositoryID", 12345),
                   ("model", "capacity", True), ("nightly", "clusterName", "--bad"),
                   ("nightly", "nodeResourceGroup", "nightly"), ("nightly", "identityResourceGroup", "models"),
                   ("nightly", "vmSize", "large"), ("human", "canvasRedirects", ["https://user:pass@example.com/"]),
                   ("human", "canvasRedirects", ["https://example.com/?token=x"])]
        for section, key, value in changes:
            bad = copy.deepcopy(self.config)
            bad[section][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.load(bad)
        del self.config["azure"]["configDir"]
        with self.assertRaises(ValueError):
            self.load()
        self.path.write_text('{"version":1,"version":1}')
        with self.assertRaises(ValueError):
            b.load_config(self.path)

    def test_mutation_arguments_rejected_without_processes(self):
        for args in (["apply"], ["destroy"], ["--apply"], ["check"], []):
            with self.subTest(args=args), mock.patch("subprocess.run") as run, contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    b.main(args)
                self.assertEqual(raised.exception.code, 2)
                run.assert_not_called()

    def test_missing_dependencies_are_advisory_not_readiness(self):
        code, out, err = self.run_cli(Wire(False))
        self.assertEqual(code, 2, err)
        result = json.loads(out)
        self.assertFalse(result["ready"])
        self.assertEqual(result["command"], "plan")
        self.assertTrue(any(d["action"] == "create" for d in result["dependencies"]))
        self.assertTrue(any(d["action"] == "blocked" for d in result["dependencies"]))
        self.assertEqual(result["owned"], [])
        self.assertEqual(set(result), {"version", "command", "ready", "coverage", "dependencies", "owned", "inventory", "summary"})
        self.assertTrue(all(v == "not-tested" for k, v in result["coverage"].items() if k != "testedScope"))
        self.assertNotIn("AZURE_CLIENT_ID", result["summary"]["repositoryVariables"])
        self.assertIn("AZURE_CLIENT_ID", result["summary"]["unresolvedVariables"])

    def test_fresh_group_absence_does_not_query_its_identity_collection(self):
        wire = Wire(False)
        path = ROOT + "/resourceGroups/identities/providers/Microsoft.ManagedIdentity/userAssignedIdentities"
        wire.overrides[path] = subprocess.CompletedProcess([], 1, "", "PRIVATE ResourceGroupNotFound")
        code, out, err = self.run_cli(wire)
        self.assertEqual(code, 2, err)
        self.assertTrue(any(d["dependency"] == "resource-group:identities" and d["action"] == "create"
                            for d in json.loads(out)["dependencies"]))
        self.assertFalse(any(path in str(args) for args, _ in wire.calls))

    def test_inherited_role_assignments_are_reference_metadata(self):
        for scope in ("/", "/providers/Microsoft.Management/managementGroups/test-root"):
            wire = Wire()
            identifier = scope.rstrip("/") + "/providers/Microsoft.Authorization/roleAssignments/" + CLIENT
            wire.overrides[ROOT + "/providers/Microsoft.Authorization/roleAssignments"] = {"value": [
                {"id": identifier, "properties": {"scope": scope, "principalId": SP}}]}
            code, out, err = self.run_cli(wire)
            self.assertEqual(code, 0, err)
            result = json.loads(out)
            self.assertEqual(result["inventory"]["assignments"][0]["scope"], scope)
            self.assertNotIn(identifier, [o["id"] for o in result["owned"]])
        wire = Wire()
        foreign = "/subscriptions/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        wire.overrides[ROOT + "/providers/Microsoft.Authorization/roleAssignments"] = {"value": [
            {"id": foreign + "/providers/Microsoft.Authorization/roleAssignments/" + CLIENT,
             "properties": {"scope": foreign, "principalId": SP}}]}
        code, out, err = self.run_cli(wire)
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("assignment target mismatch", err)

    def test_unregistered_providers_are_blockers_not_failed_or_empty_reads(self):
        wire = Wire(False)
        for provider in wire.providers:
            provider["registrationState"] = "NotRegistered"
        paths = [ROOT + "/resourceGroups/identities/providers/Microsoft.ManagedIdentity/userAssignedIdentities",
                 ROOT + "/providers/Microsoft.CognitiveServices/accounts", ROOT + "/providers/Microsoft.Consumption/budgets"]
        for path in paths:
            wire.overrides[path] = subprocess.CompletedProcess([], 1, "", "PRIVATE MissingSubscriptionRegistration")
        code, out, err = self.run_cli(wire)
        self.assertEqual(code, 2, err)
        result = json.loads(out)
        self.assertTrue(any(d["dependency"] == "provider:Microsoft.CognitiveServices" and d["action"] == "create"
                            for d in result["dependencies"]))
        self.assertIn("accounts", result["inventory"]["unavailableCollections"])
        self.assertTrue(any(d["dependency"] == "model-account" and d["action"] == "blocked"
                            for d in result["dependencies"]))
        self.assertFalse(any(path in str(args) for args, _ in wire.calls for path in paths))

    def test_unassessed_inventory_is_explicitly_not_tested(self):
        result = json.loads(self.run_cli(Wire())[1])
        for key in ("federation", "budget", "providers", "customRoles"):
            self.assertEqual(result["coverage"][key], "not-tested")

    def test_consistent_tested_scope_enabled_is_not_drift(self):
        for cmd in (None, "check"):
            wire = Wire()
            code, out, err = self.run_cli(wire, cmd)
            self.assertEqual(code, 0, err + out)
            result = json.loads(out)
            self.assertFalse(result["ready"])
            summary = result["summary"]
            self.assertEqual(summary["repositoryVariables"]["AZURE_CLIENT_ID"], CLIENT)
            self.assertEqual(summary["repositoryVariables"]["MODEL_ENDPOINT"], "https://example-model.openai.azure.com/openai/v1/")
            self.assertEqual(summary["repositoryVariables"]["AKS_BOOTSTRAP_ENABLED"], "false")
            self.assertEqual(summary["observedFlags"]["AKS_BOOTSTRAP_ENABLED"], "true")
            self.assertIn("MODEL_PRICE_INPUT", summary["unresolvedVariables"])
            self.assertNotIn("PRIVATE", out + err)
            for args, kw in wire.calls:
                self.assertTrue(kw["capture_output"])
                self.assertNotIn("shell", kw)
                if args[0] == "az":
                    self.assertEqual(args[args.index("--subscription") + 1], SUB)
                    self.assertEqual(kw["env"]["AZURE_CONFIG_DIR"], self.tmp.name)
                    self.assertTrue(args[1:3] == ["account", "show"] or args[1:4] == ["rest", "--method", "GET"])
                else:
                    self.assertEqual(args[:4], ["gh", "api", "--method", "GET"])
                    self.assertEqual(kw["env"]["GH_HOST"], "github.com")
                    self.assertIn("--hostname", args)

    def test_target_environment_name_is_case_insensitive(self):
        # GitHub treats these Unicode case variants as aliases, not distinct targets.
        from urllib.parse import quote
        for name in ("Nightly-AKS", "nightly-aKs", "nightly-akſ"):
            for command in ("plan", "check"):
                wire = Wire()
                wire.overrides["/repos/example/agents/environments"] = {"total_count": 1, "environments": [
                    {"id": 17, "name": name, "deployment_branch_policy": {
                        "protected_branches": False, "custom_branch_policies": True}, "protection_rules": []}]}
                code, out, err = self.run_cli(wire, command)
                with self.subTest(name=name, command=command):
                    self.assertEqual(code, 0, err + out)
                    self.assertFalse(any(d["dependency"] == "github:environment" and d["action"] == "create"
                                         for d in json.loads(out)["dependencies"]))
                    self.assertTrue(any("/environments/" + quote(name, safe="") + "/deployment-branch-policies" in str(args)
                                        for args, _ in wire.calls))

    def test_valid_unrelated_environment_names_are_encoded_and_inventoried(self):
        from urllib.parse import quote
        for name in ("Staging West", "preview/pr-1", "x" * 101, "x" * 255, "Préproduction", "query?part#fragment%", ".."):
            for command in ("plan", "check"):
                wire = Wire()
                wire.overrides["/repos/example/agents/environments"] = {"total_count": 2, "environments": [
                    {"id": 17, "name": "nightly-aks", "deployment_branch_policy": {
                        "protected_branches": False, "custom_branch_policies": True}, "protection_rules": []},
                    {"id": 18, "name": name, "deployment_branch_policy": None, "protection_rules": []}]}
                code, out, err = self.run_cli(wire, command)
                with self.subTest(name=name, command=command):
                    self.assertEqual(code, 0, err + out)
                    self.assertIn(name, [e["name"] for e in json.loads(out)["inventory"]["environments"]])
                    segment = "%2E%2E" if name == ".." else quote(name, safe="")
                    self.assertTrue(any("/environments/" + segment + "/secrets?" in str(args)
                                        for args, _ in wire.calls))

    def test_invalid_or_case_duplicate_environment_names_fail_closed(self):
        for name in ("", "x" * 256, "bad\nname", "Nightly-AKS"):
            wire = Wire()
            wire.overrides["/repos/example/agents/environments"] = {"total_count": 2, "environments": [
                {"id": 17, "name": "nightly-aks", "deployment_branch_policy": None, "protection_rules": []},
                {"id": 18, "name": name, "deployment_branch_policy": None, "protection_rules": []}]}
            code, out, err = self.run_cli(wire)
            self.assertEqual(code, 1)
            self.assertEqual(out, "")
            self.assertIn("environment name", err)

    def test_environment_path_encoding_does_not_relax_request_pinning(self):
        cfg = self.load()
        paths = ["/repos/example/agents/environments/preview/pr-1/secrets",
                 "/repos/example/agents/environments/../actions/secrets",
                 "/repos/example/agents/environments/Staging West/secrets",
                 "/repos/example/agents/environments/%FF/secrets",
                 "/repos/example/agents/environments/%ZZ/secrets",
                 "/repos/example/agents/environments/preview%2Fpr-1/dispatches",
                 "https://attacker.invalid/repos/example/agents/environments/preview%2Fpr-1/secrets",
                 "/repos/example/other/environments/preview%2Fpr-1/secrets"]
        with mock.patch("subprocess.run") as run:
            reader = bi.ReadOnly(cfg)
            for path in paths:
                with self.subTest(path=path), self.assertRaises(bi.InventoryError):
                    reader.get("github", path)
            run.assert_not_called()

    def test_environment_without_custom_policy_does_not_query_missing_policy_endpoint(self):
        wire = Wire()
        wire.overrides["/repos/example/agents/environments"] = {"total_count": 2, "environments": [
            {"id": 16, "name": "copilot", "deployment_branch_policy": None, "protection_rules": []},
            {"id": 17, "name": "nightly-aks", "deployment_branch_policy": {
                "protected_branches": False, "custom_branch_policies": True}, "protection_rules": []}]}
        wire.overrides["/repos/example/agents/environments/copilot/deployment-branch-policies"] = subprocess.CompletedProcess(
            [], 1, "", "PRIVATE 404: no custom branch policy")
        code, out, err = self.run_cli(wire)
        self.assertEqual(code, 0, err)
        environments = json.loads(out)["inventory"]["environments"]
        self.assertEqual(next(e["policyCount"] for e in environments if e["name"] == "copilot"), 0)
        self.assertFalse(any("/copilot/deployment-branch-policies" in str(args) for args, _ in wire.calls))

    def test_identity_mismatches_stop_inventory_and_are_sanitized(self):
        for path, data in [("account", {"id": SUB, "tenantId": APP, "state": "Enabled"}),
                           ("/v1.0/organization", {"value": [{"id": APP}]}),
                           ("/repos/example/agents", {"id": 999, "full_name": "example/agents", "owner": {"id": 67890}})]:
            wire = Wire()
            wire.overrides[path] = data
            code, out, err = self.run_cli(wire)
            self.assertEqual(code, 1)
            self.assertEqual(out, "")
            self.assertNotIn(APP, err)
            if path == "/v1.0/organization":
                self.assertFalse(any("/v1.0/applications" in str(c) for c in wire.calls))
            if path == "account":
                self.assertEqual(len(wire.calls), 1)

    def test_failure_is_never_absence_or_raw_provider_error(self):
        for failure in (subprocess.CompletedProcess([], 1, "PRIVATE stdout", "PRIVATE stderr"),
                        subprocess.TimeoutExpired("PRIVATE command", 1), OSError("PRIVATE error"),
                        subprocess.CompletedProcess([], 0, "PRIVATE invalid json", "")):
            wire = Wire()
            wire.overrides[ROOT + "/resources"] = failure
            code, out, err = self.run_cli(wire)
            self.assertEqual(code, 1)
            self.assertEqual(out, "")
            self.assertNotIn("PRIVATE", err)
            self.assertEqual(json.loads(err)["status"], "error")
            self.assertTrue(json.loads(err)["reason"].startswith("transport:"))

    def test_same_name_unowned_is_reference_not_adopted(self):
        result = json.loads(self.run_cli(Wire())[1])
        self.assertEqual(result["owned"], [])
        self.assertTrue(all(d["ownership"] == "reference" for d in result["dependencies"] if d["action"] == "noop"))

    def test_tagged_discovery_independent_of_config_and_no_child_ownership(self):
        wire = Wire()
        unrelated = {"id": arm_id("old", "Microsoft.Storage/storageAccounts", "prior"), "name": "prior", "tags": markers("shared-model")}
        wire.overrides[ROOT + "/resources"] = {"value": [unrelated], "nextLink":
            f"https://management.azure.com{ROOT}/resources?api-version=2021-04-01&$skiptoken=next"}
        wire.overrides[f"https://management.azure.com{ROOT}/resources?api-version=2021-04-01&$skiptoken=next"] = {"value": wire.identities + wire.accounts}
        wire.apps[0]["tags"] = ["ada-bootstrap-environment:" + ENV, "ada-repository-id:12345", "ada-bootstrap-component:human-identity"]
        wire.sps = [{"id": SP, "appId": wire.apps[0]["appId"], "tags": []},
                    {"id": SP[:-1] + "7", "appId": APP, "tags": wire.apps[0]["tags"]}]
        result = json.loads(self.run_cli(wire)[1])
        ids = [o["id"] for o in result["owned"]]
        self.assertIn(unrelated["id"], ids)
        self.assertIn(SP, ids)
        self.assertNotIn(SP[:-1] + "7", ids)
        self.assertNotIn("PRIVATE", json.dumps(result))
        self.assertNotIn("users", [o["kind"] for o in result["owned"]])

    def test_duplicate_or_conflicting_app_markers_block(self):
        wire = Wire()
        wire.apps[0]["tags"] = ["ada-bootstrap-environment:" + ENV, "ada-bootstrap-environment:" + ENV,
                                "ada-repository-id:12345", "ada-bootstrap-component:human-identity"]
        code, out, err = self.run_cli(wire)
        self.assertEqual(code, 2, err)
        self.assertTrue(any(d["action"] == "blocked" for d in json.loads(out)["dependencies"]))

    def test_drift_and_wrong_resource_id_do_not_fabricate_variables(self):
        wire = Wire()
        wire.identities[0]["id"] = arm_id("other", "Microsoft.ManagedIdentity/userAssignedIdentities", "ci")
        code, out, _ = self.run_cli(wire, "check")
        self.assertEqual(code, 2)
        self.assertNotIn("AZURE_CLIENT_ID", json.loads(out)["summary"]["repositoryVariables"])
        wire = Wire()
        wire.accounts[0]["properties"]["disableLocalAuth"] = False
        self.assertEqual(self.run_cli(wire, "check")[0], 2)

    def test_missing_or_mismatched_derived_variables_are_drift(self):
        for value in (None, "wrong-client"):
            wire = Wire()
            wire.variables = [i for i in wire.variables if i["name"] != "AZURE_CLIENT_ID"]
            if value is not None:
                wire.variables.append({"name": "AZURE_CLIENT_ID", "value": value})
            code, out, err = self.run_cli(wire)
            self.assertEqual(code, 2, err + out)
            self.assertTrue(any(d["dependency"] == "variable:AZURE_CLIENT_ID" and d["action"] != "noop"
                                for d in json.loads(out)["dependencies"]))

    def test_repository_variable_mapping_uses_existing_names_only(self):
        result = json.loads(self.run_cli(Wire())[1])
        summary = result["summary"]
        expected = {"AZURE_CLIENT_ID", "AZURE_TENANT_ID", "AZURE_SUBSCRIPTION_ID", "AKS_RESOURCE_GROUP", "AKS_CLUSTER_NAME",
                    "AKS_NODE_RESOURCE_GROUP", "AKS_IDENTITY_RESOURCE_GROUP", "AKS_MODEL_IDENTITY_NAME", "AKS_BOOTSTRAP_ENABLED",
                    "AKS_SCENARIO_ENABLED", "AKS_BUDGET_CONFIRMED", "MODEL_ENDPOINT", "MODEL_DEPLOYMENT", "MODEL_PRICE_INPUT",
                    "MODEL_PRICE_OUTPUT", "MODEL_PRICE_EXTRA", "MODEL_PRICE_SOURCE", "MODEL_PRICE_AS_OF", "BACKUP_HELPER_IMAGE",
                    "BACKUP_HELPER_RECEIPT", "PUBLISHED_IMAGES"}
        self.assertEqual(set(summary["repositoryVariables"]) | set(summary["unresolvedVariables"]), expected)

    def test_pagination_rejects_foreign_paths_queries_loops_duplicates_and_lists(self):
        cfg = self.load()
        url = f"https://management.azure.com{ROOT}/resources?api-version=2021-04-01"
        badlinks = ["https://attacker.invalid/", url.replace("/resources?", "/providers?"),
                    url.replace("2021-04-01", "2020-01-01") + "&$skiptoken=a", url,
                    url + "&evil=1", url.replace("https://", "https://user:pass@") + "&$skiptoken=a"]
        for link in badlinks:
            wire = Wire()
            wire.overrides[url] = {"value": [], "nextLink": link}
            with self.subTest(link=link), mock.patch("subprocess.run", side_effect=wire), self.assertRaises(bi.InventoryError):
                bi.ReadOnly(cfg).paginated("arm", url, "value")
            self.assertEqual(len(wire.calls), 1)
        for data in ({"value": {}}, {"value": [{"id": "same"}, {"id": "same"}]}, {"value": [None]}, {}):
            wire = Wire()
            wire.overrides[url] = data
            with mock.patch("subprocess.run", side_effect=wire), self.assertRaises(bi.InventoryError):
                bi.ReadOnly(cfg).paginated("arm", url, "value")

    def test_pagination_bounds_graph_and_github_pages(self):
        cfg = self.load()
        graph = "https://graph.microsoft.com/v1.0/users?%24select=id%2CuserType%2CaccountEnabled&%24top=100"
        wire = Wire()
        wire.overrides[graph] = {"value": [{"id": APP}], "@odata.nextLink": graph + "&$skiptoken=two"}
        wire.overrides[graph + "&$skiptoken=two"] = {"value": [{"id": SP}]}
        with mock.patch("subprocess.run", side_effect=wire):
            self.assertEqual([x["id"] for x in bi.ReadOnly(cfg).paginated("graph", graph)], [APP, SP])
        path = "/repos/example/agents/actions/secrets?per_page=100&page=1"
        wire = Wire()
        wire.overrides[path] = {"total_count": 2, "secrets": [{"name": "NAME_ONLY_ONE"}]}
        wire.overrides[path.replace("&page=1", "&page=2")] = {"total_count": 2, "secrets": [{"name": "NAME_ONLY_TWO"}]}
        with mock.patch("subprocess.run", side_effect=wire):
            self.assertEqual(bi.ReadOnly(cfg).paginated("github", path, "secrets"),
                             [{"name": "NAME_ONLY_ONE"}, {"name": "NAME_ONLY_TWO"}])
        arm = f"https://management.azure.com{ROOT}/resources?api-version=2021-04-01"
        wire = Wire()
        wire.overrides[arm] = {"value": [{"id": "one"}], "nextLink": arm + "&$skiptoken=two"}
        wire.overrides[arm + "&$skiptoken=two"] = {"value": [{"id": "two"}], "nextLink": arm + "&$skiptoken=three"}
        with mock.patch("subprocess.run", side_effect=wire), mock.patch.object(bi, "MAX_PAGES", 2), self.assertRaises(bi.InventoryError):
            bi.ReadOnly(cfg).paginated("arm", arm)
        self.assertEqual(len(wire.calls), 2)

    def test_wrong_id_name_pair_and_metadata_are_not_accepted(self):
        wire = Wire()
        wire.identities[0]["name"] = "other"
        code, out, _ = self.run_cli(wire)
        self.assertEqual(code, 2)
        self.assertNotIn("AZURE_CLIENT_ID", json.loads(out)["summary"]["repositoryVariables"])
        wire = Wire()
        wire.identities[0]["properties"]["clientId"] = "not-a-guid"
        code, out, _ = self.run_cli(wire)
        self.assertEqual(code, 2)
        self.assertNotIn("AZURE_CLIENT_ID", json.loads(out)["summary"]["repositoryVariables"])

    def test_resolved_default_profile_is_rejected_before_cloud(self):
        alias = Path(self.tmp.name) / "profile-link"
        alias.symlink_to(Path.home() / ".azure", target_is_directory=True)
        self.config["azure"]["configDir"] = str(alias)
        wire = Wire()
        code, out, _ = self.run_cli(wire)
        self.assertEqual((code, out, wire.calls), (1, "", []))

    def test_untaggable_metadata_is_inventory_not_ownership_or_pii(self):
        wire = Wire()
        budget_id = ROOT + "/providers/Microsoft.Consumption/budgets/guard"
        wire.overrides[ROOT + "/providers/Microsoft.Consumption/budgets"] = {"value": [
            {"id": budget_id, "name": "guard", "properties": {"amount": 100, "timeGrain": "Monthly",
             "notifications": {"warning": {"contactEmails": ["PRIVATE-UPN@example.invalid"]}}}}]}
        assignment_id = ROOT + "/providers/Microsoft.Authorization/roleAssignments/" + APP
        wire.overrides[ROOT + "/providers/Microsoft.Authorization/roleAssignments"] = {"value": [
            {"id": assignment_id, "properties": {"principalId": SP, "scope": ROOT, "roleDefinitionId": ROOT + "/roles/" + CLIENT}}]}
        code, out, err = self.run_cli(wire)
        self.assertEqual(code, 0, err + out)
        result = json.loads(out)
        self.assertEqual(result["inventory"]["budgets"][0]["amount"], 100)
        self.assertEqual(result["inventory"]["assignments"][0]["principalId"], SP)
        self.assertNotIn(budget_id, [x["id"] for x in result["owned"]])
        self.assertNotIn("PRIVATE", out + err)

    def test_tags_cannot_own_known_untaggable_children(self):
        wire = Wire()
        children = [{"id": ROOT + "/providers/" + suffix, "name": "child", "tags": markers()}
                    for suffix in ("Microsoft.Consumption/budgets/guard", "Microsoft.Authorization/roleDefinitions/" + APP,
                                   "Microsoft.Authorization/roleAssignments/" + SP,
                                   "Microsoft.ManagedIdentity/userAssignedIdentities/ci/federatedIdentityCredentials/trust")]
        wire.overrides[ROOT + "/resources"] = {"value": wire.identities + wire.accounts + children}
        code, out, err = self.run_cli(wire)
        self.assertEqual(code, 0, err + out)
        self.assertEqual(json.loads(out)["owned"], [])

    def test_owned_sp_component_is_from_exact_app_not_sp_markers(self):
        wire = Wire()
        wire.apps[0]["tags"] = ["ada-bootstrap-environment:" + ENV, "ada-repository-id:12345", "ada-bootstrap-component:shared-model"]
        wire.sps = [{"id": SP, "appId": wire.apps[0]["appId"], "tags": []}]
        result = json.loads(self.run_cli(wire)[1])
        sp = next(x for x in result["owned"] if x["id"] == SP)
        self.assertEqual(sp["component"], "shared-model")

    def test_no_local_receipt_is_needed_and_dynamic_ids_are_used(self):
        self.config["azure"]["tenantID"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        self.config["azure"]["subscriptionID"] = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        self.config["github"]["repositoryID"] = "98765"
        self.config["github"]["ownerID"] = "87654"
        wire = Wire()
        # Translate a synthetic control-plane response at the process boundary.
        def dynamic(args, **kwargs):
            old_args = [x.replace(self.config["azure"]["subscriptionID"], SUB) for x in args]
            result = wire(old_args, **kwargs)
            payload = result.stdout.replace(TENANT, self.config["azure"]["tenantID"]).replace(SUB, self.config["azure"]["subscriptionID"])
            if "/repos/example/agents" == args[4]:
                payload = payload.replace("12345", "98765").replace("67890", "87654")
            return subprocess.CompletedProcess(args, result.returncode, payload, result.stderr)
        code, out, err = self.run_cli(dynamic)
        self.assertEqual(code, 0, err + out)
        result = json.loads(out)
        self.assertEqual(result["summary"]["repositoryVariables"]["AZURE_TENANT_ID"], self.config["azure"]["tenantID"])
        self.assertEqual(result["summary"]["repositoryVariables"]["AZURE_CLIENT_ID"], CLIENT)

    def test_reader_rejects_unpinned_requests_before_process(self):
        reader = bi.ReadOnly(self.load())
        for service, url in (("arm", "https://management.azure.com/subscriptions/wrong/resources?api-version=2021-04-01"),
                             ("graph", "https://graph.microsoft.com/v1.0/me/messages"),
                             ("github", "/repos/example/agents/actions/secrets/secret-name")):
            with mock.patch("subprocess.run") as run, self.assertRaises(bi.InventoryError):
                reader.get(service, url)
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
