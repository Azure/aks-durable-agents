#!/usr/bin/env python3
"""Read-only test-environment plan/check; never full deployment qualification."""
import argparse
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

from bootstrap_inventory import (
    InventoryError,
    collect,
    identity_id,
    ownership,
    unique_object,
    valid_guid,
)

SCHEMA = {"azure": ("tenantID", "subscriptionID", "configDir"),
          "github": ("repository", "repositoryID", "ownerID"),
          "nightly": ("resourceGroup", "identityResourceGroup", "ciIdentityName", "modelIdentityName", "clusterName", "nodeResourceGroup"),
          "model": ("resourceGroup", "accountName", "deploymentName", "location", "version", "sku", "capacity"),
          "human": ("domain", "apiName", "canvasName", "cliName", "canvasRedirects")}
FLAGS = ("AKS_BOOTSTRAP_ENABLED", "AKS_SCENARIO_ENABLED", "AKS_BUDGET_CONFIRMED")
UNRESOLVED = ("MODEL_PRICE_INPUT", "MODEL_PRICE_OUTPUT", "MODEL_PRICE_EXTRA", "MODEL_PRICE_SOURCE", "MODEL_PRICE_AS_OF",
              "BACKUP_HELPER_IMAGE", "BACKUP_HELPER_RECEIPT", "PUBLISHED_IMAGES")


def require(condition):
    if not condition:
        raise ValueError("invalid configuration")


def redirect_valid(value):
    if not isinstance(value, str) or len(value) > 2048 or any(ord(c) < 33 for c in value):
        return False
    try:
        u = urlsplit(value)
        return (u.scheme in ("https", "http") and bool(u.hostname) and not u.username and not u.password
                and not u.query and not u.fragment and not u.netloc.endswith(":")
                and (u.port is None or 1 <= u.port <= 65535)
                and (u.scheme == "https" or u.hostname in ("localhost", "127.0.0.1")))
    except ValueError:
        return False


def load_config(path):
    """Closed, secret-free v1 input. No receipt/cache is consulted."""
    try:
        content = Path(path).read_text(encoding="utf-8")
        require(len(content) <= 65536)
        c = json.loads(content, object_pairs_hook=unique_object)
        require(isinstance(c, dict) and set(c) == {"version", "environmentID", *SCHEMA})
        require(type(c["version"]) is int and c["version"] == 1 and valid_guid(c["environmentID"]))
        for section, keys in SCHEMA.items():
            require(isinstance(c[section], dict) and set(c[section]) == set(keys))
            for key, value in c[section].items():
                if key not in ("capacity", "canvasRedirects"):
                    require(isinstance(value, str) and 0 < len(value) <= 4096 and not any(ord(ch) < 32 for ch in value))
        a, g, n, m, h = (c[k] for k in ("azure", "github", "nightly", "model", "human"))
        require(valid_guid(a["tenantID"]) and valid_guid(a["subscriptionID"]))
        profile = Path(a["configDir"])
        require(profile.is_absolute() and profile.is_dir())
        require(profile.resolve() != (Path.home() / ".azure").resolve())
        a["configDir"] = str(profile.resolve())
        require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}", g["repository"]) is not None)
        require(all(re.fullmatch(r"[1-9][0-9]{0,19}", g[k]) for k in ("repositoryID", "ownerID")))
        for value in [*n.values(), m["resourceGroup"]]:
            require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,62}", value) is not None)
        require(len({n["resourceGroup"].lower(), n["identityResourceGroup"].lower(), n["nodeResourceGroup"].lower(), m["resourceGroup"].lower()}) == 4)
        require(n["ciIdentityName"].lower() != n["modelIdentityName"].lower())
        require(re.fullmatch(r"[a-z0-9][a-z0-9-]{1,62}", m["accountName"]) is not None)
        require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", m["deploymentName"]) is not None)
        require(re.fullmatch(r"[a-z][a-z0-9]{1,31}", m["location"]) is not None)
        require(all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", m[k]) for k in ("version", "sku")))
        require(type(m["capacity"]) is int and 1 <= m["capacity"] <= 1000)
        require(re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,250}[a-z0-9])?\.[a-z]{2,63}", h["domain"]) is not None and ".." not in h["domain"])
        names = [h[k] for k in ("apiName", "canvasName", "cliName")]
        require(len(set(names)) == 3 and all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", v) for v in names))
        require(isinstance(h["canvasRedirects"], list) and 1 <= len(h["canvasRedirects"]) <= 10)
        require(all(redirect_valid(v) for v in h["canvasRedirects"]))
        require(len(set(h["canvasRedirects"])) == len(h["canvasRedirects"]))
        return c
    except (OSError, ValueError, TypeError, KeyError, RuntimeError):
        raise ValueError("configuration: invalid or unreadable") from None


def safe_inventory(i):
    """Project metadata, never raw responses, notes, UPNs or variable values."""
    result: dict = {}
    for key in ("groups", "resources", "identities", "accounts", "deployments", "budgets", "roles", "assignments"):
        result[key] = [{"id": x["id"]} for x in i[key]]
    for key, fields in (("budgets", ("amount", "timeGrain", "timePeriod")),
                        ("roles", ("roleName", "type", "permissions", "assignableScopes")),
                        ("assignments", ("principalId", "principalType", "roleDefinitionId", "scope"))):
        for target, source in zip(result[key], i[key]):
            properties = source.get("properties", {})
            target.update({field: properties.get(field) for field in fields})
    result["providers"] = [{"namespace": x.get("namespace"), "registrationState": x.get("registrationState")} for x in i["providers"]]
    result["unavailableCollections"] = i["unavailableCollections"]
    result["applications"] = [{"id": x["id"], "appId": x.get("appId"), "signInAudience": x.get("signInAudience"),
                               "notesPresent": bool(x.get("notes")), "appRoleCount": len(x.get("appRoles") or []),
                               "requiredResourceCount": len(x.get("requiredResourceAccess") or [])} for x in i["applications"]]
    result["servicePrincipals"] = [{k: x.get(k) for k in ("id", "appId", "appRoleAssignmentRequired", "accountEnabled")} for x in i["servicePrincipals"]]
    result["users"] = [{k: x.get(k) for k in ("id", "userType", "accountEnabled")} for x in i["users"]]
    result["directoryGroups"] = [{"id": x["id"]} for x in i["directoryGroups"]]
    result["appAssignments"] = [{k: x.get(k) for k in ("id", "principalId", "resourceId", "appRoleId", "principalType")} for x in i["appAssignments"]]
    for key in ("ciFics", "modelFics"):
        result[key] = [{"id": x["id"]} for x in i[key]]
    result["oidc"] = {k: i["oidc"].get(k) for k in ("use_default", "use_immutable_subject", "include_claim_keys")}
    result["environments"] = [{"name": x["name"], "policyCount": len(x["policies"]),
                               "variableNames": [v["name"] for v in x["variables"]],
                               "secretNames": [s["name"] for s in x["secrets"]]} for x in i["environmentDetails"]]
    for key in ("repositorySecrets", "organizationSecrets"):
        result[key] = [s["name"] for s in i[key]]
    result["variableNames"] = [v["name"] for v in i["variables"]]
    return result


def assess(config, inventory, command="plan"):
    require(command in ("plan", "check"))
    i, c = inventory, config
    dependencies, owned = [], []
    states = {}

    def record(label, action, state="reference", reason="consistent"):
        dependencies.append({"dependency": label, "action": action, "ownership": state, "reason": reason})

    for key, kind, graph in (("groups", "resource-group", False), ("resources", "resource", False), ("applications", "application", True)):
        for item in i[key]:
            state, component = ownership(item, c, graph)
            # These types need a future anchor/registry writer, never supplied tags.
            if key == "resources" and re.search(r"/(federatedIdentityCredentials|budgets|roleDefinitions|roleAssignments)/", item["id"], re.IGNORECASE):
                state, component = "reference", None
            states[item["id"].lower()] = state
            if state == "blocked":
                record("ownership:" + kind, "blocked", "unknown", "ambiguous-markers")
            if state == "owned":
                owned.append({"kind": kind, "id": item["id"], "component": component})
    owned_apps = {x["appId"]: ownership(x, c, True) for x in i["applications"] if valid_guid(x.get("appId"))}
    if len(owned_apps) != len(i["applications"]):
        raise InventoryError("inventory: invalid or duplicate application identity")
    for sp in i["servicePrincipals"]:
        state, component = owned_apps.get(sp.get("appId"), ("reference", None))
        if state == "owned":
            owned.append({"kind": "service-principal", "id": sp["id"], "component": component})

    def desired(label, items, expected_id, expected_name, parent=True, available=True):
        if not available:
            record(label, "blocked", "unknown", "provider-not-ready")
            return None
        matches = [x for x in items if x["id"].lower() == expected_id.lower()]
        collision = [x for x in items if x.get("name", "").lower() == expected_name.lower() and x not in matches]
        if len(matches) > 1 or collision or (matches and matches[0].get("name", "").lower() != expected_name.lower()):
            record(label, "blocked", "unknown", "target-collision")
            return None
        if not matches:
            record(label, "create" if parent else "blocked", "unowned", "missing" if parent else "dependency-missing")
            return None
        item = matches[0]
        state = states.get(item["id"].lower(), "reference")
        record(label, "blocked" if state == "blocked" else "noop", state, "ambiguous-markers" if state == "blocked" else "consistent")
        return item if state != "blocked" else None

    def drift(label, condition):
        if not condition:
            record(label, "drift", "reference", "configuration-mismatch")

    root = "/subscriptions/" + c["azure"]["subscriptionID"]
    n, m, h = (c[k] for k in ("nightly", "model", "human"))
    for provider in i["providers"]:
        if provider.get("namespace") in ("Microsoft.ManagedIdentity", "Microsoft.CognitiveServices", "Microsoft.Consumption"):
            state = provider["registrationState"]
            if state != "Registered":
                record("provider:" + provider["namespace"], "create" if state == "NotRegistered" else "blocked",
                       "reference", "provider-not-ready")
    rg = {}
    for name in (n["resourceGroup"], n["identityResourceGroup"], m["resourceGroup"]):
        rg[name] = desired("resource-group:" + name, i["groups"], root + "/resourceGroups/" + name, name)
    identities = {}
    for label, name in (("ci", n["ciIdentityName"]), ("model", n["modelIdentityName"])):
        item = desired("identity:" + label, i["identities"], identity_id(c, name), name, rg[n["identityResourceGroup"]] is not None,
                       available="identities" not in i["unavailableCollections"])
        if item:
            p = item.get("properties")
            valid = isinstance(p, dict) and all(valid_guid(p.get(k)) for k in ("clientId", "principalId")) and p.get("tenantId") == c["azure"]["tenantID"]
            drift("identity:" + label + ":metadata", valid)
            if valid:
                identities[label] = item
    account_id = root + f"/resourceGroups/{m['resourceGroup']}/providers/Microsoft.CognitiveServices/accounts/{m['accountName']}"
    account = desired("model-account", i["accounts"], account_id, m["accountName"], rg[m["resourceGroup"]] is not None,
                      available="accounts" not in i["unavailableCollections"])
    endpoint = None
    if account:
        p = account.get("properties", {})
        drift("model-account:configuration", account.get("location") == m["location"] and account.get("kind") == "OpenAI" and p.get("disableLocalAuth") is True)
        candidate = p.get("endpoint")
        expected = f"https://{m['accountName']}.openai.azure.com/"
        if candidate == expected:
            endpoint = expected + "openai/v1/"
        else:
            drift("model-account:endpoint", False)
    deployment = desired("model-deployment", i["deployments"], account_id + "/deployments/" + m["deploymentName"], m["deploymentName"], account is not None,
                         available="deployments" not in i["unavailableCollections"])
    if deployment:
        drift("model-deployment:configuration", deployment.get("properties", {}).get("model", {}).get("version") == m["version"]
              and deployment.get("sku", {}).get("name") == m["sku"] and deployment.get("sku", {}).get("capacity") == m["capacity"])
    human = {}
    for key in ("apiName", "canvasName", "cliName"):
        matches = [x for x in i["applications"] if x.get("displayName") == h[key]]
        if len(matches) > 1:
            record("application:" + key, "blocked", "unknown", "name-collision")
        elif not matches:
            record("application:" + key, "create", "unowned", "missing")
        else:
            app = matches[0]
            state = states[app["id"].lower()]
            record("application:" + key, "blocked" if state == "blocked" else "noop", state)
            drift("application:" + key + ":audience", app.get("signInAudience") == "AzureADMyOrg")
            if key == "canvasName":
                drift("application:canvasRedirects", sorted(app.get("spa", {}).get("redirectUris", [])) == sorted(h["canvasRedirects"]))
            if valid_guid(app.get("appId")):
                human[key] = {"applicationID": app["appId"], "objectID": app["id"]}
    drift("human:domain", any(d.get("name") == h["domain"] for d in i["organization"][0].get("verifiedDomains", [])))
    drift("github:default-branch", i["repository"].get("default_branch") == "main")
    drift("github:oidc", i["oidc"].get("use_default") is True and i["oidc"].get("use_immutable_subject") is True)
    environment = [e for e in i["environments"] if e["name"] == "nightly-aks"]
    details = [e for e in i["environmentDetails"] if e["name"] == "nightly-aks"]
    if not environment:
        record("github:environment", "create", "reference", "missing")
    else:
        env = environment[0]
        drift("github:environment-policy", env.get("deployment_branch_policy") == {"protected_branches": False, "custom_branch_policies": True}
              and all(rule.get("type") == "branch_policy" for rule in env.get("protection_rules", [])) and len(details[0]["policies"]) == 1
              and details[0]["policies"][0].get("name") == "main" and details[0]["policies"][0].get("type") == "branch")
    variables = {"AZURE_TENANT_ID": c["azure"]["tenantID"], "AZURE_SUBSCRIPTION_ID": c["azure"]["subscriptionID"],
                 "AKS_RESOURCE_GROUP": n["resourceGroup"], "AKS_CLUSTER_NAME": n["clusterName"], "AKS_NODE_RESOURCE_GROUP": n["nodeResourceGroup"],
                 "AKS_IDENTITY_RESOURCE_GROUP": n["identityResourceGroup"], "AKS_MODEL_IDENTITY_NAME": n["modelIdentityName"], **dict.fromkeys(FLAGS, "false")}
    unresolved = list(UNRESOLVED)
    for name, value in (("AZURE_CLIENT_ID", identities.get("ci", {}).get("properties", {}).get("clientId")),
                        ("MODEL_ENDPOINT", endpoint), ("MODEL_DEPLOYMENT", deployment.get("name") if deployment else None)):
        if value:
            variables[name] = value
        else:
            unresolved.append(name)
    observed = {}
    for var in i["variables"]:
        name = var.get("name")
        if not isinstance(name, str) or name in observed or not isinstance(var.get("value"), str):
            raise InventoryError("inventory: invalid or duplicate variable")
        observed[name] = var["value"]
    for name, value in variables.items():
        if name not in FLAGS:
            if name not in observed:
                record("variable:" + name, "create", "reference", "missing")
            elif observed[name] != value:
                record("variable:" + name, "drift", "reference", "configuration-mismatch")
    coverage = dict.fromkeys(("deepIAM", "humanConsent", "humanSignIn", "notesOwnership", "untaggableOwnership", "federation", "budget", "providers", "customRoles", "budgetDelivery", "pricing", "imageSignatures", "liveCapabilities", "writeAuthority"), "not-tested")
    coverage["testedScope"] = "consistent" if all(d["action"] == "noop" for d in dependencies) else "inconsistent"
    return {"version": 1, "command": command, "ready": False, "coverage": coverage,
            "dependencies": dependencies, "owned": owned, "inventory": safe_inventory(i),
            "summary": {"repositoryVariables": variables, "unresolvedVariables": sorted(unresolved),
                        "observedFlags": {k: observed.get(k) for k in FLAGS}, "human": human,
                        "modelClientID": identities.get("model", {}).get("properties", {}).get("clientId")}}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "check"), nargs="?", default="plan")
    parser.add_argument("--config", required=True, help="private non-secret v1 JSON configuration")
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
        result = assess(config, collect(config), args.command)
        print(json.dumps(result, sort_keys=True))
        return 0 if result["coverage"]["testedScope"] == "consistent" else 2
    except (ValueError, InventoryError, TypeError, KeyError, AttributeError) as exc:
        # InventoryError contains only our fixed phase/reason strings, never CLI output.
        reason = str(exc) if isinstance(exc, InventoryError) else "configuration-or-inventory-invalid"
        print(json.dumps({"version": 1, "command": args.command, "ready": False, "status": "error",
                          "reason": reason, "inventory": "unknown"}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
