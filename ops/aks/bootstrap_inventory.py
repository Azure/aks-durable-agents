"""Pinned, read-only cloud inventory. No lifecycle or mutation adapters."""
import json
import os
import re
import subprocess
from urllib.parse import parse_qsl, quote, urlencode, urlsplit

GUID = r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}"
COMPONENTS = ("nightly", "shared-model", "human-identity", "persistent-cluster")
ARM = "https://management.azure.com"
GRAPH = "https://graph.microsoft.com/v1.0"
MAX_PAGES = 100
MAX_ITEMS = 10000


class InventoryError(Exception):
    """Only fixed phase/reason strings may cross the CLI error boundary."""


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def arm_url(config, suffix, version):
    return f"{ARM}/subscriptions/{config['azure']['subscriptionID']}/{suffix}?api-version={version}"


def routes(config):
    n, m = config["nightly"], config["model"]
    paths = {"groups": ("resourcegroups", "2021-04-01"), "resources": ("resources", "2021-04-01"),
             "identities": (f"resourceGroups/{n['identityResourceGroup']}/providers/Microsoft.ManagedIdentity/userAssignedIdentities", "2023-01-31"),
             "accounts": ("providers/Microsoft.CognitiveServices/accounts", "2023-05-01"),
             "deployments": (f"resourceGroups/{m['resourceGroup']}/providers/Microsoft.CognitiveServices/accounts/{m['accountName']}/deployments", "2023-05-01"),
             "budgets": ("providers/Microsoft.Consumption/budgets", "2023-11-01"),
             "roles": ("providers/Microsoft.Authorization/roleDefinitions", "2022-04-01"),
             "assignments": ("providers/Microsoft.Authorization/roleAssignments", "2022-04-01"),
             "providers": ("providers", "2021-04-01")}
    for label, name in (("ciFics", n["ciIdentityName"]), ("modelFics", n["modelIdentityName"])):
        paths[label] = (f"resourceGroups/{n['identityResourceGroup']}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{name}/federatedIdentityCredentials", "2023-01-31")
    return {k: arm_url(config, *v) for k, v in paths.items()}


GRAPH_FIELDS = {
    "organization": "id,verifiedDomains",
    "applications": "id,appId,displayName,tags,notes,signInAudience,identifierUris,api,appRoles,spa,publicClient,isFallbackPublicClient,requiredResourceAccess,optionalClaims,groupMembershipClaims",
    "servicePrincipals": "id,appId,displayName,tags,appRoleAssignmentRequired,accountEnabled",
    "users": "id,userType,accountEnabled", "groups": "id,securityEnabled,groupTypes",
}


def graph_url(collection):
    query = {"$select": GRAPH_FIELDS[collection]}
    if collection != "organization":
        query["$top"] = "100"
    return GRAPH + "/" + collection + "?" + urlencode(query)


class ReadOnly:
    def __init__(self, config):
        self.config = config
        self.arm_routes = set(routes(config).values())
        self.graph_routes = {graph_url(k) for k in GRAPH_FIELDS}
        self.repo = "/repos/" + config["github"]["repository"]

    def _valid(self, service, url):
        if not isinstance(url, str) or len(url) > 16384:
            raise InventoryError("request: invalid target")
        p = urlsplit(url)
        if p.fragment or p.username or p.password or "%" in p.path or ".." in p.path or "\\" in url:
            raise InventoryError("request: invalid target")
        pairs = parse_qsl(p.query, keep_blank_values=True)
        q = dict(pairs)
        if len(q) != len(pairs):
            raise InventoryError("request: duplicate query")
        if service in ("arm", "graph"):
            host = "management.azure.com" if service == "arm" else "graph.microsoft.com"
            if p.scheme != "https" or p.netloc != host:
                raise InventoryError("request: foreign host")
            tokens = {"$skiptoken"} if service == "arm" else {"$skiptoken", "$skip"}
            base = p._replace(query=urlencode({k: v for k, v in pairs if k not in tokens})).geturl()
            permitted = self.arm_routes if service == "arm" else self.graph_routes
            # Compare query dictionaries: service continuations may reorder or encode them.
            matched = any(urlsplit(v).path == p.path and dict(parse_qsl(urlsplit(v).query)) == dict(parse_qsl(urlsplit(base).query)) for v in permitted)
            if not matched and service == "graph":
                matched = (re.fullmatch(r"/v1.0/servicePrincipals/" + GUID + r"/appRoleAssignedTo", p.path) is not None
                           and set(q) <= {"$select", "$top", "$skiptoken", "$skip"}
                           and q.get("$select") == "id,principalId,resourceId,appRoleId,principalType" and q.get("$top") == "100")
            if not matched or any(not q[k] or len(q[k]) > 8192 for k in tokens if k in q):
                raise InventoryError("request: unpinned collection")
        elif service == "github":
            suffix = p.path[len(self.repo):] if p.path.startswith(self.repo) else None
            allowed = ("", "/actions/oidc/customization/sub", "/environments", "/actions/variables", "/actions/secrets", "/actions/organization-secrets")
            environment = suffix is not None and re.fullmatch(r"/environments/[A-Za-z0-9_.-]+/(deployment-branch-policies|secrets|variables)", suffix)
            if (p.scheme or p.netloc or suffix is None or not (suffix in allowed or environment)
                    or set(q) - {"page", "per_page"} or (q and (q.get("per_page") != "100" or not re.fullmatch(r"[1-9][0-9]{0,2}", q.get("page", ""))))):
                raise InventoryError("request: unpinned GitHub target")
        else:
            raise InventoryError("request: unknown service")

    def _run(self, args):
        environment = dict(os.environ, AZURE_CONFIG_DIR=self.config["azure"]["configDir"],
                           AZURE_EXTENSION_USE_DYNAMIC_INSTALL="no", AZURE_CORE_COLLECT_TELEMETRY="no", GH_HOST="github.com")
        try:
            result = subprocess.run(args, capture_output=True, text=True, timeout=30, check=False, env=environment)
        except (OSError, subprocess.TimeoutExpired):
            raise InventoryError("transport: unavailable or timed out") from None
        if result.returncode:
            raise InventoryError("transport: request failed; inventory unknown")
        try:
            if len(result.stdout) > 8 * 1024 * 1024:
                raise ValueError()
            data = json.loads(result.stdout, object_pairs_hook=unique_object)
            if not isinstance(data, dict):
                raise TypeError()
            return data
        except (ValueError, TypeError):
            raise InventoryError("transport: malformed response") from None

    def account(self):
        return self._run(["az", "account", "show", "--subscription", self.config["azure"]["subscriptionID"],
                          "--only-show-errors", "--output", "json"])

    def get(self, service, path):
        self._valid(service, path)
        if service == "github":
            return self._run(["gh", "api", "--method", "GET", path, "--hostname", "github.com"])
        return self._run(["az", "rest", "--method", "GET", "--url", path, "--subscription",
                          self.config["azure"]["subscriptionID"], "--only-show-errors", "--output", "json"])

    def paginated(self, service, path, key="value"):
        original = urlsplit(path)
        original_query = dict(parse_qsl(original.query))
        result, seen, visited = [], set(), set()
        total = None
        for page in range(1, MAX_PAGES + 1):
            if path in visited:
                raise InventoryError("pagination: repeated page")
            visited.add(path)
            data = self.get(service, path)
            items = data.get(key)
            if not isinstance(items, list):
                raise InventoryError("pagination: malformed collection")
            for item in items:
                identifier = item.get("id", item.get("name")) if isinstance(item, dict) else None
                if (type(identifier) not in (str, int) or not str(identifier) or str(identifier).lower() in seen):
                    raise InventoryError("pagination: invalid or duplicate ID")
                seen.add(str(identifier).lower())
                result.append(item)
            if len(result) > MAX_ITEMS:
                raise InventoryError("pagination: item bound exceeded")
            if service == "github":
                count = data.get("total_count")
                if type(count) is not int or count < 0 or count > MAX_ITEMS or (total is not None and count != total):
                    raise InventoryError("pagination: invalid count")
                total = count
                if len(result) == total:
                    return result
                if not items or len(result) > total:
                    raise InventoryError("pagination: incomplete collection")
                path = original._replace(query=urlencode({"per_page": 100, "page": page + 1})).geturl()
                continue
            link = data.get("nextLink" if service == "arm" else "@odata.nextLink")
            if link is None:
                return result
            if not isinstance(link, str):
                raise InventoryError("pagination: invalid next link")
            self._valid(service, link)
            target = urlsplit(link)
            query = dict(parse_qsl(target.query))
            tokens = {"$skiptoken"} if service == "arm" else {"$skiptoken", "$skip"}
            if (target.scheme != original.scheme or target.netloc != original.netloc or target.path != original.path
                    or {k: v for k, v in query.items() if k not in tokens} != original_query
                    or not (set(query) & tokens) or link in visited):
                raise InventoryError("pagination: foreign or repeated collection")
            path = link
        raise InventoryError("pagination: page bound exceeded")


def valid_guid(value):
    return isinstance(value, str) and re.fullmatch(GUID, value) is not None


def identity_id(config, name):
    return f"/subscriptions/{config['azure']['subscriptionID']}/resourceGroups/{config['nightly']['identityResourceGroup']}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{name}"


def collect(config, reader=None):
    reader = reader or ReadOnly(config)
    account = reader.account()
    a, g = config["azure"], config["github"]
    if account.get("id") != a["subscriptionID"] or account.get("tenantId") != a["tenantID"] or account.get("state") != "Enabled":
        raise InventoryError("identity: Azure target mismatch")
    organization = reader.paginated("graph", graph_url("organization"))
    if len(organization) != 1 or organization[0].get("id") != a["tenantID"]:
        raise InventoryError("identity: Graph tenant mismatch")
    repo_path = "/repos/" + g["repository"]
    repo = reader.get("github", repo_path)
    if (type(repo.get("id")) is not int or str(repo["id"]) != g["repositoryID"]
            or not isinstance(repo.get("owner"), dict) or type(repo["owner"].get("id")) is not int
            or str(repo["owner"]["id"]) != g["ownerID"] or repo.get("full_name") != g["repository"]):
        raise InventoryError("identity: GitHub target mismatch")
    inventory = {"organization": organization, "repository": repo}
    urls = routes(config)
    for key in ("groups", "resources", "roles", "assignments", "providers"):
        inventory[key] = reader.paginated("arm", urls[key])
    inventory["unavailableCollections"] = []
    group_id = f"/subscriptions/{a['subscriptionID']}/resourceGroups/{config['nightly']['identityResourceGroup']}"
    for key, namespace in (("identities", "Microsoft.ManagedIdentity"), ("accounts", "Microsoft.CognitiveServices"),
                           ("budgets", "Microsoft.Consumption")):
        registrations = [p.get("registrationState") for p in inventory["providers"] if p.get("namespace") == namespace]
        if len(registrations) != 1 or registrations[0] not in ("Registered", "NotRegistered", "Registering", "Unregistering"):
            raise InventoryError("inventory: provider registration unknown")
        if registrations[0] != "Registered":
            inventory[key] = []
            inventory["unavailableCollections"].append(key)
        elif key == "identities" and not any(g["id"].lower() == group_id.lower() for g in inventory["groups"]):
            # A successful parent inventory proves the missing group; its child
            # endpoint would return 404, not an empty collection.
            inventory[key] = []
        else:
            inventory[key] = reader.paginated("arm", urls[key])
    prefix = f"/subscriptions/{a['subscriptionID']}/".lower()
    for key in ("groups", "resources", "identities", "accounts", "budgets", "roles"):
        if any(not isinstance(i.get("id"), str) or not i["id"].lower().startswith(prefix) for i in inventory[key]):
            raise InventoryError("inventory: ARM target mismatch")
    for assignment in inventory["assignments"]:
        properties = assignment.get("properties")
        scope = properties.get("scope") if isinstance(properties, dict) else None
        identifier = assignment.get("id")
        scope_valid = isinstance(scope, str) and (scope == "/" or scope.lower() == prefix.rstrip("/")
            or scope.lower().startswith(prefix) or re.fullmatch(
                r"/providers/Microsoft.Management/managementGroups/[A-Za-z0-9][A-Za-z0-9_.()-]{0,89}", scope, re.IGNORECASE))
        if not scope_valid or not isinstance(identifier, str) or not re.fullmatch(
                re.escape(scope.rstrip("/")) + r"/providers/Microsoft.Authorization/roleAssignments/" + GUID,
                identifier, re.IGNORECASE):
            raise InventoryError("inventory: assignment target mismatch")
    for label, name in (("ciFics", config["nightly"]["ciIdentityName"]), ("modelFics", config["nightly"]["modelIdentityName"])):
        expected = identity_id(config, name)
        matches = [i for i in inventory["identities"] if i["id"].lower() == expected.lower()]
        inventory[label] = reader.paginated("arm", urls[label]) if matches else []
        if "identities" in inventory["unavailableCollections"]:
            inventory["unavailableCollections"].append(label)
        if any(not i["id"].lower().startswith(expected.lower() + "/federatedidentitycredentials/") for i in inventory[label]):
            raise InventoryError("inventory: federation target mismatch")
    m = config["model"]
    account_id = f"/subscriptions/{a['subscriptionID']}/resourceGroups/{m['resourceGroup']}/providers/Microsoft.CognitiveServices/accounts/{m['accountName']}"
    inventory["deployments"] = reader.paginated("arm", urls["deployments"]) if any(i["id"].lower() == account_id.lower() for i in inventory["accounts"]) else []
    if "accounts" in inventory["unavailableCollections"]:
        inventory["unavailableCollections"].append("deployments")
    if any(not i["id"].lower().startswith(account_id.lower() + "/deployments/") for i in inventory["deployments"]):
        raise InventoryError("inventory: deployment target mismatch")
    for key in ("applications", "servicePrincipals", "users", "groups"):
        target = "directoryGroups" if key == "groups" else key
        inventory[target] = reader.paginated("graph", graph_url(key))
        if any(not valid_guid(i.get("id")) for i in inventory[target]):
            raise InventoryError("inventory: invalid directory ID")
    inventory["appAssignments"] = []
    app_ids = {i.get("appId") for i in inventory["applications"]}
    for sp in inventory["servicePrincipals"]:
        if sp.get("appId") in app_ids:
            path = GRAPH + "/servicePrincipals/" + sp["id"] + "/appRoleAssignedTo?" + urlencode({"$select": "id,principalId,resourceId,appRoleId,principalType", "$top": "100"})
            inventory["appAssignments"].extend(reader.paginated("graph", path))
    inventory["oidc"] = reader.get("github", repo_path + "/actions/oidc/customization/sub")
    for key, suffix, collection in (("environments", "/environments", "environments"),
                                     ("variables", "/actions/variables", "variables"),
                                     ("repositorySecrets", "/actions/secrets", "secrets"),
                                     ("organizationSecrets", "/actions/organization-secrets", "secrets")):
        inventory[key] = reader.paginated("github", repo_path + suffix + "?per_page=100&page=1", collection)
    inventory["environmentDetails"] = []
    for env in inventory["environments"]:
        name = env.get("name")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", name):
            raise InventoryError("inventory: unsupported environment name")
        path = repo_path + "/environments/" + quote(name, safe="")
        if "deployment_branch_policy" not in env:
            raise InventoryError("inventory: missing environment policy metadata")
        policy = env["deployment_branch_policy"]
        if policy is not None and not isinstance(policy, dict):
            raise InventoryError("inventory: invalid environment policy metadata")
        details = {"name": name, "policies": []}
        # GitHub returns 404 here when the environment has no custom policy.
        # Its explicit metadata, not an ignored request failure, proves that case.
        if policy is not None and policy.get("custom_branch_policies") is True:
            details["policies"] = reader.paginated("github", path + "/deployment-branch-policies?per_page=100&page=1", "branch_policies")
        for key in ("secrets", "variables"):
            details[key] = reader.paginated("github", path + "/" + key + "?per_page=100&page=1", key)
        inventory["environmentDetails"].append(details)
    return inventory


def ownership(item, config, graph=False):
    """Direct markers only. Untaggable children/notes never establish ownership."""
    keys = ("ada-bootstrap-environment", "ada-repository-id", "ada-bootstrap-component")
    raw = item.get("tags")
    if raw is None:
        return "reference", None
    tags = {}
    if graph:
        if not isinstance(raw, list) or any(not isinstance(v, str) for v in raw):
            return "blocked", None
        for value in raw:
            for key in keys:
                if value.startswith(key + ":"):
                    if key in tags:
                        return "blocked", None
                    tags[key] = value[len(key) + 1:]
    else:
        if not isinstance(raw, dict):
            return "blocked", None
        for key, value in raw.items():
            if key.lower() in keys:
                if key.lower() in tags or not isinstance(value, str):
                    return "blocked", None
                tags[key.lower()] = value
    if not any(k in tags for k in (keys[0], keys[2])):
        return "reference", None
    if set(tags) != set(keys) or not valid_guid(tags.get(keys[0])) or tags.get(keys[2]) not in COMPONENTS or not re.fullmatch(r"[1-9][0-9]*", tags.get(keys[1], "")):
        return "blocked", None
    if tags[keys[0]] != config["environmentID"] or tags[keys[1]] != config["github"]["repositoryID"]:
        return "reference", None
    return "owned", tags[keys[2]]
