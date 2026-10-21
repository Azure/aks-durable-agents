#!/usr/bin/env python3
"""Bounded cleanup of one explicitly configured, owned nightly AKS lineage."""
import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone

REPOSITORY_ID = "1426100286"
PURPOSE = "nightly-aks"
HOST_SUBJECT = "system:serviceaccount:agents:kaimahi-aks-durable-agents-host"
FIC_NAME = "nightly-host"
GUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}")
NAMES = ("AKS_RESOURCE_GROUP", "AKS_CLUSTER_NAME", "AKS_NODE_RESOURCE_GROUP",
         "AKS_IDENTITY_RESOURCE_GROUP", "AKS_MODEL_IDENTITY_NAME")
IDS = ("AZURE_CLIENT_ID", "AZURE_TENANT_ID", "AZURE_SUBSCRIPTION_ID")


class CloudError(Exception):
    """Deliberately excludes command output, tokens and resource identifiers."""


def configuration(environment):
    enabled = environment.get("AKS_BOOTSTRAP_ENABLED", "false")
    if enabled == "false" or enabled == "":
        return None
    if enabled != "true":
        raise ValueError("invalid enable flag")
    config = {key: environment.get(key, "") for key in IDS + NAMES}
    if any(not GUID.fullmatch(config[key]) for key in IDS):
        raise ValueError("invalid or missing Azure identifiers")
    if any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,62}", config[key]) for key in NAMES):
        raise ValueError("invalid or missing resource names")
    if config["AKS_RESOURCE_GROUP"] == config["AKS_NODE_RESOURCE_GROUP"]:
        raise ValueError("managed node group must be separate")
    return config


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError("invalid expiry")
    try:
        result = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise ValueError("invalid expiry") from None
    if result.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise ValueError("invalid expiry")
    return result


def lineage(tags):
    if not isinstance(tags, dict) or tags.get("ada-repository-id") != REPOSITORY_ID or tags.get("ada-purpose") != PURPOSE:
        raise ValueError("ownership missing or mismatched")
    run, attempt = tags.get("ada-run-id"), tags.get("ada-run-attempt")
    if any(not isinstance(v, str) or not re.fullmatch(r"[1-9][0-9]{0,19}", v) for v in (run, attempt)):
        raise ValueError("invalid run lineage")
    timestamp(tags.get("ada-expires-at"))
    return {"repositoryID": REPOSITORY_ID, "purpose": PURPOSE, "runID": run,
            "runAttempt": attempt, "expiresAt": tags["ada-expires-at"]}


def issuer_valid(issuer, config):
    return isinstance(issuer, str) and re.fullmatch(
        r"https://[a-z0-9-]+\.oic\.prod-aks\.azure\.com/" + re.escape(config["AZURE_TENANT_ID"]) + r"/" + GUID.pattern + r"/", issuer) is not None


def cluster_metadata(item, config):
    expected = (f"/subscriptions/{config['AZURE_SUBSCRIPTION_ID']}/resourceGroups/{config['AKS_RESOURCE_GROUP']}"
                f"/providers/Microsoft.ContainerService/managedClusters/{config['AKS_CLUSTER_NAME']}")
    if not isinstance(item, dict):
        raise ValueError("invalid cluster inventory")
    # AKS can fail before producing its issuer. Tags/target still authorize
    # removal, but any FIC below must independently validate its exact trust.
    partial = item.get("issuer") in (None, "") and item.get("provisioningState") in ("Creating", "Failed", "Deleting")
    if (not isinstance(item.get("id"), str) or item["id"].lower() != expected.lower()
            or item.get("name") != config["AKS_CLUSTER_NAME"]
            or item.get("nodeResourceGroup") != config["AKS_NODE_RESOURCE_GROUP"]
            or not (partial or issuer_valid(item.get("issuer"), config))):
        raise ValueError("cluster target or issuer mismatch")
    return lineage(item.get("tags"))


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def credential_metadata(items, config, cluster=None):
    if not isinstance(items, list) or len(items) > 1:
        raise ValueError("unexpected federation inventory")
    if not items:
        return None
    item = items[0]
    if (not isinstance(item, dict) or item.get("name") != FIC_NAME or item.get("subject") != HOST_SUBJECT
            or item.get("audiences") != ["api://AzureADTokenExchange"] or not issuer_valid(item.get("issuer"), config)):
        raise ValueError("unexpected federation trust")
    # Managed-identity FICs have no description/tags field. Never manufacture
    # orphan expiry evidence: only the live matching cluster proves lineage.
    if cluster is None:
        raise ValueError("orphan federation requires operator recovery")
    if item["issuer"] != cluster["issuer"]:
        raise ValueError("federation and cluster issuer differ")
    return cluster_metadata(cluster, config)


class Azure:
    def __init__(self, config):
        self.config = config

    def run(self, *args, mutation=False):
        try:
            result = subprocess.run(["az", *args, "--subscription", self.config["AZURE_SUBSCRIPTION_ID"],
                                     "--only-show-errors", "--output", "json"], capture_output=True, text=True, timeout=25, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise CloudError("Azure command unavailable or timed out") from None
        if result.returncode:
            raise CloudError("Azure request failed; state is unknown")
        if mutation:
            return None
        try:
            return json.loads(result.stdout, object_pairs_hook=unique_object)
        except (ValueError, TypeError):
            raise CloudError("Azure returned invalid state") from None

    def account(self):
        return self.run("account", "show", "--query", "{id:id,tenantId:tenantId}")

    def group(self):
        return self.run("group", "show", "--name", self.config["AKS_RESOURCE_GROUP"], "--query", "{tags:tags}")

    def cluster(self):
        items = self.run("aks", "list", "--resource-group", self.config["AKS_RESOURCE_GROUP"], "--query",
                         "[].{id:id,name:name,tags:tags,nodeResourceGroup:nodeResourceGroup,issuer:oidcIssuerProfile.issuerUrl,provisioningState:provisioningState}")
        if (not isinstance(items, list) or len(items) > 1
                or (items and (not isinstance(items[0], dict) or items[0].get("name") != self.config["AKS_CLUSTER_NAME"]))):
            raise ValueError("dedicated group contains an unexpected cluster")
        return items[0] if items else None

    def fics(self):
        return self.run("identity", "federated-credential", "list", "--resource-group", self.config["AKS_IDENTITY_RESOURCE_GROUP"],
                         "--identity-name", self.config["AKS_MODEL_IDENTITY_NAME"], "--query",
                         "[].{name:name,issuer:issuer,subject:subject,audiences:audiences}")

    def delete_cluster(self):
        self.run("aks", "delete", "--resource-group", self.config["AKS_RESOURCE_GROUP"], "--name",
                 self.config["AKS_CLUSTER_NAME"], "--yes", "--no-wait", mutation=True)

    def delete_fic(self):
        self.run("identity", "federated-credential", "delete", "--resource-group", self.config["AKS_IDENTITY_RESOURCE_GROUP"],
                 "--identity-name", self.config["AKS_MODEL_IDENTITY_NAME"], "--name", FIC_NAME, "--yes", mutation=True)

    def node_group_exists(self):
        result = self.run("group", "exists", "--name", self.config["AKS_NODE_RESOURCE_GROUP"])
        if type(result) is not bool:
            raise ValueError("managed group existence unknown")
        return result


def validate(config, cloud):
    account, group = cloud.account(), cloud.group()
    if (not isinstance(account, dict) or account.get("id") != config["AZURE_SUBSCRIPTION_ID"]
            or account.get("tenantId") != config["AZURE_TENANT_ID"]):
        raise ValueError("Azure account mismatch")
    tags = group.get("tags") if isinstance(group, dict) else None
    if not isinstance(tags, dict) or tags.get("ada-repository-id") != REPOSITORY_ID or tags.get("ada-purpose") != PURPOSE:
        raise ValueError("dedicated group ownership mismatch")


def cleanup(config, cloud, now, apply=False, wait_seconds=180, monotonic=time.monotonic, sleep=time.sleep,
            owned_run=None, node_wait_seconds=0):
    validate(config, cloud)
    item, credentials = cloud.cluster(), cloud.fics()
    metadata = cluster_metadata(item, config) if item is not None else None
    fic_metadata = credential_metadata(credentials, config, item)
    result = lambda status: {"status": status, "dryRun": not apply}
    # The scenario may tear down its own run before expiry, never another run.
    # Scheduled/default callers cannot opt into this implicitly.
    if owned_run is not None:
        if (not isinstance(owned_run, tuple) or len(owned_run) != 2
                or any(not isinstance(v, str) or not re.fullmatch(r"[1-9][0-9]{0,19}", v) for v in owned_run)):
            raise ValueError("invalid teardown run")
        if metadata is not None and (metadata["runID"], metadata["runAttempt"]) != owned_run:
            raise ValueError("teardown run mismatch")
    elif any(m is not None and timestamp(m["expiresAt"]) > now for m in (metadata, fic_metadata)):
        return result("pending-unexpired")
    if not apply and (item is not None or credentials):
        return result("would-delete")
    # Remove federation while live cluster tags still prove its lineage.
    # Deleting the cluster first loses that proof on a later sweep because
    # managed-identity FICs cannot persist expiry/ownership metadata.
    if credentials:
        fresh = cloud.fics()
        if fresh != credentials or cloud.cluster() != item:
            raise ValueError("lineage changed before federation deletion")
        credential_metadata(fresh, config, item)
        cloud.delete_fic()
        if cloud.fics():
            raise ValueError("federation deletion not confirmed")
    if item is not None:
        if cloud.cluster() != item:
            raise ValueError("cluster changed before deletion")
        if item.get("provisioningState") != "Deleting":
            cloud.delete_cluster()
        deadline = monotonic() + wait_seconds
        while cloud.cluster() is not None:
            if monotonic() >= deadline:
                return result("pending-deleting")
            sleep(3)
    node_deadline = monotonic() + node_wait_seconds
    while cloud.node_group_exists():
        if monotonic() >= node_deadline:
            raise ValueError("managed node group remains; operator recovery required")
        sleep(3)
    return result("removed" if item is not None or credentials else "absent")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("config", "validate", "cleanup"))
    parser.add_argument("--apply", action="store_true", help="delete only verified expired owned resources")
    args = parser.parse_args(argv)
    try:
        config = configuration(os.environ)
        if args.command == "config":
            print("configured=" + str(config is not None).lower())
            return 0
        if config is None:
            print(json.dumps({"status": "not-configured", "dryRun": True}))
            return 0
        cloud = Azure(config)
        if args.command == "validate":
            validate(config, cloud)
            result = {"status": "validated-read-only", "dryRun": True}
        else:
            result = cleanup(config, cloud, datetime.now(timezone.utc), apply=args.apply)
        print(json.dumps(result))
        return 0
    except (CloudError, ValueError):
        print(json.dumps({"status": "failed-closed", "dryRun": not args.apply}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
