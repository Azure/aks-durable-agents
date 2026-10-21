#!/usr/bin/env python3
"""Explicitly enabled, fixed-target AKS lifecycle. Never prints cloud responses."""
import argparse
import json
import math
import os
import re
import signal
import subprocess
import sys
import time
from datetime import date, datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import cleanup
from cleanup import CloudError

ROOT = Path(__file__).resolve().parents[2]
_path = sys.path[:]
try:
    sys.path.extend((str(ROOT), str(ROOT / "ops/images")))
    from ops.aks import tool_audit
    from ops.images.backup_helper import validate_host
    from ops.images.update_pins import validate_manifest
finally:
    sys.path[:] = _path

VERSION = "1.37.0"
LOCATION = "westus3"
PROVIDERS = ("Microsoft.ContainerService", "Microsoft.Compute", "Microsoft.Network", "Microsoft.Storage", "Microsoft.ManagedIdentity")


def command(args, *, timeout, input=None):
    """Bound the entire trusted command's process group, including grandchildren."""
    if not math.isfinite(timeout) or timeout <= 0:
        raise cleanup.CloudError("command deadline exhausted")
    try:
        with subprocess.Popen(args, stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True) as process:
            try:
                out, _ = process.communicate(input=input, timeout=timeout)
            except BaseException:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.communicate()
                raise
            if process.returncode or len(out) > 4 * 1024 * 1024:
                raise cleanup.CloudError("command failed; outcome may be unknown")
            return out
    except (OSError, subprocess.TimeoutExpired):
        raise cleanup.CloudError("command unavailable or deadline exhausted") from None


class Deadline:
    """One immutable provisioning epoch; queued time consumes the same budget."""
    def __init__(self, started, now=time.time, monotonic=time.monotonic):
        self.started, self.now, self.monotonic = float(started), now, monotonic
        self.anchor, self.tick = now(), monotonic()
        if not math.isfinite(self.started) or self.started <= 0 or self.started > self.anchor:
            raise ValueError("invalid provisioning epoch")

    def remaining(self, cleanup=False):
        observed = max(self.now(), self.anchor + self.monotonic() - self.tick)
        left = self.started + (2700 if cleanup else 1800) - observed
        if left <= 0:
            raise CloudError("run deadline exhausted")
        return left


def object_json(value):
    if not isinstance(value, str) or len(value) > 65536:
        raise ValueError("invalid configuration JSON")
    return json.loads(value, object_pairs_hook=cleanup.unique_object)


def configuration(env, images, today=None):
    config = cleanup.configuration(env)
    if config is None or any(env.get(k) != "true" for k in ("AKS_SCENARIO_ENABLED", "AKS_BUDGET_CONFIRMED")):
        raise ValueError("scenario and budget require explicit operator approval")
    for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        value = env.get(key, "")
        if not re.fullmatch(r"[1-9][0-9]{0,19}", value):
            raise ValueError("invalid run identity")
        config[key] = value
    for key in ("MODEL_ENDPOINT", "MODEL_PRICE_SOURCE"):
        value = env.get(key, "")
        parsed = urlsplit(value)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
                or parsed.query or parsed.fragment or parsed.port not in (None, 443)):
            raise ValueError("invalid operator HTTPS configuration")
        if key == "MODEL_ENDPOINT" and not parsed.path.endswith("/openai/v1/"):
            raise ValueError("model requires the reviewed OpenAI v1 endpoint")
        config[key] = value
    deployment = env.get("MODEL_DEPLOYMENT", "")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", deployment):
        raise ValueError("invalid deployment")
    config["MODEL_DEPLOYMENT"] = deployment
    for key in ("MODEL_PRICE_INPUT", "MODEL_PRICE_OUTPUT"):
        value = env.get(key, "")
        if not re.fullmatch(r"[1-9][0-9]{0,17}", value):
            raise ValueError("explicit positive model prices required")
        config[key] = int(value)
    if env.get("MODEL_PRICE_EXTRA") != "0":
        raise ValueError("operator must verify zero extra charge")
    config["MODEL_PRICE_EXTRA"] = 0
    reservation = 2 * (8192 * config["MODEL_PRICE_INPUT"] + 4096 * config["MODEL_PRICE_OUTPUT"])
    if reservation > 2_000_000_000_000:
        raise ValueError("full model reservation exceeds USD2")
    as_of = env.get("MODEL_PRICE_AS_OF", "")
    priced_on = date.fromisoformat(as_of)
    if priced_on.isoformat() != as_of or not 0 <= ((today or datetime.now(timezone.utc).date()) - priced_on).days <= 30:
        raise ValueError("model prices require a verified date within 30 days")
    config["MODEL_PRICE_AS_OF"] = as_of
    publication = validate_manifest(object_json(env.get("PUBLISHED_IMAGES", "")))
    receipt = object_json(env.get("BACKUP_HELPER_RECEIPT", ""))
    helper = validate_host(receipt, images["host"])
    if receipt["sourceCommit"] != publication["sourceCommit"] or env.get("BACKUP_HELPER_IMAGE") != helper:
        raise ValueError("publication provenance mismatch")
    for role in ("host", "harness"):
        image = publication["images"][role]
        if images[role] != image["repository"] + "@" + image["digest"]:
            raise ValueError("rendered host or fixture pin differs from publication")
    config["BACKUP_HELPER_IMAGE"] = helper
    return config


def rendered_images():
    # Reuse the chart's fixed-layout pin parser, never silently choose latest.
    original = sys.path[:]
    try:
        sys.path.extend((str(ROOT), str(ROOT / "ops/demo")))
        from ops.demo.demo import published_images
        return published_images(ROOT)
    finally:
        sys.path[:] = original


def check_versions(data):
    if not isinstance(data, dict) or not isinstance(data.get("values"), list):
        raise ValueError("unknown offered Kubernetes versions")
    for item in data["values"]:
        if not isinstance(item, dict):
            raise ValueError("malformed version inventory")
        patches = item.get("patchVersions", {})
        if not isinstance(patches, dict):
            raise ValueError("malformed version patches")
        if item.get("isPreview", False) is False and (item.get("version") == VERSION or VERSION in patches):
            return
    raise ValueError("reviewed stable Kubernetes patch is unavailable")


def check_quota(data):
    if not isinstance(data, list):
        raise ValueError("quota unknown")
    for name in ("cores", "standarddsv4family"):
        rows = [x for x in data if isinstance(x, dict) and isinstance(x.get("name"), dict)
                and str(x["name"].get("value", "")).lower() == name]
        if (len(rows) != 1 or any(type(rows[0].get(k)) is not int for k in ("limit", "currentValue"))
                or rows[0]["currentValue"] < 0 or rows[0]["limit"] - rows[0]["currentValue"] < 6):
            raise ValueError("insufficient verified quota including one surge node")


class Azure(cleanup.Azure):
    def __init__(self, config, clock=None, teardown=False):
        super().__init__(config)
        self.clock, self.teardown = clock, teardown

    def run(self, *args, mutation=False):
        seconds = min(25, self.clock.remaining(cleanup=self.teardown)) if self.clock else 25
        raw = command(["az", *args, "--subscription", self.config["AZURE_SUBSCRIPTION_ID"],
                       "--only-show-errors", "--output", "json"], timeout=seconds)
        if mutation:
            return None
        try:
            return json.loads(raw, object_pairs_hook=cleanup.unique_object)
        except (ValueError, TypeError):
            raise cleanup.CloudError("invalid Azure response") from None


def absent(cloud, config):
    cleanup.validate(config, cloud)
    if cloud.cluster() is not None or cloud.fics() != [] or cloud.node_group_exists():
        raise ValueError("previous cluster, federation or managed group requires recovery")


def preflight(config, cloud):
    absent(cloud, config)
    for provider in PROVIDERS:
        if cloud.run("provider", "show", "--namespace", provider, "--query", "registrationState") != "Registered":
            raise ValueError("provider must be registered by the operator")
    check_versions(cloud.run("aks", "get-versions", "--location", LOCATION))
    check_quota(cloud.run("vm", "list-usage", "--location", LOCATION))
    # Public access and both digest pins are checked before a paid cluster exists.
    for image in (*rendered_images().values(), config["BACKUP_HELPER_IMAGE"]):
        command(["docker", "manifest", "inspect", image], timeout=25)


def create(config, cloud, clock):
    clock.remaining()
    absent(cloud, config)  # Recheck under the shared mutation lock.
    expiry = datetime.fromtimestamp(clock.started + 2700, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    cloud.run("aks", "create", "--resource-group", config["AKS_RESOURCE_GROUP"], "--name", config["AKS_CLUSTER_NAME"],
              "--node-resource-group", config["AKS_NODE_RESOURCE_GROUP"], "--location", LOCATION,
              "--kubernetes-version", VERSION, "--node-count", "2", "--node-vm-size", "Standard_D2s_v4",
              "--node-osdisk-size", "30", "--tier", "free", "--auto-upgrade-channel", "none",
              "--node-os-upgrade-channel", "None", "--enable-aad", "--aad-tenant-id", config["AZURE_TENANT_ID"],
              "--enable-azure-rbac", "--disable-local-accounts", "--enable-managed-identity", "--enable-oidc-issuer",
              "--enable-workload-identity", "--network-plugin", "azure", "--network-plugin-mode", "overlay",
              "--network-dataplane", "cilium", "--no-ssh-key", "--tags", "ada-repository-id=" + cleanup.REPOSITORY_ID,
              "ada-purpose=" + cleanup.PURPOSE, "ada-run-id=" + config["GITHUB_RUN_ID"],
              "ada-run-attempt=" + config["GITHUB_RUN_ATTEMPT"], "ada-expires-at=" + expiry, "--no-wait", mutation=True)


def owned(config, cloud):
    item = cloud.cluster()
    if item is None:
        raise ValueError("owned cluster not present")
    metadata = cleanup.cluster_metadata(item, config)
    if (metadata["runID"], metadata["runAttempt"]) != (config["GITHUB_RUN_ID"], config["GITHUB_RUN_ATTEMPT"]):
        raise ValueError("another run owns the target")
    return item


def wait(config, cloud, clock, sleep=time.sleep):
    while True:
        clock.remaining()
        item = owned(config, cloud)
        state = item.get("provisioningState")
        if state == "Succeeded":
            return
        if state not in ("Creating", "Updating"):
            raise ValueError("cluster provisioning failed or is unknown")
        sleep(min(5, clock.remaining()))


def federate(config, cloud):
    item = owned(config, cloud)
    if item.get("provisioningState") != "Succeeded":
        raise ValueError("cluster is not ready for federation")
    credentials = cloud.fics()
    cleanup.credential_metadata(credentials, config, item)
    if not credentials:
        # Shared lock plus a second lineage/read boundary: never replace unknown trust.
        if owned(config, cloud) != item or cloud.fics() != []:
            raise ValueError("federation lineage changed")
        cloud.run("identity", "federated-credential", "create", "--resource-group", config["AKS_IDENTITY_RESOURCE_GROUP"],
                  "--identity-name", config["AKS_MODEL_IDENTITY_NAME"], "--name", cleanup.FIC_NAME,
                  "--issuer", item["issuer"], "--subject", cleanup.HOST_SUBJECT,
                  "--audiences", "api://AzureADTokenExchange", mutation=True)
    if cleanup.credential_metadata(cloud.fics(), config, owned(config, cloud)) is None:
        raise ValueError("federation creation not confirmed")


def credentials(config, cloud, kubeconfig):
    owned(config, cloud)
    path = Path(kubeconfig)
    if not path.is_absolute() or path.exists() or not path.parent.is_dir() or path.parent.is_symlink():
        raise ValueError("fresh private kubeconfig path required")
    cloud.run("aks", "get-credentials", "--resource-group", config["AKS_RESOURCE_GROUP"], "--name", config["AKS_CLUSTER_NAME"],
              "--file", str(path), "--context", "aks-nightly", mutation=True)
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
        raise ValueError("kubeconfig must be private")
    command(["kubelogin", "convert-kubeconfig", "--login", "azurecli", "--kubeconfig", str(path)],
            timeout=min(25, cloud.clock.remaining()))
    client_id = cloud.run("identity", "show", "--resource-group", config["AKS_IDENTITY_RESOURCE_GROUP"],
                          "--name", config["AKS_MODEL_IDENTITY_NAME"], "--query", "clientId")
    if not isinstance(client_id, str) or not cleanup.GUID.fullmatch(client_id):
        raise ValueError("invalid model identity")
    return client_id


def teardown(config, cloud, clock):
    try:
        result = cleanup.cleanup(config, cloud, datetime.now(timezone.utc), apply=True,
                                 owned_run=(config["GITHUB_RUN_ID"], config["GITHUB_RUN_ATTEMPT"]),
                                 wait_seconds=min(360, clock.remaining(cleanup=True)), node_wait_seconds=120)
        if result["status"] not in ("removed", "absent"):
            raise cleanup.CloudError("cluster deletion not confirmed")
        return result
    except (cleanup.CloudError, ValueError):
        # A bounded best-effort stop reduces compute spend; never relabel it cleanup.
        try:
            item = owned(config, cloud)
            if item.get("provisioningState") in ("Succeeded", "Failed"):
                cloud.run("aks", "stop", "--resource-group", config["AKS_RESOURCE_GROUP"],
                          "--name", config["AKS_CLUSTER_NAME"], "--no-wait", mutation=True)
        except (cleanup.CloudError, ValueError):
            pass
        raise


def interrupt(_signal, _frame):
    # Convert runner cancellation into unwinding so command() kills its group.
    raise KeyboardInterrupt


def main(argv=None):
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("mask", "preflight", "create", "wait", "federate", "tools", "credentials", "teardown"))
    args = parser.parse_args(argv)
    previous_term = signal.signal(signal.SIGTERM, interrupt)
    try:
        if args.command == "mask":
            base = cleanup.configuration(os.environ)
            if base is None:
                raise ValueError("configured identity required")
            directory = Path(os.environ["RUNNER_TEMP"]) / "aks-azure"
            directory.mkdir(mode=0o700)
            for key in cleanup.IDS + cleanup.NAMES:
                print("::add-mask::" + base[key])
            with open(os.environ["GITHUB_ENV"], "a") as output:
                output.write("AZURE_CONFIG_DIR=" + str(directory) + "\n")
            return 0
        if args.command == "teardown":
            config = cleanup.configuration(os.environ)
            if config is None:
                raise ValueError("cleanup configuration required")
            for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
                value = os.environ.get(key, "")
                if not re.fullmatch(r"[1-9][0-9]{0,19}", value):
                    raise ValueError("run identity required")
                config[key] = value
        else:
            config = configuration(os.environ, rendered_images())
        clock = None if args.command == "preflight" else Deadline(os.environ["AKS_STARTED_EPOCH"])
        cloud = Azure(config, clock, teardown=args.command == "teardown")
        if args.command == "preflight":
            preflight(config, cloud)
        elif args.command == "create":
            create(config, cloud, clock)
        elif args.command == "wait":
            wait(config, cloud, clock)
        elif args.command == "federate":
            federate(config, cloud)
        elif args.command == "tools":
            assert clock is not None
            command(["bash", str(ROOT / "ops/aks/tools.sh")], timeout=clock.remaining())
            tools = Path(os.environ["RUNNER_TEMP"]) / "aks-nightly-tools"
            os.environ["PATH"] = str(tools) + os.pathsep + os.environ.get("PATH", "")
            # Run in this process so cancellation unwinds the scanner session
            # before this process exits; nested detached process groups could leak.
            decisions = tool_audit.audit_tools(tools, clock.remaining)
            tool_audit.write_report(decisions, Path(os.environ["RUNNER_TEMP"]) / "aks-tool-report",
                                    os.environ.get("GITHUB_STEP_SUMMARY"))
            for decision in decisions:
                print(json.dumps(decision, sort_keys=True))
            if tool_audit.integrity_failed(decisions):
                raise CloudError("runner tool integrity check failed")
        elif args.command == "credentials":
            model = credentials(config, cloud, os.environ["KUBECONFIG"])
            with open(os.environ["GITHUB_ENV"], "a") as output:
                output.write("MODEL_CLIENT_ID=" + model + "\n")
        else:
            result = teardown(config, cloud, clock)
            print(json.dumps(result))
            return 0
        print(json.dumps({"stage": args.command, "status": "passed"}))
        return 0
    except (cleanup.CloudError, ValueError, KeyError, OSError, KeyboardInterrupt):
        print(json.dumps({"stage": args.command, "status": "failed-closed"}), file=sys.stderr)
        return 1
    finally:
        signal.signal(signal.SIGTERM, previous_term)


if __name__ == "__main__":
    sys.exit(main())
