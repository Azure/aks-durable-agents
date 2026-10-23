#!/usr/bin/env python3
"""Closed scenario selection and verified input preparation BEFORE provisioning."""
import argparse
import json
import os
import re
import subprocess
import sys
import tarfile
import time
from pathlib import Path

REPO = "Azure/aks-durable-agents"
IDENTITY = "https://github.com/" + REPO + "/.github/workflows/images.yml@refs/heads/main"
ROOT = Path(__file__).resolve().parents[2]


def selection(env):
    if env.get("EVENT_NAME") == "schedule":
        if env.get("EVENT_SCHEDULE") == "43 5 * * *":
            return "no-sandbox"
        if env.get("EVENT_SCHEDULE") != "17 8 * * 1,3,5" or env.get("AKS_SUBSTRATE_ENABLED") != "true":
            raise ValueError("unknown or disabled scheduled variant")
        return "substrate-gvisor"
    variant = env.get("VARIANT") or "no-sandbox"
    if variant not in ("no-sandbox", "substrate-gvisor"):
        raise ValueError("unknown scenario variant")
    if variant == "substrate-gvisor" and (env.get("EVENT_NAME") != "workflow_dispatch" or env.get("RUN_SCENARIO") != "true" or env.get("AKS_SUBSTRATE_ENABLED") != "true" or any(not re.fullmatch(r"[1-9][0-9]{0,19}", env.get(k, "")) for k in ("PUBLISH_RUN_ID", "VERIFY_RUN_ID"))):
        raise ValueError("actor scenario requires explicit manual approval and publication/verification runs")
    return variant


def verified_run(run, expected):
    if (type(run.get("id")) is not int or str(run["id"]) != expected or run.get("status") != "completed" or run.get("conclusion") != "success" or run.get("head_branch") != "main" or run.get("event") not in ("workflow_run", "workflow_dispatch") or run.get("path") != ".github/workflows/image-pins.yml" or any(run.get(k, {}).get("full_name") != REPO for k in ("repository", "head_repository"))):
        raise ValueError("verified image artifact must be from successful canonical main verification")


def actor_capability(value):
    fixed = {"version": 1, "mode": "actor-v2", "harness": "release-notes", "protocol": "harnesswire", "port": 80, "resumability": "STATELESS_REPLAY", "readinessPort": 8081, "readinessPath": "/readyz"}
    if type(value) is not dict or value.keys() != {*fixed, "descriptor"} or any(type(value[k]) is not type(v) or value[k] != v for k, v in fixed.items()) or not isinstance(value["descriptor"], str) or not re.fullmatch(r"release-v2-real-model-[0-9a-f]{64}", value["descriptor"]):
        raise ValueError("published harness lacks the frozen actor entrypoint")


def capability_command(image):
    return ["docker", "run", "--rm", "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--entrypoint", "/session-fixture", image, "actor-harness", "--check"]


def prepare(output, source, publish_id, verify_id, *, scheduled=False):
    # Imports stay lazy: config selection needs only stdlib and no credentials.
    sys.path[:0] = [str(ROOT), str(ROOT / "ops/images"), str(ROOT / "ops/aks")]
    import lifecycle
    import tool_audit
    from substrate_schedule import EvidenceError, resolve

    from ops.images import substrate_images, update_pins

    if scheduled and (publish_id or verify_id):
        raise ValueError("scheduled evidence cannot override the reviewed source")
    if not scheduled and any(not re.fullmatch(r"[1-9][0-9]{0,19}", value) for value in (publish_id, verify_id)):
        raise ValueError("explicit image run IDs required")
    if not source.is_absolute() or source.resolve() != source or not source.is_dir() or not output.is_absolute() or output.parent.resolve() != output.parent:
        raise ValueError("explicit clean source/output paths required")
    output.mkdir(mode=0o700)
    end = time.monotonic() + 840
    env = dict(os.environ, DOCKER_CONFIG=str(output / "anonymous-docker"), GOTOOLCHAIN="go1.27.3")
    Path(env["DOCKER_CONFIG"]).mkdir(mode=0o700)

    def command(args, *, cwd=None, limit=300):
        left = end - time.monotonic()
        if left <= 0:
            raise ValueError("preparation deadline exhausted before provisioning")
        result = subprocess.run([str(v) for v in args], cwd=cwd, env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=min(limit, left), check=False)
        if result.returncode or len(result.stdout) > 4 * 1024 * 1024:
            raise ValueError("prepaid input command failed")
        return result.stdout

    expected_source = None
    try:
        if scheduled:
            manifest = json.loads(env.get("PUBLISHED_IMAGES", ""), object_pairs_hook=update_pins.unique_object)
            publish_id, verify_id, expected_source = resolve(manifest, command, end)
        publication_run = json.loads(command(["gh", "api", "repos/" + REPO + "/actions/runs/" + publish_id]))
        verification_run = json.loads(command(["gh", "api", "repos/" + REPO + "/actions/runs/" + verify_id]))
        verified_run(verification_run, verify_id)
        for run, artifact, folder in ((publish_id, "published-substrate-images", "published"), (verify_id, "verified-substrate-images", "verified")):
            command(["gh", "run", "download", run, "--repo", REPO, "--name", artifact, "--dir", output / folder])
        def read(folder, filename):
            return json.loads((output / folder / filename).read_bytes())
        publication, mapping = read("published", "substrate-publication.json"), read("published", "substrate-images.json")
        substrate_images.validate_publication(publication)
        substrate_images.validate_run(publication, mapping, publication_run)
        if (publication != read("verified", "substrate-publication.json") or mapping != read("verified", "substrate-images.json")
                or scheduled and publication["workflowCommit"] != expected_source):
            raise ValueError("verified artifact differs from exact publishing run or reviewed source")
    except (ValueError, OSError, subprocess.TimeoutExpired):
        if scheduled:
            raise EvidenceError() from None
        raise
    for role, ref in substrate_images.refs(publication, mapping):
        command(["docker", "pull", "--platform", "linux/amd64", ref])
        if role.startswith("upstream-"):
            continue
        command(["cosign", "verify", "--certificate-identity", IDENTITY, "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com", ref])
        sbom = json.loads(command(["docker", "buildx", "imagetools", "inspect", ref, "--format", "{{json .SBOM.SPDX}}"] ))
        substrate_images.verify_sbom(role, sbom)
    pins = lifecycle.rendered_images()
    config = lifecycle.configuration(os.environ, pins)
    for ref in (*pins.values(), config["BACKUP_HELPER_IMAGE"]):
        command(["docker", "pull", "--platform", "linux/amd64", ref])
        command(["cosign", "verify", "--certificate-identity", IDENTITY, "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com", ref])
    actor_capability(json.loads(command(capability_command(pins["harness"]))))
    if command(["git", "-C", source, "rev-parse", "HEAD"]).decode().strip() != substrate_images.SUBSTRATE_COMMIT or command(["git", "-C", source, "status", "--porcelain", "--untracked-files=all"]).strip():
        raise ValueError("native tools require clean exact pinned source")
    tools = output / "native-tools"
    tools.mkdir(mode=0o700)
    flags = "-X github.com/agent-substrate/substrate/internal/version.Version=v0.5.0 -X github.com/agent-substrate/substrate/internal/version.Commit=" + substrate_images.SUBSTRATE_COMMIT
    runner_tools = Path(os.environ["RUNNER_TEMP"]) / "aks-nightly-tools"
    for name in ("ate-setup", "kubectl-ate"):
        command(["go", "build", "-mod=vendor", "-trimpath", "-buildvcs=true", "-ldflags", flags, "-o", tools / name, "./cmd/" + name], cwd=source)
        metadata = command(["go", "version", "-m", tools / name]).decode()
        if "vcs.revision=" + substrate_images.SUBSTRATE_COMMIT not in metadata or "vcs.modified=false" not in metadata:
            raise ValueError("native binary source provenance mismatch")
        command([runner_tools / "govulncheck", "-mode=binary", tools / name])
    decisions = tool_audit.audit_tools(runner_tools, lambda: max(.001, end - time.monotonic()))
    tool_audit.write_report(decisions, Path(os.environ["RUNNER_TEMP"]) / "aks-tool-report")
    if tool_audit.integrity_failed(decisions):
        raise ValueError("runner tool integrity failed before provisioning")
    python_deps = output / "python-deps"
    command([sys.executable, "-m", "pip", "install", "--disable-pip-version-check", "--only-binary=:all:", "--no-deps", "--no-compile", "--target", python_deps, "-r", ROOT / "charts/aks-durable-agents/tests/requirements.txt"])
    helm = Path(command(["which", "helm"]).decode().strip()).resolve()
    goroot = Path(command(["go", "env", "GOROOT"]).decode().strip()).resolve()
    with tarfile.open(output / "prepared.tar.gz", "w:gz") as archive:
        archive.add(source, arcname="source")
        archive.add(tools, arcname="native-tools")
        archive.add(runner_tools, arcname="runner-tools")
        archive.add(helm, arcname="runner-tools/helm")
        archive.add(goroot, arcname="go-toolchain")
        archive.add(python_deps, arcname="python-deps")
        archive.add(Path(os.environ["RUNNER_TEMP"]) / "aks-tool-report", arcname="tool-report")
        for filename in ("substrate-images.json", "substrate-publication.json"):
            archive.add(output / "verified" / filename, arcname="verified/" + filename)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("select")
    prep = commands.add_parser("prepare")
    for option in ("output", "source"):
        prep.add_argument("--" + option, type=Path, required=True)
    for option in ("publish-run-id", "verify-run-id"):
        prep.add_argument("--" + option, default="")
    prep.add_argument("--scheduled", action="store_true")
    args = parser.parse_args()
    if args.command == "select":
        variant = selection(os.environ)
        print("variant=" + variant)
        print("scheduled_substrate=" + str(os.environ.get("EVENT_NAME") == "schedule" and variant == "substrate-gvisor").lower())
    else:
        from substrate_schedule import EvidenceError
        try:
            prepare(args.output, args.source, args.publish_run_id, args.verify_run_id, scheduled=args.scheduled)
        except EvidenceError as error:
            print(str(error) + " No provisioning authorized.", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, subprocess.TimeoutExpired):
        print("Substrate input preparation failed closed; no provisioning authorized.", file=sys.stderr)
        raise SystemExit(1) from None
