"""Build pinned Substrate contexts and validate the separate publication handoff."""
import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from datetime import datetime
from pathlib import Path
from urllib.parse import quote, quote_plus, urlsplit

import yaml
from update_pins import load_json, unique_object
from update_pins import validate_run as validate_host_run

SUBSTRATE_COMMIT = "e8d40c33f96f4b7a4984bfea7334a36ab5b45b7b"
PAUSE_COMMIT = "f54c212e3a2f75d674b717a9b29052b20b60aefc"
MODULE = "github.com/agent-substrate/substrate/"
GO_PACKAGES = {role: "cmd/" + role for role in (
    "ateapi", "atecontroller", "atelet", "atenet", "ateom-gvisor", "objectstore-plugin", "podcertcontroller")}
GO_PACKAGES["counter"] = "demos/counter"
ROLES = (*GO_PACKAGES, "envoy-dataplane", "pause")
PREFIX = "ghcr.io/azure/aks-durable-agents/substrate-"
IDENTITY = "https://github.com/Azure/aks-durable-agents/.github/workflows/images.yml@refs/heads/main"
ISSUER = "https://token.actions.githubusercontent.com"
STATIC_BASE = "gcr.io/distroless/static-debian13:latest@sha256:f2ea2709ac8db56323cbd7d014277f32cb572d9ea124b0076f7aafe5980678fe"
ATELET_BASE = "gcr.io/distroless/base-debian13:latest@sha256:389cad21f73e4c37b94ffe5b13736d5a92bd5bd3c6c6b38c2be1c881e14ba2bd"
GCC_BASE = "gcc:14.3.0@sha256:ccf38976f2c7d682841165bf5da334c6e48c89550f7ebf2ac8b8c06f307f4f79"
PAUSE_KEY = "registry.k8s.io/pause:3.10.2@sha256:f548e0e8e3dc1896ca956272154dde3314e8cc4fde0a57577ee9fa1c63f5baf4"
UPSTREAM = {
    "postgres:18-alpine@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15": "docker.io/library/",
    "rustfs/rustfs:1.0.0-beta.3@sha256:378642b05b7dcb4849fb77ebe6aca4ced1c3f66e7e504247df95a5c9018d3358": "docker.io/",
    "amazon/aws-cli:2.17.0@sha256:643507c10ada7964ca6157b3d799f030b90577643da9955d319a77399ed80d73": "docker.io/",
    "envoyproxy/envoy:v1.39.4@sha256:74bd4eb5629708d3fadca1a5e6b85d208f338d7bb54e06b69565905c5294cc01": "docker.io/",
}
PROBE = "docker.io/library/python@sha256:79e7a9b9ff1cbceff819f856fb374477792a5967759d94df266de7b7b4120e6f"


def command(argv, *, timeout, cwd=None, env=None):
    # Capture raw output here; only the CLI's bounded redactor may report it.
    return subprocess.run(argv, timeout=timeout, cwd=cwd, env=env, check=True,
                          capture_output=True, text=True).stdout


def command_diagnostic(error):
    """Keep actionable tool failures, without arguments, credentials or workflow commands."""
    argv = error.cmd if isinstance(getattr(error, "cmd", None), (list, tuple)) else []
    tool = Path(str(argv[0])).name if argv else "external"
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", tool):
        tool = "external"
    operations = {"go": {"build", "version"}, "docker": {"pull", "create", "start", "inspect", "cp", "rm", "buildx"},
                  "cosign": {"sign", "verify"}, "git": {"rev-parse", "status", "show"}}
    operation = next((arg for arg in argv[1:] if isinstance(arg, str) and arg in operations.get(tool, set())), None)
    report = {"operation": tool + (" " + operation if operation else "")}
    if isinstance(error, subprocess.TimeoutExpired):
        report["timeoutSeconds"] = error.timeout
    elif isinstance(error, subprocess.CalledProcessError):
        report["exitStatus"] = error.returncode
    secrets = {value for key, value in os.environ.items() if value and re.search(r"TOKEN|SECRET|PASSWORD|CREDENTIAL|KEY", key, re.IGNORECASE)}

    def scrub(value):
        text = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value or ""
        for secret in sorted(secrets, key=len, reverse=True):
            for form in (secret, quote(secret, safe=""), quote_plus(secret)):
                text = text.replace(form, "[REDACTED]")
        text = re.sub(r'''(?i)(?:\bauthorization\s*[:=]\s*(?:bearer|basic)|\bbearer)\s+[^\s"'<>]+''', "Authorization [REDACTED]", text)
        text = re.sub(r"(?i)(https?://)[^\s/@]+@", r"\1[REDACTED]@", text)
        text = re.sub(r'''(?i)(\b(?:access[_-]?token|refresh[_-]?token|id[_-]?token|token|password|secret|credential|(?:api|access|private)[_-]?key)["']?\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;}]+)''', r"\1[REDACTED]", text)
        text = re.sub(r"\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", "[REDACTED]", text)
        text = re.sub(r"\b(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{16,}\b", "[REDACTED]", text)
        text = text.replace("::", ": :")
        return ("[truncated]\n" + text[-4096:]) if len(text) > 4096 else text

    report["stdout"] = scrub(getattr(error, "stdout", None))
    report["stderr"] = scrub(getattr(error, "stderr", None))
    return json.dumps(report, ensure_ascii=True)


def role_check(role):
    if role not in ROLES:
        raise ValueError("unknown Substrate image role")


def revision_check(revision):
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("full lowercase workflow commit required")


def image_ref(role, image, *, digest_only=False):
    role_check(role)
    suffix = r"@sha256:[0-9a-f]{64}" if digest_only else r"(?:@sha256:[0-9a-f]{64}|:sha-[0-9a-f]{40})"
    if not isinstance(image, str) or not re.fullmatch(re.escape(PREFIX + role) + suffix, image):
        raise ValueError("unexpected image repository, role or immutable reference")
    return image


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique_object)


def write_json(path, data):
    # A failed write must not leave a partial receipt that looks publishable.
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, prefix=".substrate-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(json.dumps(data, indent=2) + "\n")
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def source_identity(source, expected, run):
    if run(["git", "-C", str(source), "rev-parse", "HEAD"], timeout=15).strip() != expected:
        raise ValueError("wrong pinned source revision")
    if run(["git", "-C", str(source), "status", "--porcelain", "--untracked-files=all"], timeout=15).strip():
        raise ValueError("source checkout must be clean")
    epoch = run(["git", "-C", str(source), "show", "-s", "--format=%ct", "HEAD"], timeout=15).strip()
    if not re.fullmatch(r"[0-9]{1,12}", epoch):
        raise ValueError("invalid source commit epoch")
    return epoch


def prepare(role, source, pause_source, output, revision, *, run=command):
    role_check(role)
    revision_check(revision)
    source = Path(pause_source if role == "pause" else source).resolve()
    epoch = source_identity(source, PAUSE_COMMIT if role == "pause" else SUBSTRATE_COMMIT, run)
    context = Path(output).resolve() / role
    if context.exists():
        raise FileExistsError("build context must be fresh")
    base = None
    if role in GO_PACKAGES:
        config = yaml.safe_load((source / ".ko.yaml").read_text())
        if (config.get("defaultBaseImage") != STATIC_BASE or
                config.get("baseImageOverrides", {}).get(MODULE + "cmd/atelet") != ATELET_BASE):
            raise ValueError("pinned ko base configuration changed")
        base = ATELET_BASE if role == "atelet" else STATIC_BASE
    elif role == "pause":
        base = GCC_BASE
        if not re.search(r"(?m)^TAG\s*\??=\s*3\.10\.2\s*$", (source / "build/pause/Makefile").read_text()):
            raise ValueError("pause source TAG mismatch")
    context.parent.mkdir(parents=True, exist_ok=True)
    if role == "envoy-dataplane":
        shutil.copytree(source / "cmd/dataplane/envoy", context)
    else:
        context.mkdir()
        if role == "pause":
            shutil.copyfile(source / "build/pause/linux/pause.c", context / "pause.c")
            dockerfile = (f"FROM {GCC_BASE} AS builder\nCOPY pause.c /pause.c\n"
                          f"RUN gcc -Os -Wall -Werror -static -s -DVERSION=v3.10.2-{PAUSE_COMMIT} -o /pause /pause.c\n"
                          'FROM scratch\nCOPY --from=builder /pause /pause\nUSER 65535:65535\nENTRYPOINT ["/pause"]\n')
        else:
            env = dict(os.environ, CGO_ENABLED="0", GOOS="linux", GOARCH="amd64", GOTOOLCHAIN="go1.27.3",
                       GOFLAGS="", GOWORK="off")
            flags = f"-X={MODULE}internal/version.Version=v0.5.0 -X={MODULE}internal/version.Commit={SUBSTRATE_COMMIT}"
            run(["go", "build", "-mod=vendor", "-trimpath", "-buildvcs=true", "-ldflags", flags,
                 "-o", str(context / role), "./" + GO_PACKAGES[role]], cwd=source, env=env, timeout=900)
            kodata = source / GO_PACKAGES[role] / "kodata"
            if kodata.is_dir():
                shutil.copytree(kodata, context / "kodata")
            else:
                (context / "kodata").mkdir()
            dockerfile = (f"FROM {base}\nCOPY {role} /ko-app/{role}\nCOPY kodata/ /var/run/ko/\n"
                          f'ENV KO_DATA_PATH=/var/run/ko\nUSER 0\nENTRYPOINT ["/ko-app/{role}"]\n')
        (context / "Dockerfile").write_text(dockerfile)
    write_json(context / "input-pins.json", {"role": role, "substrateCommit": SUBSTRATE_COMMIT,
                                            "pauseCommit": PAUSE_COMMIT, "base": base})
    return {"context": str(context), "file": str(context / "Dockerfile"), "epoch": epoch,
            "image": PREFIX + role + ":sha-" + revision}


def smoke(role, image, *, run=command):
    image_ref(role, image)
    if "@" in image:
        run(["docker", "pull", image], timeout=300)
    name = "substrate-smoke-" + uuid.uuid4().hex
    args = ["-v"] if role == "pause" else ["--version"] if role == "envoy-dataplane" else ["--help"]
    if role == "objectstore-plugin":
        args = ["node", "--help"]
    try:
        run(["docker", "create", "--name", name, "--network", "none", image, *args], timeout=30)
        result = run(["docker", "start", "--attach", name], timeout=30)
        if run(["docker", "inspect", "--format", "{{.State.ExitCode}}", name], timeout=15).strip() != "0":
            raise ValueError("image smoke command exited unsuccessfully")
        if role == "pause" and "v3.10.2-" + PAUSE_COMMIT not in result:
            raise ValueError("pause version mismatch")
        with tempfile.TemporaryDirectory(prefix="substrate-packaged-") as directory:
            binary = Path(directory) / role
            if role in GO_PACKAGES:
                run(["docker", "cp", name + ":/ko-app/" + role, str(binary)], timeout=30)
                metadata = run(["go", "version", "-m", str(binary)], timeout=30)
                fields = [line.strip().split("\t") for line in metadata.splitlines()]
                if (["path", MODULE + GO_PACKAGES[role]] not in fields or
                        ["build", "vcs.revision=" + SUBSTRATE_COMMIT] not in fields or
                        ["build", "vcs.modified=false"] not in fields):
                    raise ValueError("packaged Go binary provenance mismatch")
                run(["govulncheck", "-mode=binary", str(binary)], timeout=300)
            elif role == "envoy-dataplane":
                run(["docker", "cp", name + ":/usr/local/lib/libenvoy_substrate_egress_policy.so", str(binary)], timeout=30)
                if not binary.is_file() or binary.stat().st_size == 0:
                    raise ValueError("Envoy dynamic module missing")
    finally:
        run(["docker", "rm", "-f", name], timeout=30)


def verify_sbom(role, data):
    role_check(role)
    if isinstance(data, dict) and set(data) == {"linux/amd64"}:
        data = data["linux/amd64"]
    if not isinstance(data, dict):
        raise ValueError("SPDX document required")  # noqa: TRY004 - external document validation
    creation = data.get("creationInfo")
    namespace = data.get("documentNamespace")
    if (data.get("SPDXID") != "SPDXRef-DOCUMENT" or data.get("spdxVersion") not in ("SPDX-2.2", "SPDX-2.3")
            or data.get("dataLicense") != "CC0-1.0" or not isinstance(data.get("name"), str) or not data["name"].strip()
            or not isinstance(namespace, str) or re.search(r"\s", namespace) or urlsplit(namespace).scheme not in ("http", "https")
            or not urlsplit(namespace).netloc or urlsplit(namespace).fragment
            or not isinstance(creation, dict) or not isinstance(creation.get("creators"), list)
            or not creation["creators"] or any(not isinstance(c, str) or not re.fullmatch(r"(?:Tool|Person|Organization): .+", c) for c in creation["creators"])
            or not isinstance(creation.get("created"), str)
            or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", creation["created"])):
        raise ValueError("invalid SPDX document metadata")
    datetime.fromisoformat(creation["created"])
    packages = data.get("packages", [])
    if (not isinstance(packages, list) or (not packages and role != "pause") or
            any(not isinstance(p, dict) or not isinstance(p.get("name"), str) or not p["name"].strip()
                or not isinstance(p.get("SPDXID"), str) or not re.fullmatch(r"SPDXRef-[A-Za-z0-9.-]+", p["SPDXID"])
                or not isinstance(p.get("downloadLocation"), str) or not p["downloadLocation"] for p in packages)):
        raise ValueError("invalid or missing SPDX package inventory")
    return data


def record(role, digest, revision, output, *, env=None, run=command):
    revision_check(revision)
    role_check(role)
    env = os.environ if env is None else env
    expected = {"GITHUB_EVENT_NAME": "push", "GITHUB_REPOSITORY": "Azure/aks-durable-agents",
                "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": revision}
    if any(env.get(k) != v for k, v in expected.items()):
        raise ValueError("publication requires canonical main push matching workflow revision")
    image = image_ref(role, PREFIX + role + "@" + digest, digest_only=True)
    output = Path(output)
    if (output / (role + ".receipt.json")).exists():
        raise FileExistsError("refusing to overwrite publication receipt")
    smoke(role, image, run=run)
    run(["cosign", "sign", "--yes", image], timeout=300)
    signature = decode(run(["cosign", "verify", "--certificate-identity", IDENTITY,
                            "--certificate-oidc-issuer", ISSUER, image], timeout=120))
    attached = decode(run(["docker", "buildx", "imagetools", "inspect", image,
                           "--format", "{{json .SBOM.SPDX}}"], timeout=120))
    sbom = verify_sbom(role, attached)
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / (role + "-signature.json"), signature)
    write_json(output / (role + "-sbom.json"), sbom)
    write_json(output / (role + ".receipt.json"), {"version": 1, "workflowCommit": revision,
               "substrateCommit": SUBSTRATE_COMMIT, "pauseCommit": PAUSE_COMMIT, "role": role, "image": image})


def validate_identity(data, revision=None):
    revision_check(data["workflowCommit"])
    if (type(data["version"]) is not int or data["version"] != 1 or data["substrateCommit"] != SUBSTRATE_COMMIT
            or data["pauseCommit"] != PAUSE_COMMIT or (revision is not None and data["workflowCommit"] != revision)):
        raise ValueError("publication source or workflow identity mismatch")


def validate_publication(data, revision=None):
    keys = {"version", "workflowCommit", "substrateCommit", "pauseCommit", "images"}
    if not isinstance(data, dict) or set(data) != keys:
        raise ValueError("unexpected publication fields")
    validate_identity(data, revision)
    if not isinstance(data["images"], dict) or set(data["images"]) != set(ROLES):
        raise ValueError("publication role set mismatch")
    for role, image in data["images"].items():
        image_ref(role, image, digest_only=True)
    return data


def installer_map(publication):
    validate_publication(publication)
    refs = publication["images"]
    mapping = {"ko://" + MODULE + package: refs[role] for role, package in GO_PACKAGES.items()}
    mapping.update({"${ENVOY_DATAPLANE_IMAGE}": refs["envoy-dataplane"], PAUSE_KEY: refs["pause"], "probe": PROBE})
    mapping.update({key: prefix + key for key, prefix in UPSTREAM.items()})
    return {"sourceCommit": SUBSTRATE_COMMIT, "images": mapping}


def collect(receipts, revision, output):
    revision_check(revision)
    paths = list(Path(receipts).glob("*.receipt.json"))
    if {p.name for p in paths} != {role + ".receipt.json" for role in ROLES}:
        raise ValueError("exactly ten known role receipts required")
    owned = {}
    for path in paths:
        data = load_json(path)
        if not isinstance(data, dict) or set(data) != {"version", "workflowCommit", "substrateCommit", "pauseCommit", "role", "image"}:
            raise ValueError("unexpected receipt fields")
        role = data["role"]
        role_check(role)
        if path.name != role + ".receipt.json" or role in owned:
            raise ValueError("receipt role/filename mismatch or duplicate role")
        validate_identity(data, revision)
        owned[role] = image_ref(role, data["image"], digest_only=True)
    publication = validate_publication({"version": 1, "workflowCommit": revision, "substrateCommit": SUBSTRATE_COMMIT,
                                        "pauseCommit": PAUSE_COMMIT, "images": owned}, revision)
    mapping = installer_map(publication)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "substrate-publication.json", publication)
    write_json(output / "substrate-images.json", mapping)


def refs(publication, mapping):
    expected = installer_map(publication)
    if mapping != expected:
        raise ValueError("installer map differs from exact validated publication map")
    result = list(publication["images"].items())
    result += [("upstream-" + role, expected["images"][key]) for role, key in zip(
        ("postgres", "rustfs", "aws-cli", "envoy-router"), UPSTREAM)]
    return result + [("upstream-probe", PROBE)]


def validate_run(publication, mapping, run):
    refs(publication, mapping)
    validate_host_run(run, {"sourceCommit": publication["workflowCommit"]})


def main(argv=None, *, run=command):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    options = {
        "prepare": ("role", "source", "pause-source", "output", "revision", "github-output"),
        "smoke": ("role", "image"), "record": ("role", "digest", "revision", "output"),
        "collect": ("receipts", "revision", "output"),
        "validate-run": ("publication", "map", "run"), "refs": ("publication", "map"),
        "verify-sbom": ("role", "input")}
    for command_name, fields in options.items():
        command_parser = commands.add_parser(command_name)
        for field in fields:
            if field == "role":
                command_parser.add_argument("--" + field, required=True, choices=ROLES)
            elif field in ("source", "pause-source", "output", "github-output", "receipts", "publication", "map", "run", "input"):
                command_parser.add_argument("--" + field, required=True, type=Path)
            else:
                command_parser.add_argument("--" + field, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            outputs = prepare(args.role, args.source, args.pause_source, args.output, args.revision, run=run)
            if any("\n" in value or "\r" in value for value in outputs.values()):
                raise ValueError("unsafe GitHub output path")
            with args.github_output.open("a") as stream:
                stream.write("".join(f"{key}={value}\n" for key, value in outputs.items()))
        elif args.command == "smoke":
            smoke(args.role, args.image, run=run)
        elif args.command == "record":
            record(args.role, args.digest, args.revision, args.output, run=run)
        elif args.command == "collect":
            collect(args.receipts, args.revision, args.output)
        elif args.command == "verify-sbom":
            verify_sbom(args.role, load_json(args.input))
        else:
            publication, mapping = load_json(args.publication), load_json(args.map)
            if args.command == "validate-run":
                validate_run(publication, mapping, load_json(args.run))
                print(publication["workflowCommit"])
            else:
                for role, ref in refs(publication, mapping):
                    print(role + "\t" + ref)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        detail = command_diagnostic(error) if isinstance(error, subprocess.SubprocessError) else str(error)
        parser.exit(1, "Substrate images: " + detail + "\n")


if __name__ == "__main__":
    main()
