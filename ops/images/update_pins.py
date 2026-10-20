"""Validate a trusted publication manifest and change only the chart's image pins."""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import tempfile

REPOSITORIES = {
    "host": "ghcr.io/azure/aks-durable-agents/host",
    "harness": "ghcr.io/azure/aks-durable-agents/session-fixture",
}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path):
    return json.loads(path.read_text(), object_pairs_hook=unique_object)


def validate_manifest(data):
    if not isinstance(data, dict) or set(data) != {"version", "sourceCommit", "images"}:
        raise ValueError("manifest requires version, sourceCommit and images only")
    if type(data["version"]) is not int or data["version"] != 1:
        raise ValueError("manifest version must be 1")
    if not isinstance(data["sourceCommit"], str) or not re.fullmatch(r"[0-9a-f]{40}", data["sourceCommit"]):
        raise ValueError("manifest requires a full source commit SHA")
    images = data["images"]
    if not isinstance(images, dict) or set(images) != set(REPOSITORIES):
        raise ValueError("manifest requires exactly host and harness images")
    for role, repository in REPOSITORIES.items():
        image = images[role]
        if not isinstance(image, dict) or set(image) != {"repository", "digest"}:
            raise ValueError(f"{role} requires repository and digest only")
        if image["repository"] != repository:
            raise ValueError(f"unexpected {role} repository")
        if not isinstance(image["digest"], str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", image["digest"]):
            raise ValueError(f"invalid {role} digest")
    return data


def validate_run(run, manifest):
    expected = {"path": ".github/workflows/images.yml", "event": "push", "head_branch": "main", "head_sha": manifest["sourceCommit"], "conclusion": "success"}
    if not isinstance(run, dict) or any(run.get(key) != value for key, value in expected.items()):
        raise ValueError("publication must be a successful images.yml push run on main matching sourceCommit")
    if not isinstance(run.get("repository"), dict) or run["repository"].get("full_name") != "Azure/aks-durable-agents":
        raise ValueError("publication belongs to another repository")


def render_values(text, manifest):
    # Keep comments and unrelated operator inputs byte-for-byte, without a YAML
    # dependency or a whole-file serialization. Refuse schema/layout drift.
    lines = text.splitlines(keepends=True)
    in_images = False
    roots = 0
    role = None
    roles = []
    seen = set()
    for i, line in enumerate(lines):
        if re.fullmatch(r"image:\s*\n?", line):
            roots += 1
            in_images = True
            role = None
            continue
        if not in_images:
            continue
        if line.strip() and not line[0].isspace() and not line.startswith("#"):
            in_images = False
            continue
        child = re.fullmatch(r"  (host|harness):\s*\n?", line)
        if child:
            role = child[1]
            roles.append(role)
            continue
        field = re.fullmatch(r"    (repository|digest|includesHealthProbe):[^\n]*\n?", line)
        if not field:
            continue
        key = field[1]
        identity = (role, key)
        if identity in seen or role not in REPOSITORIES or (role == "harness" and key == "includesHealthProbe"):
            raise ValueError("ambiguous image values layout")
        seen.add(identity)
        value = "true" if key == "includesHealthProbe" else json.dumps(manifest["images"][role][key])
        lines[i] = f"    {key}: {value}\n"
    expected = {(role, key) for role in REPOSITORIES for key in ("repository", "digest")} | {("host", "includesHealthProbe")}
    if roots != 1 or roles != ["host", "harness"] or seen != expected:
        raise ValueError("expected exactly the chart's host/harness image fields")
    return "".join(lines)


def update_values(path, manifest):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("values must be a regular non-symlink file")
    original = path.read_text()
    updated = render_values(original, manifest)
    if updated == original:
        return
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, prefix=".image-pins-", delete=False) as output:
            temporary = Path(output.name)
            os.fchmod(output.fileno(), stat.S_IMODE(info.st_mode))
            output.write(updated)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["update", "validate-run"])
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--values", type=Path)
    parser.add_argument("--run", type=Path)
    args = parser.parse_args()
    try:
        manifest = validate_manifest(load_json(args.manifest))
        if args.command == "update":
            if args.values is None:
                raise ValueError("update requires --values")
            update_values(args.values, manifest)
        else:
            if args.run is None:
                raise ValueError("validate-run requires --run")
            validate_run(load_json(args.run), manifest)
            print(manifest["sourceCommit"])
    except (OSError, ValueError) as error:
        parser.exit(1, f"image pins: {error}\n")


if __name__ == "__main__":
    main()
