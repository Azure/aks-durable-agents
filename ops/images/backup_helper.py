"""Create a helper publication receipt or bind it to the rendered chart host."""
import argparse
import json
import re
from pathlib import Path

from update_pins import load_json

HOST_REPOSITORY = "ghcr.io/azure/aks-durable-agents/host"
HELPER_REPOSITORY = "ghcr.io/azure/aks-durable-agents/backup-helper"
DIGEST = r"sha256:[0-9a-f]{64}"


def validate_receipt(data):
    if not isinstance(data, dict) or set(data) != {"version", "sourceCommit", "hostDigest", "image"}:
        raise ValueError("receipt requires version, sourceCommit, hostDigest and image only")
    if type(data["version"]) is not int or data["version"] != 1:
        raise ValueError("receipt version must be 1")
    if not isinstance(data["sourceCommit"], str) or not re.fullmatch(r"[0-9a-f]{40}", data["sourceCommit"]):
        raise ValueError("receipt requires a full source commit SHA")
    if not isinstance(data["hostDigest"], str) or not re.fullmatch(DIGEST, data["hostDigest"]):
        raise ValueError("receipt requires a sha256 host digest")
    if not isinstance(data["image"], str) or not re.fullmatch(re.escape(HELPER_REPOSITORY) + "@" + DIGEST, data["image"]):
        raise ValueError("receipt requires the digest-pinned canonical backup-helper image")
    return data


def create_receipt(source_commit, host_digest, helper_digest):
    return validate_receipt({"version": 1, "sourceCommit": source_commit,
                             "hostDigest": host_digest, "image": HELPER_REPOSITORY + "@" + helper_digest})


def validate_host(data, host_image):
    """Fail before writers start unless the *rendered* chart host matches.

    Receipt shape/matching is not signature or publication-run verification;
    callers must first obtain this receipt from a trusted publication.
    """
    validate_receipt(data)
    if host_image != HOST_REPOSITORY + "@" + data["hostDigest"]:
        raise ValueError("receipt host digest does not match the rendered canonical chart host")
    return data["image"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    create.add_argument("--source-commit", required=True)
    create.add_argument("--host-digest", required=True)
    create.add_argument("--helper-digest", required=True)
    create.add_argument("--output", type=Path, required=True)
    validate = commands.add_parser("validate")
    validate.add_argument("--receipt", type=Path, required=True)
    validate.add_argument("--host-image", required=True)
    args = parser.parse_args()
    try:
        if args.command == "create":
            data = create_receipt(args.source_commit, args.host_digest, args.helper_digest)
            with args.output.open("x") as output:
                output.write(json.dumps(data, indent=2) + "\n")
        else:
            print(validate_host(load_json(args.receipt), args.host_image))
    except (OSError, ValueError) as error:
        parser.exit(1, f"backup helper: {error}\n")


if __name__ == "__main__":
    main()
