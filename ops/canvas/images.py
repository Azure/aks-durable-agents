#!/usr/bin/env python3
"""Build isolated local Canvas qualification images; never push them."""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import uuid
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PYTHON = "python:3.13-alpine@sha256:79e7a9b9ff1cbceff819f856fb374477792a5967759d94df266de7b7b4120e6f"
ALPINE = "alpine:3.23@sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0"


def check_paths(canvas, out):
    if not (canvas / "go.mod").is_file() or not (canvas / "examples/release-review/canvas.yaml").is_file():
        raise ValueError("--canvas requires a Canvas source checkout with release-review")
    if out.exists() or out.is_symlink() or out != out.resolve() or any(out.is_relative_to(p) or p.is_relative_to(out) for p in (REPO, canvas.resolve())):
        raise ValueError("--out must be a new directory outside both source checkouts")


def run(args, cwd=REPO, **kwargs):
    print("+", " ".join(map(str, args)), flush=True)
    return subprocess.run(list(map(str, args)), cwd=cwd, check=True, capture_output=True, **kwargs).stdout


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")
    path.chmod(0o600)


def materialize_definition(canvas, out, preset):
    if preset == "release-review":
        return canvas / "examples/release-review/canvas.yaml"
    if preset != "compact":
        raise ValueError("unknown definition preset")
    target = out / "definition"
    shutil.copytree(Path(__file__).parent / "fixtures/compact", target)
    # Reuse immutable released suites, not edited instructions or released pins.
    shutil.copytree(canvas / "examples/release-review/layouts", target / "layouts")
    return target / "canvas.yaml"


def build(canvas, out, preset="release-review"):
    check_paths(canvas, out)
    if run(["git", "status", "--porcelain"], cwd=canvas).strip():
        raise ValueError("Canvas source must be clean for a pinned qualification")
    out.mkdir(mode=0o700, parents=True)
    env = dict(os.environ, CGO_ENABLED="0", GOPROXY="off")
    binaries = out / "bin"
    binaries.mkdir(mode=0o700)
    for name, package, root in (
        ("host", "./ops/canvas/drillhost", REPO),
        ("production-host", "./cmd/host", REPO),
        ("netprobe", "./ops/canvas/netprobe", REPO),
        ("canvas-harness", "./cmd/canvas-harness", canvas),
        ("copilot-review", "./cmd/copilot-review", canvas),
    ):
        run(["go", "build", "-trimpath", "-o", binaries / name, package], cwd=root, env=env)
    definition = materialize_definition(canvas, out, preset)
    run([binaries / "canvas-harness", "prepare", "-definition", definition, "-out", out / "producers", "-bind", "0.0.0.0", "-base-port", "9000"], cwd=canvas)
    inventory = json.loads((out / "producers/inventory.json").read_text())
    entries = [{"id": "bundle-v4-" + Path(e["bundle"]).parent.name, "port": int(e["address"].rsplit(":", 1)[1])} for e in inventory["entries"]]
    fixtures = out / "fixtures"
    fixtures.mkdir(mode=0o700)
    recorded = canvas / "examples/release-review/evals/recorded"
    writer = {"changes": [{"document": name, "operation": "replace", "content": (recorded / "writer" / filename).read_text()} for name, filename in (("notes", "notes.json"), ("announcement", "announcement.md"))]}
    save(fixtures / "writer.json", writer)
    save(fixtures / "reviewer.json", {"changes": [{"document": "review", "operation": "replace", "content": (recorded / "reviewer/review.json").read_text()}]})
    if preset == "compact":
        for role in ("writer", "reviewer"):
            shutil.copy2(definition.parent / (role + ".json"), fixtures / (role + ".json"))
    host = out / "host-context"
    host.mkdir(mode=0o700)
    for name in ("host", "production-host", "netprobe"):
        shutil.copy2(binaries / name, host / name)
    shutil.copytree(fixtures, host / "fixtures")
    shutil.copytree(out / "producers", host / "producers")
    (host / "Dockerfile").write_text(f"FROM {PYTHON}\nCOPY --chmod=0555 host production-host netprobe /\nCOPY --chown=65532:65532 fixtures /fixtures\nCOPY --chown=65532:65532 producers /seed/producers\nENV PYTHONDONTWRITEBYTECODE=1\nUSER 65532:65532\n")
    producer = out / "producer-context"
    producer.mkdir(mode=0o700)
    shutil.copy2(binaries / "canvas-harness", producer / "canvas-harness")
    shutil.copy2(binaries / "netprobe", producer / "netprobe")
    (producer / "Dockerfile").write_text(f'FROM {ALPINE}\nRUN adduser -D -u 65532 canvas\nWORKDIR /data\nCOPY --chmod=0555 canvas-harness /usr/local/bin/canvas-harness\nCOPY --chmod=0555 netprobe /netprobe\nUSER 65532:65532\nENTRYPOINT ["canvas-harness"]\n')
    suffix = uuid.uuid4().hex[:10]
    tags = {"host": "local/canvas-drill-host:" + suffix, "producer": "local/canvas-drill-producer:" + suffix}
    for name, context in (("host", host), ("producer", producer)):
        run(["docker", "build", "--pull=false", "--network=none", "-t", tags[name], context])
    metadata = {
        "drillOnly": True, "producerHasDiagnosticProbe": True, "identityExercised": False,
        "definition": str(definition), "definitionPreset": preset,
        "definitionSHA256": hashlib.sha256(definition.read_bytes()).hexdigest(),
        "hostRevision": run(["git", "rev-parse", "HEAD"]).decode().strip(),
        "hostWorkingDiffSHA256": hashlib.sha256(run(["git", "diff", "HEAD"])).hexdigest(),
        "canvasRevision": run(["git", "rev-parse", "HEAD"], cwd=canvas).decode().strip(),
        "bases": [PYTHON, ALPINE], "tags": tags, "entries": entries,
        "binarySHA256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in binaries.iterdir()},
    }
    save(out / "images.json", metadata)
    return metadata


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--canvas", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--definition", choices=("release-review", "compact"), default="release-review", help="explicit qualification scope; compact is not the full showcase")
    args = parser.parse_args()
    os.umask(0o077)
    build(args.canvas.resolve(), args.out.absolute(), args.definition)


if __name__ == "__main__":
    main()
