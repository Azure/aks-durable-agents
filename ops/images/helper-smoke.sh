#!/usr/bin/env bash
# Exercise the packaged helper's real socket-denial probe, not just network-none.
set -euo pipefail
image=${1:?usage: helper-smoke.sh IMAGE}
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
[[ $(docker image inspect --format '{{.Config.User}}' "$image") == 65532:65532 ]]
name="backup-helper-smoke-$$-$RANDOM"
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT
runtime=(--rm --name "$name" --platform linux/amd64 --network none --read-only
  --cap-drop ALL --security-opt no-new-privileges --pids-limit 64 --memory 256m
  --cpus 1 --tmpfs '/tmp:uid=65532,gid=65532,mode=0700')

# A negative control proves network-none alone cannot satisfy the socket probe.
if output=$(timeout --kill-after=5s 30s docker run "${runtime[@]}" "$image" _probe 2>&1); then
  echo 'Helper accepted network-none without socket-denying seccomp' >&2
  exit 1
fi
[[ "$output" == *'socket creation allowed: recovery isolation absent'* ]]
seccomp=(--security-opt "seccomp=$root/ops/backup/no-network.json")
timeout --kill-after=5s 30s docker run "${runtime[@]}" "${seccomp[@]}" "$image" _probe |
  python3 -c 'import json,sys; data=json.load(sys.stdin); assert data == {"socket_denial": "verified"}; print(json.dumps(data))'

timeout --kill-after=5s 30s docker run -i "${runtime[@]}" "${seccomp[@]}" --entrypoint python3 "$image" - <<'PY'
import json
import os
from pathlib import Path
import subprocess

assert (os.getuid(), os.getgid()) == (65532, 65532), "helper must run nonroot"
for binary in ("/host", "/session-fixture"):
    assert Path(binary).is_file() and os.access(binary, os.X_OK), f"missing executable {binary}"

def run(*args):
    return subprocess.run(args, capture_output=True, text=True, timeout=10)

result = run("/host", "health-probe", "127.0.0.1:1")
assert result.returncode == 1 and "host: health listener unavailable" in result.stderr, result
result = run("/session-fixture", "init", "--scenario", "v1", "--data", "/tmp/v1")
assert result.returncode == 0, result
result = run("/session-fixture", "evidence", "--scenario", "v1", "--data", "/tmp/v1")
assert result.returncode == 0, result
proof = json.loads(result.stdout)
assert proof["publicationCount"] == proof["receiptCount"] == proof["fakeModelCalls"] == 0, proof
result = run("/session-fixture", "init", "--scenario", "v2", "--data", "/tmp/v2")
assert result.returncode == 0, result
result = run("/session-fixture", "evidence", "--scenario", "v2", "--data", "/tmp/v2")
assert result.returncode != 0, "missing model ledger must not become zero-call evidence"
print(json.dumps({"uid": os.getuid(), "gid": os.getgid(), "host": "verified", "fixture": "verified"}))
PY
