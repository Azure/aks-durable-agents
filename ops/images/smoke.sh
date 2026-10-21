#!/usr/bin/env bash
# Probe the actual binaries as the image user, with no network or host mounts.
# An optional second argument smokes a published helper instead of rebuilding it.
set -euo pipefail
prefix=${1:-local/aks-durable-agents}
container=
cleanup() { if [[ -n "$container" ]]; then docker rm -f "$container" >/dev/null; fi; }
trap cleanup EXIT
for role in host session-fixture; do
  image="$prefix/$role:local"
  [[ $(docker image inspect --format '{{.Config.User}}' "$image") == 65532:65532 ]]
  container=$(docker run -d --network none --read-only --tmpfs /tmp:uid=65532,gid=65532,mode=0700 --entrypoint /session-fixture "$image" fake --addr 127.0.0.1:9001 --ledger /tmp/keepalive/fake-calls.jsonl)
  docker exec "$container" /session-fixture init --scenario v1 --data /tmp/v1
  docker exec "$container" /session-fixture evidence --scenario v1 --data /tmp/v1 | python3 -c 'import json,sys; data=json.load(sys.stdin); assert data["publicationCount"] == data["receiptCount"] == data["fakeModelCalls"] == 0'
  docker exec "$container" /session-fixture init --scenario v2 --data /tmp/v2
  # Missing-ledger refusal is intentional: never manufacture zero-call evidence.
  if docker exec "$container" /session-fixture evidence --scenario v2 --data /tmp/v2; then
    echo 'Missing v2 model ledger was accepted' >&2
    exit 1
  fi
  if [[ "$role" == host ]]; then
    # The host's own probe makes a successful TCP connection to the inert fake.
    docker exec "$container" /host health-probe 127.0.0.1:9001
    docker exec "$container" /session-fixture network-probe --address 127.0.0.1:9001 --expect allowed
  fi
  cleanup
  container=
done

helper=${2:-$prefix/backup-helper:local}
if [[ $# -lt 2 ]]; then
  # PR/local validation uses the production host just built by make images.
  # Publication instead builds from the immutable pushed host digest.
  docker build --network=none --platform linux/amd64 -f ops/backup/Dockerfile \
    --build-arg "HOST_IMAGE=$prefix/host:local" -t "$helper" ops/backup
fi
bash ops/images/helper-smoke.sh "$helper"
