#!/usr/bin/env bash
# Strict Go scan of actual packaged executables, including the helper copies.
set -euo pipefail
prefix=${1:-local/aks-durable-agents}
helper=${2:-$prefix/backup-helper:local}
work=$(mktemp -d)
container=
cleanup() {
  if [[ -n "$container" ]]; then docker rm -f "$container" >/dev/null; fi
  rm -rf -- "$work"
}
trap cleanup EXIT
for role in host session-fixture backup-helper; do
  image="$prefix/$role:local"
  if [[ "$role" == backup-helper ]]; then image="$helper"; fi
  container=$(docker create --platform linux/amd64 --entrypoint /session-fixture "$image")
  binaries=(session-fixture)
  if [[ "$role" != session-fixture ]]; then binaries+=(host); fi
  for binary in "${binaries[@]}"; do
    docker cp "$container:/$binary" "$work/$binary"
    govulncheck -mode=binary "$work/$binary"
  done
  docker rm -f "$container" >/dev/null
  container=
done
