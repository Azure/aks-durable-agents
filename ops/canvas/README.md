# Local native Canvas producer qualification

This drill creates a **new, UUID-named kind cluster** with default CNI disabled,
installs pinned Cilium, and runs the native Helm profile. It never targets an
existing cluster or pushes images. Use a local Docker daemon and private artifact
directories outside both source checkouts. No host sysctl/kernel changes are
performed. Normal completion or exceptions delete only the owned cluster;
interruption by a killed process may require cleanup using `ownership.json`.

## Scope and prerequisites

- Linux amd64, Docker, Go 1.27.2 with cached modules, Helm 3.20.0, kubectl, Python
  3.14.3, and **kind v0.33.0**. The installed kind executable is not upgraded.
- An independently supplied clean Canvas checkout containing `canvas-harness`,
  `copilot-review`, and its versioned `examples/release-review` layouts. Its
  revision is recorded. This private source, its commands and compiled suite
  layouts are **not distributed in this repository**.
- Pinned Kubernetes 1.37.0 node, Cilium 1.20.3 chart/images and Python/Alpine bases.
  Exact digests are in `drill.py` and `images.py`; chart SHA256 is checked before
  cluster creation. Pull the image bases before the offline image build.
- The selected kind binary can be stored with private artifacts. Official Linux
  amd64 v0.33.0 SHA256:
  `aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d`.
  Older kind releases can emit a kubeadm API rejected by the pinned node.

Vendor Cilium images are pulled by unchanged digest directly into the owned node's
containerd. This avoids Docker archive imports that can leave dangling dated CRI
image aliases. Locally built application images are loaded by tag, then pinned to
actual **node manifest digests**, not Docker config IDs. The chart is installed
with workloads disabled before PVC preparation and workload enablement.

## Build and run

This is **optional external qualification**, not a self-contained public install.
A fresh public clone cannot reproduce the cluster drill without those private
inputs and cached image/chart dependencies. The [offline checks](#offline-checks)
can run from this repository alone; do not substitute unreviewed producer binaries
or import private source/assets to make the drill appear self-contained.

Replace the absolute paths below. Both output directories must be new; existing
paths are refused. The private parent directory must already be operator-owned.
The builder uses `GOPROXY=off`, `CGO_ENABLED=0` and Docker `--network=none`; modules
and digest-pinned bases must be cached. Cluster setup requires registry access for
Cilium, and installs only into the newly created cluster.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 ops/canvas/images.py \
  --canvas /absolute/path/to/clean-canvas \
  --definition compact \
  --out /absolute/private/new-artifacts

PYTHONDONTWRITEBYTECODE=1 python3 ops/canvas/drill.py \
  --kind /absolute/path/to/kind-v0.33.0 \
  --canvas /absolute/path/to/clean-canvas \
  --artifacts /absolute/private/new-artifacts \
  --cilium-chart /absolute/path/to/cilium-1.20.3.tgz \
  --evidence /absolute/private/new-evidence
```

Run from this repository root. Save stdout/stderr privately. Preserve artifact
files and local image tags for reruns; choose a fresh evidence path each time.
The runner uses an explicit private kubeconfig/context for every Helm/kubectl call.
After an interruption, inspect its ownership record and delete only that exact
owned kind cluster, never the current/default kubectl context.

`--definition compact` copies the small protocol fixture and reuses the unchanged
released writer/reviewer suite pins from Canvas. It has a distinct Canvas
**definition** identity but the same immutable compiled harness identities. It
supplies its own fictional documents/fake outputs; it is not the full release
showcase or a semantic evaluation of those instructions. The builder's default
`release-review` remains available for archive export and negative qualification.

The full release-review writer context exceeds this host's unchanged conservative
8192 input bound (9823 units in the captured qualification request). It is refused
before HTTP/credential dispatch or budget reservation. **The full showcase is not
runnable/qualified under this policy**, including for a later real-model smoke.
Do not raise caps, edit suite pins, or reset a ledger just to make it pass. The
compact request bodies are under 6500 bytes; both turns must pass the actual host
input check, with a live strict-schema completion cap of 4096 including reasoning.
Recorded native `max_tokens=16384`/temperature/request hashes remain unchanged.

## What the proof checks

- Actual Canvas engine/browser API → Sessions host → static native producer →
  modeltransport → loopback HTTPS fake, with no implicit HTTP retry.
- Writer whole-document proposals require manual acceptance; the reviewer runs
  separately after host, producer and engine restarts. Its fake provider checks
  the exact accepted writer bytes and document paths before returning a review.
- Independent durable HTTP, fake-credential and host-budget ledgers progress
  0 → 1 → 2 and remain at two after a third request fails without a proposal.
  Journal logical-content SHA remains unchanged across restart. Both pod UIDs
  change, the private archive remains loadable, and actual nodes match affinity.
- Exact configured harness ports are reachable. Live-listener positive controls
  precede six denials: host/outsider → producer readiness, outsider → harness,
  producer → extra host port, producer egress, and host → private TCP443.
  Matching Cilium `Policy denied` drop evidence is mandatory; connection failure
  alone is insufficient. The fixture listeners are diagnostic-only.

`summary.json` exists with `passed:true` only after all assertions pass. Evidence
includes image/source/binary pins, rendered values, pod readbacks, network probes,
drop monitor output, turns, counters and local engine/forward logs. Failure
readbacks are captured before cleanup. HTTP/credential count files contain no
prompt, document or token contents; other engine state/turn artifacts contain
fictional fixture data and must still stay private.

## Limits

Both images are explicitly **DRILL-ONLY**. The host assembly calls production
`host.Run` but injects a scoped fake credential and TLS transport in-process; no
production fake-credential flags exist. The producer image adds a diagnostic
probe to the generic command. Production rendered CLI arguments are separately
checked against the actual host parser by shared chart/Go tests.

This uses explicit auth-off/trusted-network mode. It does **not** exercise Entra,
workload identity, caller TLS/token admission, real inference/billing, AKS storage,
a hostile-tenant boundary, action executors, durable effect receipts or copied
controller replay. Evaluation remains **not verified**. These gates still require
separate qualification; producer-only proof does not unblock the full hosted flow.

## Offline checks

These unit checks do not build external Canvas commands or create a cluster:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s ops/canvas -v
go test -race ./ops/canvas/...
python3 -B charts/aks-durable-agents/tests/test_chart.py
```
