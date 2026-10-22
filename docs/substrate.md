# Opt-in Substrate host wiring

[Embedded host](host.md) · [Preview 0 gates](preview-0.md)

This is development wiring for **one host and one stateless-replay harness**.
It uses released dependencies, but is not an AKS or recovery qualification. The default
remote harness mode and the fixture-only Helm chart are unchanged. Install
Substrate separately; this application does not own its CRDs, signers, node
agents, routers, worker pools, database or snapshot store.

## Version set

Build with **Go 1.27.3**, including remote-only builds. Sessions core and the
separately versioned adapter use canonical upstream releases, without fork
replacements:

| Component | Pinned version |
|---|---|
| Sessions root | `github.com/agent-primitives/sessions v0.3.0` |
| Sessions Substrate adapter | `github.com/agent-primitives/sessions/integrations/substrate v0.3.0` |
| Substrate client and separately installed server | `v0.5.0` |

The root tag resolves to `bcbd4d9`; the adapter's separate tag resolves to
`d74eec3`, one commit later, updating its dependency to the released root. A root
tag alone does not release a nested module. These compatible released pins do
not complete the [Preview 0 release gates](preview-0.md#2-no-unreleased-dependencies--blocked).
Check the **selected** graph, not just direct requirements:

```sh
go version
go list -m all
go mod graph
go mod verify
```

Keep the client and server at the adapter's exact compatible **v0.5.0** runtime
version. The module test checks the client graph, not the installed server.
At v0.5.0, `SuspendActor` is synchronous and has no durability-option field. The
adapter inspects the highest native snapshot generation and refuses pending or
local-only evidence rather than using an older completed snapshot. Later servers
add asynchronous defaults/options; do not float the server independently or
copy newer-main API assumptions into this assembly.

Use a **fresh, compatible state set** for this runtime upgrade: host journal,
Substrate catalog, objects and actors. Swapping images does not migrate old
runtime catalogs or snapshot references. Sessions can migrate its journal schema;
that is not a qualified migration of the complete recovery set. Downgrading an
image is not a data rollback. See the separate
[install-only operator guide](../ops/aks/SUBSTRATE.md).

## Prerequisites

Use a dedicated private kind cluster for development, never an unreviewed shared
cluster. Pin every runtime image and sandbox asset. Provision these separately:

- Substrate control API with verified server TLS, projected short-lived client
  token and a dedicated host identity. Keep the token and CA outside the Actor.
  Label the host's namespace `ate.dev/api-access=true`: v0.5.0's default control
  API ingress policy requires this for access from another namespace. This label
  does not replace control authentication or the host's own egress policy.
- A gVisor WorkerPool and one ActorTemplate in the configured template atespace.
  The template selects that pool, uses `VOLUMES` fidelity, disables golden
  snapshots and mounts a `durable-dir` for harness files. The harness serves
  gRPC on **port 80**, reports stateless replay, and requests no model or tool
  credentials. Use the fixture image's explicit `/session-fixture actor-harness`
  entrypoint, not the legacy port-9000/Pod-marker `harness` command. Preflight
  verifies `actor-harness --check` on the selected immutable digest before paid
  resources; the image role/receipt schema is unchanged. See the
  [manual AKS actor variant](../ops/aks/SUBSTRATE.md#manual-sessions-actor-variant)
  for the separate executor Pod, native placement/checkpoint proof and live-go
  boundary. Offline/image checks do not qualify its live AKS execution.
- An actor atespace reserved for this host/template binding. Do not change it or
  the template while sessions exist; Actor names derive from session UIDs.
- A retained S3-compatible development store for kind. This does not qualify
  Azure Blob, backup/restore, snapshot durability or a released configuration.
- A private router Service reachable only by the trusted host. Router h2c is
  **not caller authentication**: anyone reaching it can target Actors by
  atespace/UID. Endpoint validation does not replace network enforcement.

## Host inputs

Supply exactly one `-substrate-harness=name=atespace/template` instead of
`-harness`. Memory-snapshot mode and mixed remote/Substrate routes are not
supported. Do not pass fixture `-harness-service`, `-peer-node-file` or
`-node-name` options in Substrate mode.

Example inputs for an already-installed private runtime (replace the template,
paths and ordinary model/auth configuration with your own):

```sh
./host \
  -substrate-harness=echo=agents/echo \
  -substrate-atespace=agents \
  -ateapi-addr=api.ate-system.svc.cluster.local:443 \
  -ateapi-server-name=api.ate-system.svc \
  -ateapi-ca-file=/var/run/control/ca.pem \
  -ateapi-token-file=/var/run/control/token \
  -atenet-router=atenet-router.ate-system.svc.cluster.local:80 \
  -addr=127.0.0.1:8080 -health-addr=127.0.0.1:8081 \
  -journal=/data/journal.db -model-policy=/config/model-policy.json \
  -model=your-deployment \
  -model-base-url=https://your-resource.openai.azure.com/openai/v1/ \
  -auth-config=/config/auth.json -tls-cert=/tls/server.crt -tls-key=/tls/server.key
```

The router, token and CA inputs are mandatory. Control and router endpoints must
be literal loopback addresses or exact `service.namespace.svc.cluster.local:port`
Services; TLS server identity is verified even through a loopback forward.
There is no skip-verification or plaintext control option. The token is re-read
per RPC to observe projected-token rotation. Missing/empty credentials refuse
calls rather than falling back to node/model/user credentials. Keep existing
host listener, approver, model policy and executor configuration requirements;
Substrate does not replace them.

## Limits and recovery labels

The [two Preview 0 paths](preview-0.md#1-proof-on-real-aks--blocked) are conditional:
**“single host; recovery authority not yet boot-scoped”** with Substrate, or
**“no sandbox isolation yet”** without it. Released libraries do not establish
AKS lifecycle/network/backup proof or a released Blob recovery configuration.
Do not use this wiring as an unqualified park/recovery demonstration.
Public Suspend/Resume and approval parks still invoke Substrate snapshot/restore.
The stateless host explicitly uses `WithVolumesOnly()`: it validates observed,
completed **VOLUMES** results with a durable URI and disables memory-snapshot
admission. It does not configure the template; keep the prerequisites above.
Tests exercise the real TLS adapter and refuse wrong fidelity, missing URI,
newest-pending evidence and invalid held checkpoints before Resume. The release
includes [observed fidelity (#181)](https://github.com/agent-primitives/sessions/pull/181),
[held/newest-generation validation (#195)](https://github.com/agent-primitives/sessions/pull/195)
and the [v0.5.0 adapter (#201)](https://github.com/agent-primitives/sessions/pull/201).
These offline checks do not qualify the assembled approval/recovery scenario or
[effective restore-source behavior (#192)](https://github.com/agent-primitives/sessions/issues/192).
Declaring the harness stateless alone is not VOLUMES enforcement.

In v0.5.0 native Pause uses `SUSPENDING` and `SUSPENDED`, not `PAUSING` and
`PAUSED`, and can leave the newest snapshot node-local. The adapter's checkpoint
validation refuses stale or local-only evidence with `FAILED_PRECONDITION`,
pending upload with `UNAVAILABLE`, and transitioning/busy Actors with `ABORTED`.
After inspecting and reconciling Actor state, use Sessions Suspend to establish
and record a durable checkpoint before Resume; retrying a stale reference cannot
fix it. These client-side checks are not atomic restore preconditions.

Client-side checkpoint validation is not atomic with Resume. One host reduces
competition but does not fence router auto-resume or operator lifecycle calls.
Avoid those operations during recovery and reconcile unexpected Actor state.
[Atomic expected-snapshot restore](https://github.com/agent-substrate/substrate/issues/2832)
gates multi-host deployment. Boot-scoped authority is deferred: old callers or
credentials are not proved unable to read receipts or cause effects.

Keep one serving host and fenced journal writer, no surge or forced disk detach.
Host journal, receipts and model ledger stay outside Actor snapshots. The
[current fixture backup recipe](../ops/backup/README.md) assumes host+harness
share one PVC; it is **not an Actor-backed backup recipe**. A Substrate recovery
set also needs matching runtime database/catalog and snapshot objects, consistent
held-checkpoint references and effect reconciliation. No HA, multitenancy,
boot-authority or atomic-restore guarantee is made here.
