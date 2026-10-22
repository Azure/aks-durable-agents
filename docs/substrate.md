# Opt-in Substrate host wiring

[Embedded host](host.md) · [Preview 0 gates](preview-0.md)

This is development wiring for **one host and one stateless-replay harness**.
It uses released dependencies, but is not a recovery qualification. The default
remote harness mode and the fixture-only Helm chart are unchanged. Install
Substrate separately; this application does not own its CRDs, signers, node
agents, routers, worker pools, database or snapshot store.

## Version set

Build with **Go 1.27.2**, including remote-only builds. Sessions core and the
separately versioned adapter use canonical upstream release tags, without fork
replacements:

| Component | Release |
|---|---|
| Sessions root | `github.com/agent-primitives/sessions v0.3.0` (`bcbd4d9dcb35`) |
| Sessions Substrate adapter | `v0.3.0` (`d74eec347772`, tag `integrations/substrate/v0.3.0`) |
| Substrate client and server | `v0.5.0` (`e8d40c33f96f`) |

Root Sessions tags do not release the nested adapter module. Its separate release
requires Sessions v0.3.0 and Substrate v0.5.0. Released pins do not close the
[Preview 0 release gates](preview-0.md#2-no-unreleased-dependencies--blocked).
Check the **selected** graph, not just direct requirements:

```sh
go version
go list -m all
go mod graph
go mod verify
```

Keep the Substrate server/client pin matched to the adapter. v0.5.0's suspend
is synchronous and returns after the newest generation completes; later Substrate
versions add an asynchronous default and need an explicit synchronous request.
Do not float the server independently.

**Fresh-state reinstall required:** moving from the old `96dffb287919` runtime to
v0.5.0 is not an in-place upgrade. Substrate does not support pre-1.0 minor
upgrades; v0.5.0 also changes the stored sandbox-class wire type. Reinstall it
with fresh state, then recreate templates and Actors for v0.5.0 with the matching
adapter. Old Actors and the session checkpoints held on them do not carry over;
do not point retained sessions at a fresh runtime and call it recovery. Rollback
also needs the older runtime/adapter and compatible state, not a downgrade over
v0.5.0 state. See the [upstream migration notes](https://github.com/agent-primitives/sessions/blob/v0.3.0/CHANGELOG.md#substrate-v050)
and the separate [host journal upgrade warning](host.md#configuration-and-local-build).

## Prerequisites

Use a dedicated private kind cluster for development, never an unreviewed shared
cluster. Pin every runtime image and sandbox asset. Provision these separately:

- Substrate control API with verified server TLS, projected short-lived client
  token and a dedicated host identity. Keep the token and CA outside the Actor.
  Label the host's namespace `ate.dev/api-access=true`: v0.5.0 denies ingress to
  the control API from other namespaces by default. This label does not replace
  control authentication or the host's own egress policy.
- A gVisor WorkerPool and one ActorTemplate in the configured template atespace.
  The template selects that pool, uses `VOLUMES` fidelity, disables golden
  snapshots and mounts a `durable-dir` for harness files. The harness serves
  gRPC on **port 80**, reports stateless replay, and requests no model or tool
  credentials. The current port-9000 fixture is not that image.
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
**“no sandbox isolation yet”** without it. The Substrate path still needs qualification of the released
fidelity and held-checkpoint checks, a compatible released Blob plugin,
and actual AKS lifecycle/network/backup proof. This wiring alone closes none of
those gates; do not use it as an unqualified park/recovery demonstration.
Public Suspend/Resume and approval parks still invoke Substrate snapshot/restore
paths in the current pin. They remain unqualified: the host keeps default
stateless-replay policy, without opting into `WithVolumesOnly()` enforcement.
The pin includes [observed fidelity (#181)](https://github.com/agent-primitives/sessions/pull/181)
and [exact-held/newest-generation validation (#195)](https://github.com/agent-primitives/sessions/pull/195),
but not [effective restore-source validation (#192)](https://github.com/agent-primitives/sessions/issues/192).
Declaring the harness stateless does not disable snapshot/restore RPC paths.

In v0.5.0 a paused Actor is `SUSPENDED` with a node-local newest snapshot, not
`PAUSED`; a pause in progress is `SUSPENDING`, not `PAUSING`. The adapter selects
the newest generation before checking durability, never an older completed one.
Resume requires the exact recorded held checkpoint and a completed durable copy.
A stale or local-only checkpoint is `FAILED_PRECONDITION`; a pending upload is
`UNAVAILABLE`, and a transitioning/busy Actor is `ABORTED`. For this stateless
host, inspect the Actor and Suspend again to establish and record a durable
checkpoint before Resume; retrying a stale reference cannot fix it. These are
client-side checks, not atomic restore preconditions.

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
