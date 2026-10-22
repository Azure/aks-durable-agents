# Embedded host (`cmd/host`)

[Back to overview](../README.md) · [Caller authentication](entraauth.md) · [Keyless transport](modeltransport.md)

**Experimental proof only.** In required mode this host installs Sessions'
`WithAuthorization` for per-RPC owner checks and approver read/approval access.
This is host-RPC isolation, not journal-wide enforcement or governed activation.
By default both listeners must be **literal loopback IPs**, even with
authentication enabled. The explicit auth-off private TLS exception below changes
only the Sessions listener, never health or required mode.
Remote harness addresses are loopback-only unless the explicit split-pod Service
override described below is configured. The optional [Substrate backend](substrate.md)
uses a separately installed private runtime and one stateless-replay harness; it
does not change listener or authorization limits. Do not expose
this host through ingress, port forwarding to untrusted users, or a public proxy.
Required-mode permissions and remaining journal limits are described below.

What the host enforces:

- `-auth-mode=required` is the default. It requires a TLS certificate/key and
  installs the actual sessions unary/stream authentication interceptors with
  `entraauth.Verifier`. Failed authentication reaches no Sessions handler.
  Unary verification is admission-only; stream context expiry is cooperative.
  Rejections and failed signing-key refreshes are logged by fixed reason code,
  rate-limited, never with token, claim or provider text ([details](entraauth.md#trust-and-failure-contract)).
- In required mode, `WithAuthorization` captures `authn.Caller(ctx)` as the
  immutable owner on Create and implicit Exec creation, not request `IdentityRef`.
  Ordinary session operations require that owner. An exact listed issuer/subject
  OR a verified approver app role grants `GetSession`, `Replay` and `Approve` on
  any valid owned session. Ownership **does not grant approval**. With neither
  approval source, all decisions are denied, including denial decisions.
  Approvers gain no other cross-owner operation: no Exec, Resume, Suspend,
  Delete, Cancel or Fork. Listing stays natively owner-only, including for
  approvers; there is no cross-owner inbox or notifier. Supply session UIDs to
  approvers out of band.
  Configured admission checks always apply; configured approver roles require a
  usable `roles` claim even for listed subjects when approving or reading another
  owner's session ([source rules](entraauth.md#optional-caller-and-approver-checks)).
  Ordinary owner operations do not require approver roles. Missing, inaccessible
  and ownerless sessions return generic `PermissionDenied` before request-tuple
  validation or payload disclosure. A concurrent deletion may instead return
  `Aborted` before the owner lookup. Authorized malformed approval tuples may
  return `InvalidArgument`. Required-mode Fork is refused with
  `FailedPrecondition` even for owners; authorized Cancel remains `Unimplemented`.
  Startup refuses an approver whose issuer is not exactly `identity.issuer`, whose
  `oid` subject is not a lowercase GUID, or whose `sub` subject has ASCII
  whitespace or control characters: it could never match. **Upgrade note:** such
  entries used to load and only deny `Approve`; now they stop a required-mode host
  at startup. Fix the entry's `issuer` or `subject` (lowercase GUID for `oid`) to
  match the approver's token; do not switch `subjectClaim` to `sub`, which changes
  ownership keys.
- `-auth-mode=off` leaves existing behavior unchanged: anyone who can reach the
  host may read, act on sessions and approve. It is for trusted-network
  development only, with an explicit startup warning. Private pod access requires
  the separate opt-in below; it does not authenticate callers. Off-mode Fork
  behavior is unchanged.
- Health and gRPC reflection are registered only on `-health-addr`; that listener
  has no Sessions service. It is plaintext loopback operator access, not a public
  health endpoint. There is no dynamic harness registry or self-RPC bypass.
- All model calls use the [keyless transport](modeltransport.md). The host pins the configured
  deployment for chat and streaming, overriding harness-supplied model IDs.
  Caller JWTs are not forwarded to the model, harness or tool executor.
- Static harness/tool routes use public placement packages and an independently
  implemented version-1 Unix executor protocol. Explicit `durable_dedup: true`
  is required to dispatch; the executor still owns resource authorization and
  durable deduplication. Protocol/transport errors are bounded and sanitized;
  there are no automatic retries. A timeout/error never proves no effect occurred.

## Read disclosure and rollout

**Approvers can read full sessions, including prompts, outputs and tool arguments.**
`Replay` exposes committed journal records, not just an approval summary.
`GetSession` returns a `Session`: resource metadata and timestamps, model/harness,
execution/compute/deletion states, lineage, last sequence, pending approval tuple,
labels, annotations, origin and provenance `IdentityRef`. The stored authorization
owner is **not serialized** in that response. `Approve` returns the same `Session`
plus the decision record, not the full journal. It only records a decision; it
never implicitly calls Resume or grants execution rights to the approver.

**Start required mode on a new private journal.** Existing ownerless sessions are
denied to everyone, including approvers. There is no automatic owner binding or
migration. Stop and fence old writers and retain their journal and evidence
separately; do not switch an existing auth-off journal to required mode in place.
Unchanged required-mode restarts retain the new journal and its owners.

Deployment requires a published, verified and pinned image containing this host
change. A current image digest alone does not establish the new behavior. Follow
[publish then pin](../ops/images/README.md#publish-then-pin) before rollout. The
schema-v6 upgrade warning below still applies to retained older journals; schema
migration does not create authorization owners.

## Configuration and local build

In default remote mode, `-harness` is repeatable; the alphabetically first
configured harness is the creation default. Alternatively, configure exactly one
[`-substrate-harness`](substrate.md#host-inputs), never both modes. There are no
built-in echo/chat harnesses. All builds, including remote mode, use Go 1.27.3. For a local
release-notes fixture, configure `release-notes=127.0.0.1:9000`, `/data/journal.db`,
`/data/tools.json`, `/data/publish.sock` and a durable publication database.
The model URL must be HTTPS with `/openai/v1/` (not the old plaintext fake `/v1`);
required-mode clients must supply verified TLS and per-RPC delegated credentials.
The old credential-free fixture driver therefore runs only with explicit off mode.

Example operator-managed auth JSON (illustrative IDs; **no tokens or secrets**):

```json
{
  "identity": {
    "tenantID": "11111111-2222-3333-4444-555555555555",
    "issuer": "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0",
    "audience": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "allowedClientIDs": ["12345678-1234-1234-1234-123456789abc"],
    "requiredScope": "sessions.access",
    "subjectClaim": "oid"
  },
  "approvers": [{
    "issuer": "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0",
    "subject": "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
  }]
}
```

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o host ./cmd/host
docker build -t aks-durable-agents:local .
./host -addr=127.0.0.1:8080 -health-addr=127.0.0.1:8081 \
  -journal=/data/journal.db -harness=release-notes=127.0.0.1:9000 \
  -tool-executors=/data/tools.json -model-policy=/config/model-policy.json \
  -model=your-deployment -model-base-url=https://your-resource.openai.azure.com/openai/v1/ \
  -model-scope=https://ai.azure.com/.default \
  -auth-config=/config/auth.json -tls-cert=/tls/server.crt -tls-key=/tls/server.key
```

The image is digest-pinned distroless static, UID/GID 65532. Its build context
contains only the prebuilt binary and Dockerfile, not sessions source,
credentials or test fixtures. Provision private writable PVC/runtime directories
for UID 65532, with one writer, `Recreate`, no surge and no force-detach before
fencing. The binary sets umask 077. Shutdown drains for ten seconds before
canceling connections; completion still depends on handlers honoring cancellation.
No Azure resource, RBAC, token acquisition or live inference is performed by tests.

**Journal upgrade warning:** Sessions v0.3.0 migrates older journals to schema v6
on open, retaining event evidence and leaving authorization mode `off`. Stop all
older writers and back up the complete journal (including its WAL, if present)
before first open; upgrade every writer before restarting it. Older builds cannot
reopen v6. There is no downgrade migration: rollback requires restoring a compatible
backup, losing later writes, not merely swapping the image back. Use v0.3.0-aware
readers for the new canonical record fields. RWO storage is not application writer
fencing. See the [upstream compatibility notes](https://github.com/agent-primitives/sessions/blob/v0.3.0/CHANGELOG.md#compatibility).

## Bounded model policy and split-pod proof

`cmd/host` requires `-model-policy` before startup; missing or unknown pricing
refuses inference. The standalone `modeltransport` library retains its legacy
nil-policy API for existing callers, but the host CLI does not use that mode.
The strict, versioned policy file names one run, deployment and private SQLite
ledger. Rates are integer **micro-USD per million tokens**, not per-token USD:

```json
{
  "version": 1,
  "runID": "private-proof-unique-run",
  "ledgerPath": "/data/real-attempts.db",
  "deployment": "your-deployment",
  "pricing": {
    "inputMicroUSDPerMillionTokens": 100000,
    "outputMicroUSDPerMillionTokens": 500000,
    "extraMicroUSDPerCall": 0,
    "source": "https://azure.microsoft.com/en-us/blog/gpt-6-astra-sol-and-luna-for-production-agents-in-microsoft-foundry/",
    "asOf": "2026-09-22"
  }
}
```

Those example rates describe the dated Luna Global Standard short-context offer;
verify the actual deployment SKU and billable terms before using them. They are
not defaults for other deployments. Explicit zero extra charges is required;
unknown/additional-charge models are refused. Version 1 permits two attempts;
version 2 requires `"maxAttempts": 3` for a three-turn run. Either version may
explicitly opt in to `"maxInputTokens": 32768`; omission keeps 8192, and other
explicit values are refused. The entire selected-count/selected-input worst-case
reservation must fit USD 2. It is a reservation, not a bill or a claim that a
failed/unknown attempt was free. Never reset or replace a run ledger to retry.

The policy explicitly rewrites outgoing Chat JSON to set
`max_completion_tokens: 4096` (including reasoning) and request streaming usage.
It checks the entire supported text-only conversation with a conservative
UTF-8-byte-plus-framing input bound of 8192, or the explicit 32768 opt-in,
before ledger reservation or credential/network I/O. Provider-reported input
usage must fit that same bound.
Tools, multimodal and unsupported request forms are refused rather than silently
uncounted. This is host policy, logged at startup—not adapter support or a change
to the neutral request recorded by sessions. Response usage is recorded durably;
missing usage is unknown, not zero. A failed, incomplete or unknown attempt stops
further dispatch, including replay of an identical request. The selected two or
three durable attempt slots survive host restarts. The count is a conservative attempt
count, not proof that the provider received or billed every reserved dispatch.

Both model functions have a 25-second context including token acquisition and
response reads. Unary and streaming Sessions handlers have a maximum 30-second
context; an earlier caller deadline wins. Use a 35-second bridge helper timeout.
Cancellation **does not prove journal persistence or an external effect stopped**.
After lost responses/timeouts, stop new mutations and reconcile the original
session/execution, journal head/pending tuple, real-attempt ledger and publication
receipts. Do not retry, create a replacement session or automatically Resume.

Sessions and health listeners stay loopback-only unless the explicit private
Sessions TLS opt-in below is selected. For a split-pod deployment,
`-harness-service=service.namespace.svc.cluster.local:9000` permits exactly that
configured non-loopback harness address. Repeat this flag for multiple exact
Service/port pairs; each route must match a listed endpoint. Arbitrary IPs,
other Services, duplicate exceptions, and unlisted ports still fail. This private plaintext harness connection is not authentication.
Use policies in both directions to restrict it to the host pod. With
`-peer-node-file=/data/fixture-node.json -node-name=OWN_NODE`, startup refuses a
missing/mismatched peer marker before journal access. Required pod affinity and
operator readback must also verify both live pod UIDs, node names and marker
freshness. Share only a new scenario PVC subtree/socket; do not open a historical
journal with the new schema. Each Deployment remains one replica with Recreate;
RWO is not a writer fence or a sandbox between containers sharing storage.

The sessions Chat adapter refuses nonempty request Params. The host first
validates and consumes its supported hints, then clears Params only on the
provider-facing request copy. The original request/map and journal input hash
stay unchanged. It bridges only `response_format` into the live Chat body;
supported harness token/temperature hints cannot override its fixed 4096
completion-token ceiling or reasoning-model default temperature. Empty Params
retain the plain fixture path. Structured responses are checked for refusal, missing/non-success finish and empty content.
Duplicate response-envelope keys, case/Unicode aliases that Go decodes as the
same envelope field, and unpaired UTF-16 escapes in that envelope are rejected
before adapter decoding. The host does not parse JSON text nested inside model
`content`; consumers validate their own output contracts. Opaque provider numbers
remain lossless; request-schema property names stay case-sensitive.
Buffered responses are checked before adapter decoding; streaming callbacks may
have seen prefixes before a later finish check fails. Prefixes are not completed
results or accepted proposals. See the [bounded policy reference](../modeltransport/README.md)
for schema accounting and selected input/attempt budgets. Omitted-field snapshots
for both versions retain their exact bytes; changing a bound or count against an
existing ledger fails closed. Use a new run and ledger for an opt-in, never reset
the prior budget. Older binaries reject the new field. Neither opt-in rewrites
historical neutral requests or outgoing request hashes. Native controller replay does
not enter the live transport and must leave the attempt ledger unchanged.

## Native document producer routes

A Canvas producer uses the exact immutable registry key
`bundle-v4-<64-lowercase-hex>`; this is not a Kubernetes resource name. Configure
one static `-harness=KEY=ADDRESS` per prepared archive and one exact
`-harness-service=FQDN:PORT` exception per non-loopback endpoint. Native routes
also pin the remote descriptor ID: serving a different descriptor at the same
address is refused. There is no dynamic registration or short-name alias.

Native document-only deployments omit `-tool-executors` and fixture-only peer
marker flags. They do not gain action execution or replay authority. Retain
required same-node affinity and verify actual placement; omitting the marker is
not marker attestation. See the chart's [native profile](../charts/aks-durable-agents/README.md#native-document-producer-profile).

`/host health-probe 127.0.0.1:8081` is a bounded TCP readiness check using a
literal loopback address and canonical nonzero port. It does not initialize
identity, policy or journal state and does not prove authorization or inference
readiness. The native chart uses it without requiring a fixture binary.

## Explicit private Sessions TLS for the hosted engine

`-sessions-trusted-network=true` is a narrow opt-in for the
[chart's private Canvas profile](../charts/aks-durable-agents/README.md#private-canvas-engine-profile),
not a remote-authenticated mode. It is accepted only with `-auth-mode=off`, both
`-tls-cert` and `-tls-key`, and `-addr=0.0.0.0:<numeric-port>` (port 1–65535;
0 is also accepted for ephemeral local tests).
For the chart this is `-addr=0.0.0.0:8080`; `-health-addr=127.0.0.1:8081` stays
literal loopback. Missing TLS, another bind address, invalid ports, or required
auth with the flag fail before journal/identity initialization. Without the flag,
existing loopback validation is unchanged. Required-auth TLS and admission rules
are unchanged; the flag does not enable wildcard required-auth listeners.

The host serves TLS even though caller authentication is off. Its leaf must
contain the exact chart Sessions Service DNS SAN:
`<agents.name>-sessions.<namespace>.svc.cluster.local`. Use the rendered name
because long release names are shortened/hashed. The engine dials this name on
8080 with an explicit CA and hostname verification, never insecure TLS or a
plaintext fallback. The existing host TLS Secret contains `tls.crt`, `tls.key`
and `ca.crt`; only the CA item is projected into the engine. The engine's own
TLS certificate/key come from a different Secret with IP SAN `127.0.0.1`, for
its loopback HTTPS API and the operator's local port-forward/CA-verified adapter.
No Secret material belongs in values or ConfigMaps. Secret rotation requires
explicit restarts of affected processes; no live reload is promised.

**Identity is not exercised.** Sessions resource ownership and authenticated
approval are not introduced by TLS or by label-selected NetworkPolicies. Limit
private TCP8080 ingress to this release's engine in the same namespace and
verify all additive policies and enforcement before enabling workloads. Do not
expose this listener through Ingress, NodePort, LoadBalancer or an untrusted proxy.
Host model/WI configuration and exact harness egress remain host-owned; the engine
receives no model credentials or workload identity. Health remains a separate
plaintext loopback operator endpoint with no Sessions service. Neither readiness
nor a successful TLS connection proves authorization, inference or replay.

Use one retained host disk and a separate retained Azure Disk/POSIX Filesystem
RWOP engine disk, prepared for UID65532; no automatic ownership repair or state
migration is performed. Fence previous writers before force recovery. The engine
creates its private 0700 child `/data/state` and binds instance, definition and
Sessions endpoint there. Binding the DNS endpoint **does not detect a new host
journal behind the same DNS name**. Preserve/fence the original host journal and
ledger; missing/moved session evidence must fail closed, not trigger replacement
sessions or implicit Resume. See the chart guide for preparation, local TLS
port-forward setup and the policy-first zero-replica installation gate.

## What still belongs upstream

The required-mode policy isolates this host's RPCs only. The journal's durable
authorization marker remains `off`; an unenforced writer can bypass these checks.
Keep the journal private and exclusive to this enforced host. Do not share it
with auth-off hosts, direct writers or older binaries. Backups contain the same
sensitive journal data and require the same private access controls.

Governed activation still needs upstream contracts for durable policy/startup
compatibility and rejection of unenforced writers, owned Fork, verified approval
attribution and caller-bound approval retries. Request `IdentityRef` is untrusted
provenance, not an authorization owner; enforced approval clears supplied actor
identity and does not record verified caller attribution. No operator role,
listing extension, Fork implementation or activation protocol is added here.

Keep literal-loopback required-mode listeners, verified TLS, NetworkPolicy and
writer fencing. Qualified client server-identity validation, credential lifecycle,
registry/operator separation and a reviewed stop/backup/fence/activate procedure
remain necessary. No live deployment or public-host exposure is qualified here.
See [Sessions authorization tracking](https://github.com/agent-primitives/sessions/issues/127).
