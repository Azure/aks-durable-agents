# Embedded host (`cmd/host`)

[Back to overview](../README.md) · [Caller authentication](entraauth.md) · [Keyless transport](modeltransport.md)

**Experimental proof only.** Sessions does not yet invoke `Authorizer` in its RPC
handlers. This host does not fork those handlers or invent a replacement
ownership/policy activation contract. Both listeners must be **literal loopback IPs**, even with authentication enabled.
Remote harness addresses are loopback-only unless the explicit split-pod Service
override described below is configured. The optional [Substrate backend](substrate.md)
uses a separately installed private runtime and one stateless-replay harness; it
does not change listener or authorization limits. Do not expose
this host through ingress, port forwarding to untrusted users, or a public proxy.
All authenticated callers otherwise share access to session reads and effects.

What the host enforces:

- `-auth-mode=required` is the default. It requires a TLS certificate/key and
  installs the actual sessions unary/stream authentication interceptors with
  `entraauth.Verifier`. Failed authentication reaches no Sessions handler.
  Unary verification is admission-only; stream context expiry is cooperative.
  Rejections and failed signing-key refreshes are logged by fixed reason code,
  rate-limited, never with token, claim or provider text ([details](entraauth.md#trust-and-failure-contract)).
- In required mode, `Approve` additionally invokes an `api.Authorizer` using
  `authn.Caller(ctx)` and an exact issuer/subject approver allowlist. An owner is
  **not implicitly an approver**; an allowlisted non-owner can approve. Empty
  allowlist denies every approval, including denial decisions. This check occurs
  before session lookup, disclosure or journal mutation. Request `IdentityRef`
  remains untrusted provenance; this host does not claim verified audit attribution.
  Startup refuses an approver whose issuer is not exactly `identity.issuer`, whose
  `oid` subject is not a lowercase GUID, or whose `sub` subject has ASCII
  whitespace or control characters: it could never match. **Upgrade note:** such
  entries used to load and only deny `Approve`; now they stop a required-mode host
  at startup. Fix the entry's `issuer` or `subject` (lowercase GUID for `oid`) to
  match the approver's token; do not switch `subjectClaim` to `sub`, which changes
  ownership keys.
- `-auth-mode=off` disables authentication and the approval gate for trusted-network
  local development only, with an explicit startup warning. Required mode also
  warns that owner isolation and durable policy activation are absent.
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

**Journal upgrade warning:** the pinned sessions dependency upgrades schema v4 to v5 on
open, retaining event evidence and leaving authorization mode `off`. Stop old
writers and back up the complete journal before first open. The older daemon
cannot reopen v5: rollback requires restoring a compatible backup, not merely
swapping the image back. RWO storage is not application writer fencing.

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

Sessions and health listeners stay loopback-only. For a split-pod deployment,
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

## What still belongs upstream

Before governed activation, sessions #127 needs:

- **c1:** verified-caller per-action checks before disclosure/effects; atomic owned
  Create and Exec auto-create; storage-authorized listing before pagination;
  read/replay/delete/cancel/exec/suspend/resume/fork checks, including exec on
  effect-driving Resume and suspend on stateful Fork.
- **c2:** owned fork-child reservation/publication and server-derived decision
  attribution; durable authorization-policy version/startup compatibility checks,
  rejecting incompatible/off writers and unbound legacy sessions without an
  explicitly reviewed binding migration. The host must consume this contract,
  not write its own authorization marker.
- **Operations/TLS:** qualified end-to-end client server-identity validation,
  credential lifecycle, registry/operator separation, deployment/network controls,
  and a reviewed stop/backup/fence/activate procedure. TLS plus admission is not
  a substitute for either c1 or c2. No live deployment is qualified here.
