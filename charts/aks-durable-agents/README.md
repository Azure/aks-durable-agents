# aks-durable-agents

Experimental Helm chart for the loopback sessions host. Its `appVersion` is
`experimental`, not a source commit or built-image identity. The default legacy
profile installs two single-replica
`Recreate` Deployments (host; harness/executor/inert fake), a harness-only
ClusterIP Service, separate ServiceAccounts, immutable configuration, three
NetworkPolicies, and optionally a retained RWO PVC. **Workloads start at zero
replicas.** By default no sessions API Service or Ingress is installed; sessions
`8080` and separate host health `8081` listeners remain loopback-only. The opt-in
[native document producer profile](#native-document-producer-profile) replaces
the fixture harness/executor/fake pod without changing the legacy defaults.
The separate [private Canvas profile](#private-canvas-engine-profile) adds a
headless engine and private TLS Sessions Service; it is disabled by default.

## Prerequisites and operator steps

- Existing **AKS 1.37**, Linux amd64 nodes, OIDC issuer and workload identity
  enabled, Cilium enforcing Kubernetes NetworkPolicy, Azure Disk CSI, and an
  existing dedicated namespace. Nodes need room for both pods on one node.
- Reviewed immutable image receipts: `image.{host,harness}.repository` is a
  registry/repository **without a tag**; `.digest` is `sha256:<64 lowercase hex>`.
  In the legacy profile, host must contain `/host` **and `/session-fixture`
  supporting `network-probe`**.
  The ordinary repository Dockerfile contains only `/host` and is insufficient
  for the legacy fixture profile;
  use the [reference-profile image build](../../ops/images/README.md), which
  packages the production host with the probe binary and CA roots. Set
  `image.host.includesHealthProbe: true` only after verifying that image's digest.
  This is an operator attestation: schema cannot inspect image contents.
  The legacy harness image must contain the configured fixture/executor binaries and the
  same `/session-fixture network-probe` readiness command.

This remains experimental source, not a self-contained chart distribution.
The [reference fixture source and image build recipe](../../ops/images/README.md)
are supplied; the external RPC client/reviewer used by older rehearsals are not.
Publication bootstraps before real digest defaults; until those pins land, supply
reviewed image digests explicitly. Do not infer provenance from `appVersion`.
Required-mode owner authorization needs a published, verified and pinned host
image containing the `WithAuthorization` change. The current digest alone does
not establish that behavior; follow [publish then pin](../../ops/images/README.md#publish-then-pin).
The reference fixture is not a production agent. It simulates local publication
and includes an inert fake role; it does not turn the production host into a
fake-model host. Initialize a new private subtree for this public fixture
lineage; do not adopt state from older externally built fixtures.

Older development images and launchers must be rebuilt/updated for the
`/session-fixture` executable path and `ADA_FIXTURE_BINARY` / `ADA_NATIVE_BINARY`
test inputs. This is a packaging-interface change, not a data migration: retain
existing journals, receipts, policy run IDs, ledgers, PVC subpaths and operator
values as one compatible set. Do not reset a ledger to adopt new example values.
- Create the Entra application/permission configuration separately. Required
  auth needs `tenantID`, exact tenant `issuer`, GUID `audience`, nonempty
  `allowedClientIDs`, `requiredScope`, and explicit `{issuer, subject}` approvers
  or `approverRoles`. Approval uses **subject OR app role**, never bypassing
  optional `memberOnly`/`requiredGroups` admission. `requiredRoles` admits any
  listed caller role; all listed groups are required. All default off/empty.
  Configured approver roles require a nonempty `roles` claim even for listed
  subjects; startup logs source counts and operator role names, not claims.
  See [policy setup and OR example](../../docs/entraauth.md#optional-caller-and-approver-checks).
  New claim policies are refused with `auth.mode: off`.
  Each approver `issuer` must equal `auth.issuer` exactly; with `subjectClaim: oid`
  each `subject` must be a lowercase object ID GUID, and with `sub` it must have
  no ASCII whitespace or control characters. Values that rendered before can now
  fail install/upgrade; fix the approver's `issuer` or `subject` (lowercase GUID
  for `oid`), not `subjectClaim`.
  Supply an existing `auth.tlsSecretName` with `tls.crt`/`tls.key` readable by
  UID65532. No credential material belongs in values; the chart creates no Secret.
  Required mode enforces owner permissions on host RPCs. Listed subjects OR
  verified approver roles can read and approve any valid owned session, including
  full prompts, outputs and tool arguments; ownership alone does not grant approval.
  No other cross-owner operations are granted. Listing stays owner-only; approvers
  need UIDs out of band, with no inbox or notifier. Required-mode Fork is refused.
  Approve records only a decision, never an implicit Resume. See the
  [response disclosure and rollout rules](../../docs/host.md#read-disclosure-and-rollout).
  This is not journal-wide enforcement or verified approval attribution: the
  journal marker stays `off`, unenforced writers can bypass it and caller-bound
  retries are absent. Keep journals private and exclusive to the enforced host,
  with loopback/TLS and NetworkPolicy restrictions. No public-host or two-human
  independence guarantee is added. Off requires explicit `trustedNetwork: true`;
  anyone reaching that auth-off host can read, act and approve. Off-mode behavior,
  including Fork and the private Canvas profile, is unchanged.
- Create a workload identity and federated identity credential whose subject is
  `system:serviceaccount:<namespace>:<release>-aks-durable-agents-host`
  (prefixes over 40 characters use a shortened name plus an eight-hex SHA256
  suffix; use the rendered ServiceAccount name when configuring federation). Supply its client
  ID in `workloadIdentity.clientID`. Assign the approved model role at the exact
  model resource scope separately. Configure image-pull access separately.
  **No Entra app registration, federation, role assignment, or cloud provisioning
  is performed by this chart.** Only the host has WI admission labeling.
- Set `model.endpoint` (HTTPS `/openai/v1/`), deployment, token scope, and
  `model.policy` with an immutable run ID and dated, verified pricing in integer
  microUSD per million tokens. `extraMicroUSDPerCall` must be zero. The host
  additionally checks real calendar dates and the USD2 full-run reservation.
  The host defaults to 8192 input/4096 completion tokens and two attempts;
  the explicit input/attempt opt-ins below reserve the selected full-run budget.
  Failed/unknown outcomes lock further dispatch. Reservations are not bills.
  Credentials remain workload-identity-only, not values.

### Explicit model-policy limits

For a new three-turn writer/reviewer/revision run with the larger input bound:

```yaml
model:
  policy:
    maxAttempts: 3
    maxInputTokens: 32768
```

`maxAttempts` defaults to 2, which renders policy version 1 without a
`maxAttempts` field. Setting 3 renders version 2 with `maxAttempts: 3`; these are
total dispatch attempts, not retries. Omit `maxInputTokens` to retain 8192;
32768 is the only accepted explicit value. Completion remains 4096, including
reasoning. The host uses the selected limits in request/usage checks and its
USD2 worst-case reservation. Older host binaries reject the input-limit field;
use an image supporting it. This configuration is not live-model qualification.

Helm removes null keys during values coalescing. An explicit null for either
setting selects that setting's safe default (two attempts or 8192 input), not
unlimited calls/tokens. The host's policy JSON itself rejects null.

Default rendered policy bytes are unchanged. Limits are part of the immutable
policy snapshot: do not change them on an existing run/ledger. Prepare a new run
ID and `persistence.subPath`, fence old writers and deliberately replace the
immutable ConfigMap as described below; an in-place Helm upgrade is not a budget
reset. Retain the prior journal/ledger and evidence. Input limits do not alter
historical requests or their hashes.

### Retained storage: no automatic initialization

**Required-mode authorization starts on a new private journal.** Ownerless
sessions are denied to everyone, including approvers; no automatic binding or
migration is supplied. Stop and fence old writers and retain their data as a
separate compatible set. Do not enable required mode against an existing auth-off
journal in place or replace a retained Canvas journal behind the same endpoint.
For unchanged required-mode restarts, preserve the new journal and its owners.
The [Sessions schema-v6 upgrade/rollback warning](../../docs/host.md#configuration-and-local-build)
still applies to older retained journals; a schema upgrade does not bind owners.

**Stop all previous writers before this release shares any PVC.** RWO,
`Recreate`, and pod affinity do not fence another release or old deployment.
Use `persistence.existingClaim` for retained data, or leave it empty to create a
PVC with configured size/class. Created PVCs have `helm.sh/resource-policy: keep`;
uninstall does not delete them and reinstall requires explicit ownership review.
No resize/migration, bootstrap Job, hook, root/chown, or recursive fsGroup runs.

Before enabling workloads, separately prepare `persistence.subPath` for UID/GID
65532 with private permissions and compatible initialized scenario files,
including `instructions.txt`, `tools.json` (Unix executor `/data/publish.sock`),
and the four private directories `tmp-daemon`, `tmp-fixture-harness`,
`tmp-executor`, `tmp-fake`. A newly created PVC alone is **not ready to run**.
Mounts expose only this subtree. The executor creates the shared Unix socket.
The harness writes `/data/fixture-node.json`; host startup refuses a missing or
mismatched node marker before journal access. Independently verify marker
freshness against live pod UID/node, node placement, restarts and start times.
Affinity is scheduling-time only, not a runtime or hostile-tenant boundary.

An unchanged run restart must preserve its exact policy, journal, ledger and
receipts. **A new run requires a separately prepared subtree**; never repoint a
new run ID at an old ledger, copy/reset a journal, or delete an unknown-outcome
lock. Reconcile state and authorize recovery separately. ConfigMaps are
immutable; in-place policy/auth edits intentionally fail. Stop writers and
review a deliberate replacement procedure before changing them, preserving
previous evidence. Schema migration/rollback compatibility is not guaranteed.

## Policy-first installation

The following are **operator instructions**, not actions performed by tests.
Replace the example context/namespace and supply reviewed `operator-values.yaml`.
Do not use the synthetic test fixtures for installation.

1. Complete the prerequisites above. Keep `networkPolicy.enabled: true`.
   Install the dormant release; this applies the NetworkPolicies with no pods:

   ```sh
   helm --kube-context my-aks upgrade --install agents ./charts/aks-durable-agents \
     --namespace agents -f operator-values.yaml --set workloads.enabled=false
   ```

2. **Apply/verify NetworkPolicies before scaling workloads.** Read back all
   rendered release policies (three normally, five with Canvas) and inspect every
   additive policy in the namespace:

   ```sh
   kubectl --context my-aks --namespace agents get networkpolicy -o yaml
   kubectl --context my-aks --namespace agents get deployment
   ```

   Confirm all Deployments have zero replicas, exact release/namespace selectors
   and expected rules. Independently qualify Cilium enforcement with approved
   network probes before proceeding; object existence is not proof of enforcement.
   If any rule/enforcement is unknown, stop. If chart policies are explicitly
   disabled, equivalent operator-managed isolation must already be verified.

3. Only after that gate, enable the **same** release without changing its policy
   or retained-storage inputs:

   ```sh
   helm --kube-context my-aks upgrade agents ./charts/aks-durable-agents \
     --namespace agents -f operator-values.yaml --set workloads.enabled=true
   ```

   Verify actual placement, marker freshness and readiness. Host may restart
   until the harness creates the marker; do not treat readiness as authorization
   to replay mutations. Before any isolation-affecting upgrade, scale to zero
   again and repeat the gate. No hooks enforce these operator checks.

The default deny selects this release only. Host can reach kube-system DNS
UDP/TCP53, public IPv4 TCP443 excluding private/link-local/loopback ranges, and
this namespace's exact harness selector on TCP9000. Harness ingress9000 is only
from this namespace's host selector; harness has no external/DNS egress allowance.
**Public443 is not model-domain enforcement.** Other additive policies can weaken
isolation. Containers within the harness pod can reach their own loopback, share
UID/storage and are not isolated from each other. No IPv6 allowance is added.

## Native document producer profile

Set `harness.native.enabled: true` explicitly. Supply `entries` from Canvas's
prepared inventory, with each exact immutable bundle ID and listening port:

```yaml
harness:
  native:
    enabled: true
    inventory: /data/producers/inventory.json
    entries:
      - id: bundle-v4-<actual-64-lowercase-hex-digest>
        port: 9000
```

The placeholder above is not deployable. Use 1–32 unique IDs and unique ports;
8081 is reserved for producer readiness. Inventory is fixed to the displayed path.
The chart cannot read the PVC: the operator must verify that configured entries
match the immutable prepared inventory and that its listeners bind the pod
interface (for example, prepare with `-bind 0.0.0.0` inside this private pod).

The native harness image must contain `/usr/local/bin/canvas-harness serve` and
support `-inventory` and `-ready-listen`. The host image needs `/host health-probe`;
`image.host.includesHealthProbe: true` remains an operator attestation. No fixture
binary, executor, fake inference sidecar, or fixture marker is used. Required-auth
TLS/token settings and host-only workload identity remain unchanged.

Separately initialize the retained subtree for UID/GID 65532 with private regular
archive files under `producers/`, plus `tmp-daemon/` and `tmp-producer/`. Do not
use projected ConfigMap symlinks or weaken archive validation. Only the archive
subtree is mounted read-only at the producer's `/data/producers`; it cannot mount
the host journal/ledger. A separate writable temp subtree is mounted at `/tmp`.
The chart still performs no initialization/chown Job or automatic migration.

One harness Service exposes exactly the configured ports using unique `grpc-N`
port names. Host arguments contain one exact Service/port exception per entry;
NetworkPolicy allows those ports only between the release's host and harness.
Producer `/readyz` on 8081 is not exposed through the Service or permitted from
application pods. Host readiness uses its own loopback TCP probe. Required
same-node affinity and single-replica `Recreate` remain; verify placement and
fence previous writers separately. This is not fixture-marker attestation.

The [local kind drill](../../ops/canvas/README.md) exercises the rendered native
profile with fake HTTPS inference and enforced Cilium denials. Its diagnostic
images and explicit trusted-network mode do **not** qualify AKS, workload
identity, authenticated callers, real inference, actions, or copied replay.

## Private Canvas engine profile

**Experimental, explicit auth-off trusted network only; identity is not
exercised.** This profile requires the separately reviewed Canvas hosted runtime
and matching engine/producer image receipts. The chart cannot attest binary
contents or runtime-image compatibility. Offline render tests do not qualify a
live PVC, Cilium, AKS, workload identity, real model calls, or replay. Remote
announcement/executor/operator replay remains unavailable until its separate
implementation; readiness is not permission to replay or infer.

Keep all existing host/model/native inputs and add these operator inputs (the
placeholders are deliberately not deployable):

```yaml
canvas:
  image:
    repository: <reviewed-registry/repository>
    digest: sha256:<actual-64-lowercase-hex-digest>
    includesHealthProbe: true
  enabled: true
  instanceID: <unique-project-instance>
  origin: https://127.0.0.1:9443
  sessionsTLSSecretName: <existing-host-tls-secret>
  tlsSecretName: <different-existing-engine-tls-secret>
  persistence:
    existingClaim: "" # Or an independently verified, prepared engine disk claim.
    size: 1Gi
    storageClass: managed-csi
harness:
  native:
    enabled: true # Also supply the exact prepared entries described above.
auth:
  mode: off
  trustedNetwork: true
networkPolicy:
  enabled: true
workloads:
  enabled: false
```

The closed schema requires explicit instance ID, HTTPS literal-127.0.0.1 origin
with canonical port 1–65535, both TLS Secret references, a digest-pinned engine
image and its health-probe attestation. `instanceID` is 1–63 lowercase ASCII
letters, digits or hyphens, starting with a letter, matching the runtime. Use a
separate instance/project/private state root per release. No credential or PEM
material belongs in values or ConfigMaps. `auth.tlsSecretName` and the required
mode auth ConfigMap are not used by this profile; required-auth and disabled
Canvas profiles retain their existing behavior.

### Separate disks, prepared files and writer fencing

The engine gets **only its own disk** at `/data`, never the host journal/ledger
or native producer mount. A newly created claim is retained (`keep`),
`volumeMode: Filesystem`, **ReadWriteOncePod**, default class `managed-csi`.
Use Azure Disk CSI with a POSIX filesystem; no Azure Files/SMB support is claimed.
For an existing claim, the operator must independently verify the underlying
Azure Disk, Filesystem/POSIX semantics, RWOP access mode and effective fencing
before enabling the release. Merely naming a different claim does not prove it
uses a different disk. The chart refuses a claim name shared with host/harness.

Before startup, with every prior writer stopped and fenced, prepare the engine
mount writable by UID/GID 65532. Supply real definition/layout/source-archive
files under `/data/definition/` (entry `/data/definition/canvas.yaml`), preserving
their normal source modes and the definition's relative paths. Prepare writable
`/data/home` and `/data/tmp`; these are `HOME` and `TMPDIR`. Do not put model keys,
Sessions credentials, or TLS keys on the engine disk. No registry fetch or
engine model egress is permitted. Do not use projected ConfigMap symlinks for
prepared definition/archive inputs or strip their normal read modes.

Leave `/data/state` absent for a fresh instance: the runtime creates a private
0700 **child**, not a state root at the PVC mount point. Preserve compatible
private state on restart. The runtime owns the stable lifecycle flock and
instance/definition/endpoint binding; the chart does not initialize, migrate,
chmod/chown, recursively apply fsGroup, reset, or repair old ownership. No init
container, hook or preparation Job is installed. Incompatible/unmarked/nonprivate
state must refuse rather than be adopted. Never change an instance/definition or
reset old state to get past refusal.

All three Deployments stay single-replica `Recreate`, with no surge; the engine
uses nonroot 65532, read-only root filesystem, all capabilities dropped, no token
automount, no workload identity and no sidecars. RWOP, Recreate and flock do not
replace operational fencing. Fence the old node/writer before force-detach or
recovery. Retain both disks and reconcile unknown outcomes. Endpoint metadata
binds the configured Sessions DNS endpoint, **not its journal/backend identity**:
a replacement host journal behind the same DNS is not detected by that marker.
Retain/fence the host PVC too; per-session UID/project/harness checks fail closed
on missing/moving evidence, not by creating replacement sessions.

### Two TLS hops, loopback port-forward and readiness

1. Supply a host Secret with `tls.crt`, `tls.key`, and `ca.crt`. Its leaf must have
   the exact rendered DNS SAN
   `<agents.name>-sessions.<namespace>.svc.cluster.local` (use the rendered name,
   including shortening/hash for long releases). Engine config pins that FQDN
   with `:8080`, explicit CA verification and no plaintext downgrade. The engine
   receives **only `ca.crt` via Secret items**, never the host private key.
2. Supply a **different** engine TLS Secret with `tls.crt` and `tls.key`; its leaf
   needs IP SAN **127.0.0.1**. Keep its issuing CA in the operator's local trust
   file for the adapter/browser. Secret file projections are read-only and
   readable by UID65532. Treat rotation of either TLS Secret/CA as requiring
   explicit affected-process restarts; no live reload is promised.
3. The headless engine runs `/usr/local/bin/canvas-engine -config
   /config/engine.json`, serving HTTPS **only on 127.0.0.1:8443**. There is no
   engine Service, Ingress, NodePort or LoadBalancer. For the example origin,
   an approved operator may forward the selected engine pod's port with
   `kubectl --context my-aks --namespace agents port-forward pod/<engine-pod> 9443:8443`.
   The local forward port **must equal `canvas.origin`'s port**; the pod listen
   port need not equal it. Do not expose the forward on a public interface.
4. Configure the local Canvas adapter with its explicit HTTPS engine URL
   `https://127.0.0.1:9443` and absolute CA-file reference (its version-1
   `CANVAS_ENGINE_CONFIG` file uses `engineURL` and `caFile`). Do not disable TLS
   verification or substitute ambient credentials. The iframe receives neither
   TLS keys nor Sessions/model credentials. This is a headless API plus a local
   adapter, not a public engine UI or sign-in flow.

Engine readiness executes `/usr/local/bin/canvas-engine health-probe
127.0.0.1:8081`; that command must perform bounded **HTTP GET `/readyz`**, requiring
status 200 and its command-owned response body. A TCP connect is insufficient
while initialization owns reserved sockets. The image's `includesHealthProbe`
value is an operator attestation of this behavior, not a chart implementation of
it. Host health remains loopback-only with its existing `/host health-probe`.

Engine configuration is public paths/identifiers only, a flat version-1 JSON
ConfigMap with an immutable content-hashed name. Changing the origin creates a
new ConfigMap reference and a Recreate rollout without changing `/data/state` or
implicitly migrating identity/state. Preserve instance/definition/endpoint
bindings; content hashing is not permission to change retained-state identity.

Use the policy-first gate above: **all three pods dormant, verify all five
policies and additive rules, then enable the same release**. The only new
application flow is engine → this release's host TCP8080 in the same namespace;
engine egress is that exact host selector plus kube-system DNS UDP/TCP53. Existing
host egress is unchanged, and the native harness still has no egress allowance.
The host uses `-addr=0.0.0.0:8080 -sessions-trusted-network=true` with both TLS
files even in auth-off mode. Health remains `127.0.0.1:8081`. NetworkPolicy is
**not authentication**: label identity is not exercised, selectors can be
spoofed by sufficiently privileged actors, and other additive policies can
weaken isolation. Do not enable in a hostile or unverified namespace.

## Offline verification

Pinned tools: **Helm 3.20.0** (`v3.20.0+gb2e4314`), **Python 3.14.3**, and
**PyYAML 6.0.3** (`tests/requirements.txt`). From the repository root:

```sh
python3 -B charts/aks-durable-agents/tests/test_chart.py
```

The suite runs strict `helm lint` and `helm template` offline with Kubernetes
1.37 for default-shape/required-auth and proof-shape/auth-off fixtures, compares
goldens, and checks schema failures and safety invariants. Canvas coverage checks
real rendered objects, exact JSON/host-argument fixtures, private TLS projections,
independent RWOP storage, selectors, security and disabled-profile compatibility.
Bare defaults refuse
rendering: real digests, identity, auth and pricing inputs are intentionally
missing. Fixture IDs and `a…`/`b…` digests are synthetic, not deployment receipts.
To deliberately regenerate and inspect goldens, append `--update-goldens`.

### Differences from the reference proof manifests

Names/selectors/namespace are release-scoped; chart adds its own default deny,
separate harness SA, optional retained PVC, secure required-auth default with
TLS/auth mounts, and explicit model scope. Proof fixture opts into auth-off and
one replica, retaining the two-pod commands, security, probes, data/socket paths,
same-node affinity and network rules. Init Job is deliberately omitted: preparing
retained data stays an explicit operator step, not a Helm lifecycle side effect.
The local proof's initialization/storage/cloud operations are not automated.
