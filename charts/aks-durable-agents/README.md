# aks-durable-agents

Experimental Helm chart for the loopback sessions host. Its `appVersion` is
`experimental`, not a source commit or built-image identity. The default legacy
profile installs two single-replica
`Recreate` Deployments (host; harness/executor/inert fake), a harness-only
ClusterIP Service, separate ServiceAccounts, immutable configuration, three
NetworkPolicies, and optionally a retained RWO PVC. **Workloads start at zero
replicas.** No sessions API Service or Ingress is installed; sessions `8080` and
separate host health `8081` listeners remain loopback-only. The opt-in
[native document producer profile](#native-document-producer-profile) replaces
the fixture harness/executor/fake pod without changing the legacy defaults.

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
  `allowedClientIDs`, `requiredScope`, and explicit `{issuer, subject}` approvers.
  Each approver `issuer` must equal `auth.issuer` exactly; with `subjectClaim: oid`
  each `subject` must be a lowercase object ID GUID, and with `sub` it must have
  no ASCII whitespace or control characters. Values that rendered before can now
  fail install/upgrade; fix the approver's `issuer` or `subject` (lowercase GUID
  for `oid`), not `subjectClaim`.
  Supply an existing `auth.tlsSecretName` with `tls.crt`/`tls.key` readable by
  UID65532. No credential material belongs in values; the chart creates no Secret.
  Required auth is **admission-only**, not sessions resource enforcement or
  authenticated two-human approval. Off requires explicit `trustedNetwork: true`.
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

2. **Apply/verify NetworkPolicies before scaling workloads.** Read back all three
   rendered release policies and inspect every additive policy in the namespace:

   ```sh
   kubectl --context my-aks --namespace agents get networkpolicy -o yaml
   kubectl --context my-aks --namespace agents get deployment
   ```

   Confirm both Deployments have zero replicas, exact release/namespace selectors
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

## Offline verification

Pinned tools: **Helm 3.20.0** (`v3.20.0+gb2e4314`), **Python 3.14.3**, and
**PyYAML 6.0.3** (`tests/requirements.txt`). From the repository root:

```sh
python3 -B charts/aks-durable-agents/tests/test_chart.py
```

The suite runs strict `helm lint` and `helm template` offline with Kubernetes
1.37 for default-shape/required-auth and proof-shape/auth-off fixtures, compares
goldens, and checks schema failures and safety invariants. Bare defaults refuse
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
