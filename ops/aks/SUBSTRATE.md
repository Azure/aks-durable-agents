# Install-only Substrate on disposable AKS

This recipe installs **Substrate v0.5.0** and checks a native gVisor counter actor
on an already provisioned, explicitly owned disposable AKS cluster. It does not
install Sessions, change its adapter pin, make model requests, or qualify approval,
RAM recovery, cold restore or replay. The existing no-sandbox workflow is unchanged.
No live AKS execution of this recipe is claimed.

The snapshot store is a private **S3-compatible RustFS development service inside
AKS**, not Azure Blob. It and the PostgreSQL catalog are disposable. They remain
through an actor check but are lost with cluster teardown. This is an explicit
interim limitation, not a production snapshot/backup service.

## Lineage and changes for v0.5.0

The composition follows the earlier manually assembled AKS recipe: resolve
immutable images before provisioning, compose runtime manifests directly, use
private services and Secret references, remove GKE credential-provider paths,
use explicit contexts, and retain whole-cluster teardown. It does **not** run the
GKE provisioning/deploy installer or label every node. Earlier worker reassignment
and unchanged model-call counts did not prove an external restore or RAM-free boot;
this check makes neither claim.

| Earlier composition | v0.5.0 composition |
|---|---|
| Substrate `b1bd558aba3c5406f63b5114adf49623e5b50d7a` with local certificate-controller adaptations | Exact clean upstream `e8d40c33f96f4b7a4984bfea7334a36ab5b45b7b` (`v0.5.0`); no local source or Kubernetes SDK patches |
| ActorTemplate applied as a Kubernetes object | Atespaces, ActorTemplates and Actors are native Control API resources; WorkerPool and SandboxConfig remain Kubernetes CRDs |
| Valkey plus its TLS bootstrap | PostgreSQL catalog, certificate projections and the matching API connection configuration; no Valkey resources |
| Storage settings on atelet | Object-store plugin sidecars on atelet and the API, both pointing to the same private RustFS service |
| Six core runtime images | Resolve the selected v0.5.0 graph, including object-store plugin and Envoy dataplane/helper images, not only the old six binaries |
| Patched certificate controller for AKS's served API | Built-in certificate API discovery; preflight still requires the target to serve PodCertificateRequest and ClusterTrustBundle and support their projected volumes |
| Old sandbox configuration and snapshot defaults | String sandbox class `gvisor`, pinned gVisor assets, VOLUMES/durable-dir template and explicitly disabled golden snapshots |
| Private image-registry rewrite for locally built harnesses | Operator-reviewed immutable image inputs; no registry creation, image publication, Azure role assignment or Sessions harness image in the installer |

Worker readiness alone is not the actor check. It must establish a running actor,
its assigned worker and effective gVisor runtime, then obtain advancing counter
responses through the router. No configured runtime label or changed worker UID
can substitute for that execution evidence.

## Prerequisites and change boundary

Use a fresh dedicated AKS 1.37.0 Linux/amd64 cluster, not a shared platform or an
existing Substrate install. Provisioning, Kubernetes cluster-install permissions,
node sizing, Azure identities and the eventual whole-cluster teardown must be
approved separately. The planned profile is two fixed D4s_v4 nodes with Cilium;
actual quota, available allocatable resources, node images and admission behavior
must be verified for the approved target. The script does not create or resize
cloud resources, obtain admin credentials or relax existing cluster admission.

The installer needs normal cluster-user credentials with permission to install
its explicit CRDs, RBAC, signer and runtime objects. Node agents/workers are trusted
infrastructure: the v0.5.0 worker profile runs as root with capabilities including
SYS_ADMIN and Unconfined AppArmor/seccomp. It does not preserve the no-sandbox
fixture pod's restricted runtime profile. The fresh runtime/worker namespaces
therefore declare the scoped privileged Pod Security profile in the reviewed manifests; existing namespaces are not relabeled.
This is not shared-tenant authorization or hostile-tenant isolation qualification.

Prepare the source, tools, images and clients **before paid resources**. Obtain
node names and run metadata from the approved lifecycle once its target exists:

- A clean checkout of the exact source commit above. Do not substitute main,
  which has different module paths, worker names and suspend contracts.
- Prebuilt `ate-setup` and `kubectl-ate` from that checkout, with checked source
  provenance. Use the same source for the native counter actor image.
- An operator-reviewed image map of immutable digest references tied to that
  source. Availability of public runtime image releases is not assumed. Build,
  vulnerability review, registry publication and pull permissions are separate
  operations; this tool does not perform them.
- Python with the repository's pinned [chart test requirements](../../charts/aks-durable-agents/tests/requirements.txt),
  Go on `PATH` (for build-metadata verification), kubectl, Azure CLI and an
  isolated kubeconfig with an explicit context.
- Explicit approved node names, target/run metadata, and the original provisioning
  epoch. Installation and verification share the existing 30-minute work budget;
  they never reset it or use the 15-minute teardown reserve.

The pinned SandboxConfig downloads the public gVisor nightly 2026-10-10 asset
from `gs://gvisor/releases/` anonymously, checking the source's SHA-256. Node egress
to Google Cloud Storage is still required even though telemetry is disabled and
no GCP identity is used. A private-asset mirror needs separate review; never silently
rewrite the URL or place runtime assets under a snapshot prefix.

Control/API, router and snapshot services stay private. Router routing metadata
is not caller authentication. Restrict access to trusted operators on this dedicated
cluster; Kubernetes administrators and the runtime node agents remain trusted.
The tool refuses a pre-existing runtime rather than adopting or upgrading it.

## Prepare tools and review the render

Set `SUBSTRATE_SOURCE` to the clean source checkout, `SUBSTRATE_TOOLS` to a private
build directory **outside** that checkout, `SUBSTRATE_IMAGES` to the reviewed image
map, and `SUBSTRATE_NODES` to the comma-separated approved node names. Build tools
before provisioning the paid cluster:

```sh
mkdir -p "$SUBSTRATE_TOOLS"
go -C "$SUBSTRATE_SOURCE" build -mod=vendor -trimpath -buildvcs=true \
  -o "$SUBSTRATE_TOOLS/ate-setup" ./cmd/ate-setup
go -C "$SUBSTRATE_SOURCE" build -mod=vendor -trimpath -buildvcs=true \
  -ldflags='-X github.com/agent-substrate/substrate/internal/version.Version=v0.5.0 -X github.com/agent-substrate/substrate/internal/version.Commit=e8d40c33f96f4b7a4984bfea7334a36ab5b45b7b' \
  -o "$SUBSTRATE_TOOLS/kubectl-ate" ./cmd/kubectl-ate
go version -m "$SUBSTRATE_TOOLS/ate-setup"
go version -m "$SUBSTRATE_TOOLS/kubectl-ate"
"$SUBSTRATE_TOOLS/kubectl-ate" --version
```

Both tools must have the exact source `vcs.revision` and `vcs.modified=false`;
`kubectl-ate --version` must identify v0.5.0. Both tools support `--version`,
but the Go build metadata is authoritative for their clean source revision.
Do not use `-buildvcs=false`, locally patched tools or tools from Substrate main.

### Check Kubernetes admission before a live attempt

CI validates every rendered Deployment, DaemonSet, StatefulSet, Job and WorkerPool
for one, two and three approved nodes using server-side dry-run. It reuses the
local demo's owned kind runner and pinned Kubernetes 1.37.0 image, without running
the model demo or installing Substrate workloads. WorkerPool scheduling fields
are also checked as a core Pod, since CRD schema validation alone cannot check
all Pod semantics. A deliberately invalid multi-value node field selector must
be rejected. Each approved node has its own OR term with one `metadata.name` value.

With Docker, kind >= 0.33.0, kubectl 1.37 and Helm available, run the same check:

```sh
python3 -B ops/aks/check_substrate_manifests.py --source "$SUBSTRATE_SOURCE" \
  --directory "$(mktemp -d)"
```

Only namespaces and CRDs are created, in a fresh owned kind cluster that is
removed on exit. Synthetic digests are admission-only inputs: no Substrate images are
pulled and no AKS, runtime execution or image-publication qualification is claimed.
A passing check does not authorize another live attempt.

### Obtain the published digest map

The [existing image pipeline](../images/README.md#substrate-v050-inputs) builds the
pinned runtime, counter, Envoy dataplane and pause sources, then signs and records
their digests. After a successful main publication and anonymous verification,
download `verified-substrate-images` from **Verified image pins** and set
`SUBSTRATE_IMAGES` to its `substrate-images.json`. Do not substitute the earlier
unverified publication artifact, a tag or a synthetic test map. New GHCR packages
may need an administrator to make them public before verification can succeed.

The separate publication receipt records the workflow revision and Kubernetes
pause source; the installer's map keeps `sourceCommit` at the Substrate v0.5.0
revision above. Source-built pause 3.10.2 replaces the upstream pause digest in
that map. PostgreSQL, RustFS, AWS CLI, router Envoy and the Python probe retain
pinned upstream image inputs. The chart's host/harness pins are not changed.
Publication does not authorize a live AKS attempt; obtain a fresh exact-target go.

The image map is a JSON object with exactly `sourceCommit` and `images`.
`sourceCommit` is the full v0.5.0 SHA above. `images` maps each **original source
image reference** (including `ko://...`, third-party images and embedded dataplane
references) to the approved `registry/repository@sha256:...` reference. Include
`probe` as an additional key: its image must contain executable `python3` with
standard-library HTTP support. Every used reference must be resolved; a tag, a
missing key or a `latest` substitution is not an image receipt. Credentials do
not belong in this map. The selected source graph has eight `ko://` package
references (the seven runtime binaries plus `demos/counter`), five source-pinned
third-party images, the literal `${ENVOY_DATAPLANE_IMAGE}` map key, and `probe`.
Build that dataplane from the pinned source's `cmd/dataplane/envoy/Dockerfile`;
it is not another Go/ko binary. Preserve reviewed publication/source evidence for
all supplied references.

Unlike Kubernetes image pulls, actor image extraction is done by atelet. This
recipe removes the GKE credential provider and does not install an Azure image
credential provider or the older local-registry rewrite. The counter and pause
images must therefore be anonymously readable by atelet; Kubernetes/AcrPull
permissions alone do not prove actor-image access. Runtime/probe pull permissions
must also be ready before the approved run. No private-registry parity is claimed.

From the durable-agents repository, render without cloud or Kubernetes API calls:

```sh
python3 -B ops/aks/substrate.py --source "$SUBSTRATE_SOURCE" \
  --image-map "$SUBSTRATE_IMAGES" --nodes "$SUBSTRATE_NODES" > substrate-render.json
```

Review the rendered Kubernetes objects and native ActorTemplate as the exact
cluster-install change set. This is not a cloud plan, source attestation or live
image-pull check. Treat the file as private operator work rather than a public CI
artifact. No `--apply` means no Azure login, cluster mutation or actor request.

## Apply only after approval

Use an absolute isolated `AZURE_CONFIG_DIR`, explicit `AZURE_TENANT_ID` and
`AZURE_SUBSCRIPTION_ID`, and the owning disposable lifecycle's configured target:
`AKS_RESOURCE_GROUP`, `AKS_CLUSTER_NAME` and `AKS_NODE_RESOURCE_GROUP`. Supply
`GITHUB_RUN_ID` and `GITHUB_RUN_ATTEMPT` matching the target's ownership tags.
Neither a model identity nor `AZURE_CLIENT_ID` is required: this command uses the
already-authenticated isolated Azure session and checks its tenant/subscription.
The kubeconfig must be an absolute, private regular file (no symlink or group/other
permissions), with an explicit context. Preserve `AKS_STARTED_EPOCH` from
**before provisioning**, not the current time. Set `AKS_SUBSTRATE_ENABLED`,
`AKS_BOOTSTRAP_ENABLED` and `AKS_BUDGET_CONFIRMED` to `true` only for the reviewed target. Enabling GitHub
variables, creating roles or restoring an expired tenant is not done by this tool.
An operator must separately approve those changes if needed.

Choose `SUBSTRATE_EVIDENCE` as a **new** directory under an existing private
operator directory, outside the checkout. Apply now requires `--evidence-dir`;
existing directories and symlink paths are refused rather than adopted. The tool
creates it with mode `0700` and writes atomic `0600` files. It resolves the path
before upstream setup changes the working directory.

Only after the target and exact change list are approved, use:

```sh
python3 -B ops/aks/substrate.py --source "$SUBSTRATE_SOURCE" \
  --image-map "$SUBSTRATE_IMAGES" --nodes "$SUBSTRATE_NODES" \
  --apply --evidence-dir "$SUBSTRATE_EVIDENCE" \
  --kubeconfig "$KUBECONFIG" --context "$AKS_CONTEXT" \
  --ate-setup "$SUBSTRATE_TOOLS/ate-setup" --ate "$SUBSTRATE_TOOLS/kubectl-ate"
```

The preflight must bind the selected kubeconfig server to the Azure target and
validate repository/purpose/run ownership, API discovery, selected nodes and fresh
runtime names before mutation. Tool subprocesses inherit the explicit context and
the same deadline. The console success summary is emitted only after the actor
check and smoke cleanup succeed; no source stdout, bearer tokens or counter
payloads are forwarded to the console.

## Failure, evidence and cleanup

A failed or timed-out step is a failed install/check. Do not increase timeouts
to make it pass. Runtime objects may be present after a partial
failure; do not run a broad upstream uninstall against an uncertain cluster. Use
the owning disposable-cluster lifecycle's exact-target teardown and verify cluster,
managed node group and any owned federation are gone. The existing expiry sweeper
is only a backstop, not proof of successful teardown.

The smoke probe exits on SIGTERM and has a five-second termination grace period;
its existing 30-second deletion wait is unchanged. This does not alter worker or
runtime workload grace periods, resource requests or the overall budget.

Evidence separates verification from cleanup:

- `native-proof.json` is saved **before any smoke deletion**, only after two
  counter responses advance memory/file counts from 1 to 2 and the actor/worker
  identity remains stable. Its `nativePassed` status does **not** claim cleanup
  or overall success. A cleanup failure cannot erase this receipt.
- `native-result.json` records `nativePassed`, a failed error category, or
  `notReached`; it never contains raw actor or response payloads.
- `cleanup.json` records each owned smoke deletion as passed, failed or not
  reached. Ordinary cleanup failures do not skip remaining deletes or replace a
  primary verification error. Cancellation during verification still attempts
  owned cleanup. An interrupt during cleanup stops further cleanup commands and
  records the remaining actions as not reached.
- `install-result.json` records the overall result. Cleanup or evidence-storage
  failure remains a failed install with a nonzero exit, even if native proof passed.
- `steps.json` indexes commands using safe tool/operation labels and outcome
  categories. Each numbered `*.stderr.txt` retains stderr, including an empty
  file when the command emitted none. Failed and timed-out steps are included.
  Credentials are scrubbed **before** retaining a bounded 64 KiB tail. Redaction
  is best effort: keep these files private, review before sharing, and never
  publish them as CI artifacts. Stdin, stdout, arguments and environment dumps
  are not retained. Evidence-storage errors stop normal work but do not prevent
  remaining owned cleanup commands.

The smoke check removes only its exact Control objects and probe where possible.
It leaves the runtime for the owning cluster teardown. S3 credentials are generated
for this disposable install and referenced through a Secret; the dedicated upstream
setup commands create their own CA/JWT/config state. Never upload those secrets,
kubeconfigs, raw command output, runtime logs or actor payloads as public artifacts.
Only the fixed proof summaries are suitable for collection; a saved native proof
must always be interpreted alongside the separate cleanup and overall results.

Offline tests use synthetic image maps and mocked external commands. A render
against the exact upstream source can verify manifest adaptation, not image
pullability, API/admission behavior, runtime isolation, restore fidelity or live
teardown. A real run requires the operator's approval of the exact target and
change list. The host has separate [Sessions v0.3.0/Substrate v0.5.0 wiring](../../docs/substrate.md),
which requires a fresh compatible state set rather than an in-place runtime upgrade.
This install-only check does not connect that host to the runtime or nightly.

## Manual Sessions actor variant

`aks-e2e.yml` has an explicit `substrate-gvisor` choice. It is **manual-only**:
`run_scenario` remains false by default, `variant` defaults to `no-sandbox`, and
scheduled runs always select the existing no-sandbox case. No Substrate scenario
has been live-qualified by the offline/image/admission tests. A passing native
counter install does not authorize a Sessions run. Obtain a fresh operator go
for the exact target, node/request capacity, identities, model budget and inputs
before dispatch; do not enable the schedule as part of this qualification.

In addition to the existing operator/configuration/required-auth gates, selection
requires `AKS_SUBSTRATE_ENABLED=true` and explicit dispatch inputs:

- `variant=substrate-gvisor` and `run_scenario=true`;
- `substrate_publish_run_id`: a successful canonical-main **Images** run;
- `substrate_verify_run_id`: a successful canonical-main **Verified image pins**
  run exporting the exact same Substrate publication and 15-entry image map.

The pre-paid job validates both runs and map equality, anonymously pulls inputs,
rechecks owned signatures/SBOMs and runs the selected immutable application
harness's `actor-harness --check`. A legacy image without that entrypoint fails
**before provisioning**. It builds/scans pinned runner and native tools and
transfers their source/toolchain/map bundle to the scenario. Binary compilation,
anonymous pull and signature/SBOM verification finish before cluster creation;
cluster nodes still have to pull the published images when workloads start. Publication
still occurs only through the existing main Images success/signature gates.
No token, kubeconfig or Azure cache is in the prepared artifact.

The same original provisioning epoch bounds all installation, scenario and
cleanup work: **30 minutes + 15 minutes cleanup**, never separate per-variant
windows. Existing workflow node sizing is a candidate test profile, not a new
sizing approval. Recompute complete rendered requests including init/Always
sidecars/probes and system workloads before requesting the first live go. Keep
the D4 design recommendation; do not shrink host, worker or harness requests.
Actual peak memory, cost and timing fit remain unqualified.

### Assembly and proof boundaries

The released Sessions v0.3.0 adapter uses verified control TLS and a host-only
projected KSA token for audience `api.ate-system.svc`, with the live serving-DNS
ClusterTrustBundle. The private h2c router carries the host-initiated harnesswire
stream to actor port80; model/tool requests return on that stream. No actor→host
callback listener, host PVC or provider/executor credentials are needed.
The native template gates each Resume on HTTP `/readyz` at actor port8081,
served only after the harness listener is bound. The explicit 30-second probe
bound matches the native default and stays inside the original work deadline;
it is not a runtime retry or a larger run budget. The capability check requires
this readiness contract before accepting an image.

The chart's explicit `runtime.mode=substrate` renders host and **separate executor
Pods**, with same-node RWO affinity for their Unix socket. Executor has no WI or
control-token mount and default-deny network. The shared host Namespace's API
label also covers executor; host-only Pod selectors and executor egress denial,
not a claim of separate Namespaces, enforce that boundary. Actors use a fresh
owned WorkerPool/atespace/template; privileged node agents remain scoped to their
infrastructure. The installer-owned router overlay replaces the upstream
any-source data rule, permitting exact host Namespace+Pod labels and its own
smoke probe. Reapplying the overlay preserves this rule; inventory/UID and
additional Cilium-policy checks reject drift.

The frozen actor harness performs one real-model preparation, parks with zero
effects, and commits a ready external **VOLUMES** SUSPEND checkpoint. The host
restarts while the gate is pending. Simulated Approve records a decision only;
explicit Continue at the approved head resumes and produces one publication,
receipt and artifact without another model request. This is not approve-and-run
or delegated human/Entra approval.

Private evidence binds the session to actual actor UID/template/digest, observed
RUNNING gVisor placement before the harness invocation, authoritative worker Pod
UID/node and the exact journal-held newest VOLUMES snapshot. First placement is
immutable across host restart; latest may name a different worker after resume.
A template label, Pod RuntimeClass or counter actor is not this evidence.
Pre-cleanup native proof is separate from cleanup and overall results.

The `aks-substrate` public collector accepts only its closed proof/network/timing
schema, never raw identities, snapshot URIs, logs or private stderr. Positive
and negative caller controls include untrusted Pod and executor access to
router/control/model endpoints. These are **not guest-egress or hostile-tenant
isolation qualification**; public proof says `guestEgress=not-qualified`.

Finally, both trusted writers are fenced and a restored host archive runs the
same harness in strict offline terminal replay: complete coverage, zero provider
and executor callbacks, unchanged journal/ledger/effect inventories and effective
socket denial. This does not restore the Substrate catalog or snapshot objects,
prove a cold destination/worker replacement, or qualify Blob/MSHV/MEMORY/golden
snapshots, RAM-free boot, concurrency or production recovery.
