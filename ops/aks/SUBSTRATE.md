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

Only after the target and exact change list are approved, use:

```sh
python3 -B ops/aks/substrate.py --source "$SUBSTRATE_SOURCE" \
  --image-map "$SUBSTRATE_IMAGES" --nodes "$SUBSTRATE_NODES" \
  --apply --kubeconfig "$KUBECONFIG" --context "$AKS_CONTEXT" \
  --ate-setup "$SUBSTRATE_TOOLS/ate-setup" --ate "$SUBSTRATE_TOOLS/kubectl-ate"
```

The preflight must bind the selected kubeconfig server to the Azure target and
validate repository/purpose/run ownership, API discovery, selected nodes and fresh
runtime names before mutation. Tool subprocesses inherit the explicit context and
the same deadline. A fixed proof is emitted only after the actor check succeeds;
no source stdout, bearer tokens or counter payloads are forwarded to the console.

## Failure, evidence and cleanup

A failed or timed-out step is a failed install/check. Do not increase timeouts
to make it pass. Runtime objects may be present after a partial
failure; do not run a broad upstream uninstall against an uncertain cluster. Use
the owning disposable-cluster lifecycle's exact-target teardown and verify cluster,
managed node group and any owned federation are gone. The existing expiry sweeper
is only a backstop, not proof of successful teardown.

The smoke check removes only its exact Control objects and probe where possible.
It leaves the runtime for the owning cluster teardown. S3 credentials are generated
for this disposable install and referenced through a Secret; the dedicated upstream
setup commands create their own CA/JWT/config state. Never upload those secrets,
kubeconfigs, raw command output, runtime logs or actor payloads as public artifacts.
Only the fixed proof summary is suitable for collection.

Offline tests use synthetic image maps and mocked external commands. A render
against the exact upstream source can verify manifest adaptation, not image
pullability, API/admission behavior, runtime isolation, restore fidelity or live
teardown. A real run requires the operator's approval of the exact target and
change list. Sessions host wiring is a separate follow-up after the compatible
adapter merges.
