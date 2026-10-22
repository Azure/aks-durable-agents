# Manual AKS e2e and independent expiry cleanup

The dispatch-only **Nightly AKS e2e** workflow defaults to read-only identity/RG
validation. Its optional real-model scenario is separately operator-gated and has
**no schedule**. Offline tests do not qualify a live AKS deployment. The existing
kind workflow and its fake-model assertions are unchanged.

Keep the scenario disabled until the separate required-auth qualification has
passed Continue and strict replay, the helper publication is reviewed, and the
operator approves a manual scenario run. A schedule is a separate later change,
only after an accepted manual pass; this workflow cannot turn it on.

Read-only validation and independent cleanup always load trusted `main` code.
Scenario jobs pin checkout to the dispatch's immutable `github.sha`. Only `main`
and the exact `feat/aks-e2e-scenario` implementation branch are eligible; a first
branch run additionally requires an operator-approved temporary allowance for
that exact branch in `nightly-aks`. Do not allow PR/fork refs or arbitrary branches.
Remove the temporary allowance after qualification; keep `main` cleanup enabled.

## Operator configuration

Create the GitHub environment `nightly-aks` with a custom deployment branch rule
allowing only the `main` branch, not all protected branches and not tags. Do not
leave a mandatory per-run reviewer on an unattended environment. Supply these
**repository variables**, not environment-only variables or secrets:

| Variable | Value |
| --- | --- |
| `AZURE_CLIENT_ID` | CI managed identity client ID |
| `AZURE_TENANT_ID` | Dedicated test tenant ID |
| `AZURE_SUBSCRIPTION_ID` | Dedicated test subscription ID |
| `AKS_RESOURCE_GROUP` | Dedicated persistent cluster RG |
| `AKS_CLUSTER_NAME` | Single disposable cluster name |
| `AKS_NODE_RESOURCE_GROUP` | AKS-created managed node RG (do not precreate) |
| `AKS_IDENTITY_RESOURCE_GROUP` | Persistent model identity RG |
| `AKS_MODEL_IDENTITY_NAME` | Dedicated model managed identity name |
| `AKS_BOOTSTRAP_ENABLED` | `true` only after all setup has been reviewed |

The config check runs before requesting OIDC or entering the environment. Disabled
or absent enable flag means **not configured**, with no Azure login. Enabling an
incomplete/invalid configuration fails. A read-only dispatch verifies the selected
subscription/tenant and dedicated RG ownership; it does not prove model access,
quota, image compatibility, NetworkPolicy enforcement, replay or all role grants.

GitHub federation must match the repository's actual OIDC subject settings,
including immutable owner/repository IDs where enabled, and the `nightly-aks`
environment. Issuer is `https://token.actions.githubusercontent.com`; audience is
`api://AzureADTokenExchange`. Use short-lived OIDC, no client secret or PAT.

CI needs AKS lifecycle and Kubernetes cluster administration only on its dedicated
cluster RG; the model identity gets model use only on the selected model account.
The CI identity's federation-editing authority is restricted to that dedicated
model identity. Subscription-level reads for account/provider/RG metadata, compute
usage and AKS versions/operation polling are distinct from those write scopes.
Do not grant subscription-wide Contributor or node-RG deletion permissions.
No role assignment or persistent identity is created by these workflows.

## Cleanup ownership and lifecycle contract

**AKS expiry cleanup** supports manual `dry_run` (default **true**), a 15-minute
expiry sweep, and completion of exactly **Nightly AKS e2e**. Scheduled/completion
runs apply cleanup, but do nothing until configured. It never loads triggering
head code, artifacts, kubeconfigs or cloud configuration from a pull request.
Only the explicit configured targets are inventoried; Azure stdout/errors are
captured privately and only fixed status fields reach the summary.

A dedicated RG must have tags `ada-repository-id` equal to this repository's
immutable GitHub ID, and `ada-purpose=nightly-aks`. The single cluster must match
the configured resource ID, name and managed node RG. It additionally needs:

- `ada-run-id`: positive GitHub run ID;
- `ada-run-attempt`: positive attempt;
- `ada-expires-at`: exact UTC `YYYY-MM-DDTHH:MM:SSZ` expiry.

The model identity must contain **no unexpected FICs**. Its optional `nightly-host`
FIC must have the exact cluster OIDC issuer, audience `api://AzureADTokenExchange`,
subject `system:serviceaccount:agents:kaimahi-aks-durable-agents-host`.
Managed-identity FICs have **no description or tags field**: ownership/expiry must
come from the live matching cluster's tags, not fabricated FIC metadata. Cleanup
re-reads that proof and removes the matching FIC **before** requesting cluster
deletion. Removing federation blocks future exchanges; it does not instantly
revoke previously issued model tokens. If a FIC remains after the cluster is already gone at the start of a
later invocation, expiry/lineage cannot be independently proven: fail closed and
request operator recovery. Do not guess age or automatically delete that orphan.
Malformed/unknown ownership or API errors never count as absence.
Expired owned partial cluster creation may be removed before an issuer exists,
but a FIC can never be deleted with an unknown or mismatched issuer.

Cleanup re-reads the expired owned cluster and matching FIC, removes that FIC
first and confirms absence, then requests cluster deletion and waits up to three
minutes for absence. A later sweep can safely finish a slow tagged-cluster delete
without leaving a normal-path orphan FIC. Only after cluster deletion is confirmed
does it check managed-node-RG absence. An orphan
node RG is an operator recovery failure, never permission to delete an RG.

| Status | Meaning |
| --- | --- |
| `not-configured` | No login or inspection performed |
| `validated-read-only` | Account/RG preflight only |
| `absent` | No cluster, FIC or managed node RG remains |
| `would-delete` | Dry run; no deletion performed |
| `pending-unexpired` | Active cluster lineage retained |
| `pending-deleting` | Cluster deletion not yet complete; matching FIC already removed |
| `removed` | Cluster/FIC removed and managed node RG absent |
| `failed-closed` | Unknown/mismatched state, orphan FIC/node RG or unconfirmed cleanup; inspect privately |

An externally deleted cluster with a remaining FIC still requires operator
review; normal cleanup removes the FIC first, and adds no metadata store.
`pending-*` is not a claim of complete teardown. Cleanup is capped at ten minutes;
Azure asynchronous operations can outlive a runner. A budget alert is delayed
and does not stop resources. These controls are **not a hard-dollar cap**.
Environment-based federation also creates roughly 96 deployment records per day
for configured 15-minute sweeps.

Cleanup jobs serialize in `aks-nightly-mutations`, with cancellation disabled.
The scenario uses this **same job-level group for short cluster/FIC
mutation sections**, recheck state inside it, and refuse a new run while prior
resources remain. Do not hold the group across serving/model work or asynchronous
provisioning waits: an independent expiry sweep must not wait behind a hung
scenario. GitHub concurrency retains only one pending job: a newer arrival can
cancel an older pending teardown despite `cancel-in-progress: false`. An unlocked
finalizer makes cancelled/skipped/failed teardown a failed scenario; the expiry
sweeper is a backstop, never a successful teardown claim.

## Replay image prerequisite

The image pipeline publishes a separate `backup-helper.json` receipt; it does not
change the two-image chart-pin manifest. Before the scenario creates a cluster or starts writers,
its reviewed helper receipt must bind to the **actual chart-pinned host digest**,
not merely the latest published host. See [reference images](../images/README.md)
and [stopped-writer backup/restore](../backup/README.md). The existing two-image
`images.json` must bind both chart host and harness pins to the same source commit
as the helper receipt. Same host/wrong fixture is refused. Do not use a newly
published helper with older incompatible chart pins; first review the matching
image-pin update. Shape matching is not signature verification: the operator must
review the successful canonical publication, signatures/attestations and receipts.

The scenario installs only `ops-backup-no-network.json` on its two disposable
Linux/amd64 nodes through a narrow root DaemonSet. It drops capabilities, denies
privilege escalation, has no API token/identity/host network, mounts only the
kubelet seccomp directory and rejects existing drift/symlinks. It verifies the
root-owned 0644 file hash on every node and removes the installer before inference.
No shared cluster/node is touched, no chart root hook is introduced, and no new
node/autoscaling is permitted afterward. Recovery uses non-root Localhost seccomp
and actual socket-denial probes, not merely `--network=none`.

## CI runner tools and vulnerability policy

The installer pins kubectl **v1.37.1** and kubelogin **v0.2.21** with verified
SHA256 checksums. These binaries stay on the ephemeral runner; they are not
included in the host, fixture, helper images or restored workloads. The scenario
client and scanner build with the repository's declared `go.mod` toolchain,
without an independent Go version bump in this installer.

A separate credential-free CI job scans both executables. The scenario repeats
that scan within its work budget before Kubernetes credentials or inference.
Runner binary scans are **report-only**: every advisory is recorded, without an
exception list, in the run summary and separate seven-day two-file artifacts.
Scan errors warn and mean unscanned, not clean. Checksum/integrity failures,
cancellation and scenario-budget expiry still block. See the
[CI runner scan policy](TOOL-SCANS.md).

Our source `govulncheck ./...` remains strict and unfiltered. Image validation and
publication also require clean scans of the actual packaged Go executables;
runner advisories never bypass those gates. A source toolchain bump does not fix
upstream runner binaries or authorize a live scenario.

## Scenario opt-in and operator inputs

These **repository variables** are additional non-secret inputs. Do not set
`AKS_SCENARIO_ENABLED=true` before the qualification/approval gates above pass.
Setting bootstrap alone never enables provisioning.

| Variable | Required assertion/input |
| --- | --- |
| `AKS_SCENARIO_ENABLED` | `true` only after qualification and explicit manual-run approval |
| `AKS_BUDGET_CONFIRMED` | `true` after confirming the existing subscription budget/recipient is active |
| `MODEL_ENDPOINT` | Reviewed HTTPS endpoint ending `/openai/v1/`, no query or credentials |
| `MODEL_DEPLOYMENT` | Operator-verified available bounded model deployment |
| `MODEL_PRICE_INPUT`, `MODEL_PRICE_OUTPUT` | Positive integer microUSD per million tokens |
| `MODEL_PRICE_EXTRA` | Explicit `0` after checking there is no additional per-call charge |
| `MODEL_PRICE_SOURCE` | Verified public HTTPS pricing source |
| `MODEL_PRICE_AS_OF` | Verified `YYYY-MM-DD`, not future and at most 30 days old |
| `BACKUP_HELPER_IMAGE` | Reviewed canonical helper `@sha256:…` reference |
| `BACKUP_HELPER_RECEIPT` | Reviewed `backup-helper.json` content, unchanged closed schema |
| `PUBLISHED_IMAGES` | Matching reviewed two-image `images.json` content, unchanged schema |

CI has no model-deployment, pricing or subscription-budget ARM read grant; these
are operator assertions, not automatic live verification. No new Azure grants,
provider registration or persistent identities are created. Preserve identifiers
as variables only: they can appear in public step headers before runtime masking.
Never put credentials, private evidence, model prompts or user data in them.

After the gates, verify the exact reviewed commit/ref before an explicitly approved
manual command (not a command to run during offline implementation):

```sh
gh workflow run aks-e2e.yml -R Azure/aks-durable-agents \
  --ref feat/aks-e2e-scenario -f run_scenario=true
```

The default without `run_scenario=true` stays read-only. A requested scenario with
missing opt-in/budget approval fails before any environment/Azure login.

### What a manual scenario attempts

1. Refuse remaining clusters, model FICs or managed node RGs; check providers,
   stable AKS 1.37.0 availability, regional/family quota including one surge node,
   and anonymous public access to pinned host/fixture/helper images.
2. Under the short mutation lock, create a new two-node `Standard_D2s_v4` cluster
   in the dedicated RG, with Azure CNI overlay/Cilium, OIDC/WI, managed Entra Azure
   RBAC and local admin accounts disabled. Persist run/attempt/expiry tags before
   asynchronous creation; never adopt a previous cluster. Poll outside the lock.
3. Create only the exact host FIC for this owned cluster. Use normal cluster-user
   credentials plus kubelogin, not admin credentials. Install the chart dormant,
   initialize an empty private UID/GID65532 subtree before its tmp directories,
   verify retained chart policy objects and dormant positive/negative controls.
4. Perform a bounded credential-only WI propagation check (no inference probe),
   then enable the production host with real WI/model and **simulated approval**
   (`auth.mode: off`, `trustedNetwork: true`). Access is loopback API-server
   port-forward only; no ingress/public application service or human token.
5. Require eight policy-control records across dormant/live phases. Each source
   first proves a permitted path in its own Pod: untrusted-to-peer before
   untrusted-to-harness denial, and host-to-harness before host-to-peer denial.
   No additive allow policy is installed. Park after
   one known-successful bounded model attempt and zero effects. Restart only the
   host; prove the harness UID/marker/node, checkpoint and ledger unchanged.
   Approve without effect; Continue must produce exactly one publication, receipt
   and artifact without another model attempt. Never call demo seal/verify/meter.
6. Fence both source Deployments to zero and wait for PVC consumers to disappear.
   Call the existing backup tool **without `--stop`**, preserving that fence;
   restore into fresh recovery namespace/PVC with the matching helper. Require
   complete session/head/execution replay coverage, zero provider/executor calls,
   socket denial and unchanged hashes/evidence. No restored writers are started.
7. Attempt same-run teardown within the original hard deadline: only the exact
   run ID **and attempt** may bypass expiry. Revoke/confirm the FIC first, delete the cluster, then verify
   cluster/FIC/managed-node-RG absence. Namespace deletion is not cleanup. A failed
   delete may attempt bounded stop of only the positively owned eligible cluster;
   stop remains a failure, not zero residual cost or a cleanup success.

One immutable provisioning epoch supplies a 30-minute work deadline and 15-minute
teardown reserve across jobs and queue delays. Commands run in bounded process
groups, including backup descendants; the clock is not reset after host restart.
The unchanged model policy allows two total dispatch attempts, 8192 input/4096
completion tokens per attempt and a USD2 full-run reservation; the expected
scenario uses exactly one attempt, and failed/unknown outcomes stop it. No
inference retry, larger input bound, third-attempt opt-in or autoscaling is used.
Actions queue/cancellation/outages and Azure asynchronous operations can outlive
these controls. A teardown queued past the hard deadline cannot issue further
Azure commands; the unlocked finalizer fails and the trusted expiry sweeper is
the backstop, not confirmed cleanup. There is no Azure-enforced dollar cap. Budget alerts are delayed.
Orphan managed node RGs still require exact-scope operator recovery.

### Evidence and failure tracker

Only closed-schema `proof.json`, eight-record `network-proof.json`, `timings.json`,
failure-only `diagnostics.json` and optional `rollout-status.json`, and fixed
status/summary metadata are retained for seven days. The AKS collector ignores
console input entirely and refuses unknown
fields, malformed or incomplete proof, symlinks/nonregular files and oversized
data. Private command logs, model text, kubeconfig/cache, values, journals and
backup archives are never uploaded.

Failure diagnostics contain exactly `version: 1` and fixed-enum `phase`,
`operation`, `reason`, `cleanup` fields, never exception text or command output.
Install operations distinguish profile create/rollout/verify/remove/node-check,
namespace/volume create, chart install, policy check and fixture init create/wait/remove;
workload Deployment rollouts use `deployment-rollout`; other steps use the default
`phase` operation. Reasons are `deadline-exhausted`,
`command-timeout`, `command-failed`, `interrupted`, `invariant-failed`, `io-failed`
or `unclassified-failure`. These categories do **not** identify an underlying
pod/container root cause. The original failure context is captured before source
fencing; even if fencing also fails, its exception still takes precedence while
diagnostics retain the original context. `cleanup` is `succeeded`, `failed` or
`not-run` for that in-process **source fence only**, not Azure teardown.

Only failure/cancellation collection reads diagnostics; success ignores them and
still requires all three success proofs. Workflow stage is independent of scenario
phase. Missing, unsafe or malformed diagnostics produce `Diagnostics: unavailable`;
all failure summaries say `Underlying cause: not determined`. Publication is best
effort: invalid public directories, a hard kill or a diagnostic-write failure may
leave no diagnostics and never justify a guessed workload fix.

Optional rollout status has exactly six fields: `version: 1`,
`controllerKind`, `controllerName`, `podReasons`, `readyNodes`, `desiredNodes`.
Controller pairs are only `DaemonSet/nightly-profile`,
`Deployment/kaimahi-aks-durable-agents-host`,
`Deployment/kaimahi-aks-durable-agents-harness`, or `other/other`. Sorted, unique
reasons are limited to `ImagePullBackOff`, `ErrImagePull`, `CrashLoopBackOff`,
`CreateContainerConfigError`, `ContainerCreating`, `FailedMount`, `OOMKilled`, `Unschedulable`,
`readiness probe failing`, and `other`. The readiness label is reserved: core/v1
Pod status does not prove a probe-specific cause, so this producer never derives
it from generic unready state or messages. Unknown/unsupported status is `other`.
DS counts are integers 0..2147483647 or `null` (unknown, not invented zero);
Deployment/other counts are always `null`.

Only a failed rollout categorized `command-failed` permits optional read-only
capture: at most two GETs for a DS or three for a Deployment, sharing at most five
seconds of the **existing work deadline**, never the teardown reserve. Per-command
limits/request timeouts and checks before/after reads, parsing and projection
discard the entire capture on error, expiry or interruption. JSON parsing is not
hard-preempted at five seconds; an over-budget result is discarded. Source
selectors and verified controller ownership constrain attribution. Deployment
reasons aggregate live Pods from **all owned ReplicaSet revisions**, including
old revisions; deleting Pods are ignored. No Pod/node/container names, UIDs,
namespaces, labels, messages, events or logs are published. Fixtures are sanitized
API-shape examples, not historic live captures.

Failure/cancellation collection requires matching validated rollout diagnostics
before loading this optional file; missing/unsafe status says
`Rollout status: unavailable` only for a known rollout operation. Success ignores
it and still needs all three proofs. These categories are not a functional fix or
a root-cause determination, and source-fence status is not cloud teardown proof.

The separate bot-owned tracker is titled **AKS e2e regression**. Its managed body
contains only allowlisted stage, workflow URL and commit SHA; existing kind bot
validation/markers are preserved, and success never automatically closes it.
Review this outward template before approving a live run (no report is posted by
offline checks):

```text
<!-- aks-e2e-tracking -->

<!-- aks-e2e-status:start -->
Stage: teardown
Workflow: https://github.com/Azure/aks-durable-agents/actions/runs/RUN_ID
Commit: FULL_SHA
<!-- aks-e2e-status:end -->
```

A green simulated-approval scenario is **not** real delegated Entra approval,
required-auth/TLS, independent Azure billing telemetry, or hostile-tenant/model-
domain isolation qualification. Those limitations remain even after a manual pass.

## Offline verification

```sh
python3 -B -m unittest discover -s ops/aks -p 'test_*.py'
# Opt-in local Docker exercise only; never contacts AKS or a model.
RUN_AKS_CONTAINER_TESTS=true python3 -B -m unittest discover -s ops/aks -p 'test_profile.py'
actionlint .github/workflows/aks-e2e.yml .github/workflows/aks-cleanup.yml
```

Tests use fake Azure responses and commands, not live cloud resources. No nightly
real-model, delegated Entra approval, TLS or Substrate qualification is implied.
