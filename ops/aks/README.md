# AKS e2e bootstrap

This is workflow infrastructure, not a live AKS qualification. The dispatch-only
**Nightly AKS e2e** workflow performs read-only identity/resource-group validation.
It has no cluster provisioning, model request, Helm install or scenario schedule.
The existing kind workflow and its fake-model assertions are unchanged.

New dispatch and cleanup workflows must be merged to the default branch before
first use. Both workflows check out `refs/heads/main`; a dispatch on a feature
branch is not a way to execute that branch's scenario in this bootstrap.

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
Any future scenario must use this **same job-level group for short cluster/FIC
mutation sections**, recheck state inside it, and refuse a new run while prior
resources remain. Do not hold the group across serving/model work or asynchronous
provisioning waits: an independent expiry sweep must not wait behind a hung
scenario. Do not dispatch a scenario until it implements this contract and the
manual qualification/cleanup gates have passed.

## Replay image prerequisite

The image pipeline publishes a separate `backup-helper.json` receipt; it does not
change the two-image chart-pin manifest. Before a future scenario starts writers,
its reviewed helper receipt must bind to the **actual chart-pinned host digest**,
not merely the latest published host. See [reference images](../images/README.md)
and [stopped-writer backup/restore](../backup/README.md). Node seccomp-profile
installation is not part of this bootstrap; the existing helper fails closed
without it.

## Offline verification

```sh
python3 -B -m unittest discover -s ops/aks -p 'test_*.py'
actionlint .github/workflows/aks-e2e.yml .github/workflows/aks-cleanup.yml
```

Tests use fake Azure responses and commands, not live cloud resources. No nightly
real-model, delegated Entra approval, TLS or Substrate qualification is implied.
