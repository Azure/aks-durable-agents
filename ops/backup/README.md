# Stopped-writer backup and isolated restore

For the chart's **single-writer SQLite, release-notes v2 experimental proof**. This is
an offline recovery recipe, not HA or continuous backup. It gives a point-in-time
copy **while all writers are stopped**. The operator chooses backup frequency,
RPO, downtime/RTO, encryption, retention and erasure. The local kind rehearsal is
not an Azure Disk recovery-time measurement.

## Preconditions

- Python 3.13+, kubectl, namespace read/create/delete Pod permissions, Deployment
  scale permission, and permission to create a fresh recovery namespace/PVC/policy.
  Every command below pins a private kubeconfig and context.
- Freeze Helm upgrades, GitOps, HPA, CronJobs and every other actor that might
  create a journal/receipt/ledger writer. Keep that fence until backup finishes.
  The script rejects writer HPAs, nonzero chart replicas and **any nonterminal
  Pod mounting the source PVC**, including unlabelled/terminating Pods. These
  checks do not fence a concurrent Kubernetes administrator or reconciler.
- Install [no-network.json](no-network.json) as
  `/var/lib/kubelet/seccomp/ops-backup-no-network.json` on every eligible Linux
  amd64 node using your approved node-management process. It denies new sockets
  (including Unix sockets) and io_uring. Missing profiles fail closed. The helper
  also drops capabilities, disables privilege escalation and mounts no API token.
  A fresh namespace denies ingress/egress; replay tests actual socket denial,
  rather than relying on a particular CNI's NetworkPolicy implementation.
- Build the helper from the **reviewed digest-pinned host image** containing both
  `/host` and its matching `/session-fixture` binary. The root Dockerfile alone does
  not supply the chart's fixture/probe. No executor is launched by the helper.

```sh
docker build -f ops/backup/Dockerfile \
  --build-arg HOST_IMAGE="$APPROVED_HOST_IMAGE_BY_DIGEST" \
  -t "$HELPER_TAG" ops/backup
# Publish through your approved image pipeline, then use its immutable digest.
HELPER='registry.example/backup@sha256:<verified-digest>'
```

Backups contain session content, receipts, identity metadata and ledger state.
Use private local storage and operator-managed encryption/retention. SHA-256
checks detect corruption, **not authenticity**; keep the printed archive digest
in a separately trusted record. Never restore an untrusted archive/image.

## Backup

```sh
python3 ops/backup/backup.py backup \
  --kubeconfig "$PRIVATE_KUBECONFIG" --context "$CONTEXT" \
  --namespace "$NAMESPACE" --release "$RELEASE" \
  --pvc "$SOURCE_PVC" --subpath "$DATA_SUBPATH" \
  --image "$HELPER" --output "$PRIVATE_BACKUP/archive.tar.gz" --stop
```

`--stop` scales **both** chart Deployments to zero: host and harness, whose Pod
contains the receipt-store executor. It waits for their Pods to disappear and
checks all PVC consumers before and after copying. Without `--stop`, the command
refuses unless both Deployments are already zero with no remaining consumer.
Do not use a bare `.db` copy or run SQLite commands against a live/source file.

A short-lived Pod mounts the source PVC **read-only**. It copies the whole data
subtree, including SQLite WAL/rollback sidecars, to scratch before opening any
SQLite file. Before SQLite can discard a corrupt WAL suffix, it validates copied
WAL headers, salts, frame checksums and complete committed boundaries. Invalid,
uncommitted or stale tails and nonempty rollback journals fail closed for separate
operator recovery; this is not a forensic salvage tool. It then checkpoints,
integrity-checks and switches only scratch copies to DELETE journal mode, producing
self-contained database files. The
archive includes journal, publications/receipts, model-budget ledger, instructions
and scenario evidence. Runtime sockets and the chart's four `tmp-*` trees are
excluded; private empty tmp directories are recreated at restore.

`manifest.json` records raw-copy and final SHA-256 inventories, SQLite inventory,
exclusions, time, source PVC UID, prior replica counts, image references and the
host model policy. The transferred archive is hash/integrity-checked locally.
On success the reader is removed and prior replica counts are restored. A failed
copy/check leaves writers stopped; inspect the error and manually recover rather
than blindly restart. A rollout failure also returns failure. The output path
must not exist; partial/failed archives are removed. Keep chart/auth/TLS inputs
separately: this is a data backup, not a Kubernetes/credential backup.

## Restore and strict replay

```sh
python3 ops/backup/backup.py restore \
  --kubeconfig "$PRIVATE_KUBECONFIG" --context "$CONTEXT" \
  --namespace "$NEW_RECOVERY_NAMESPACE" --pvc "$NEW_RECOVERY_PVC" \
  --subpath "$DATA_SUBPATH" --storage-class managed-csi --size 1Gi \
  --image "$HELPER" --archive "$PRIVATE_BACKUP/archive.tar.gz" \
  --session "$RECORDED_COMPLETED_SESSION_UID"
```

Namespace and PVC are **created, never reused**. Hashes and SQLite integrity are
checked before data is written to the empty new PVC. Restored directories are
0700, files 0600, owned by UID/GID 65532. Provision enough space; helper scratch
is limited to 4 GiB and 1 GiB memory. Larger datasets need a separately qualified
resource change, not a larger timeout.

The restore writer Pod is deleted. A separate recovery Pod mounts the restored
PVC **read-only**, probes socket denial and copies it into writable scratch.
The host image's offline recovery entrypoint runs:

```sh
/session-fixture verify-replay --scenario v2 --journal SCRATCH/journal.db \
  --instructions SCRATCH/instructions.txt --session RECORDED_UID
```

This is strict controller replay, not the Sessions event-listing RPC. It requires
matching recorded harness identity/instructions, a nonempty terminal session,
`completed: true`, matching expected/covered execution IDs, `provider_calls: 0`
and `executor_calls: 0`. Missing required v2 evidence/receipt/ledger files fails.
There is **no serving Sessions host, executor, Service, cloud identity or model
client** in this recovery path. All new sockets are forbidden. Replay changes
only scratch; restored-PVC hashes and UID/modes are re-verified afterward.
The command removes its helper Pods, but leaves the isolated namespace/PVC for
inspection, including on failure. It never changes the production claim.

## Operator switchover — deliberately manual

1. Keep recovery isolated. Preserve the archive and its trusted digest, original
   claim, original Helm values, images, matching sessions schema/harness version,
   policy and receipts. Do not test using an older daemon that cannot read schema v5.
2. Reconcile **external effects since the backup** against the executor's durable
   receipts and the external system. Restore cannot undo a publication/payment or
   prove a timed-out request did nothing. An **unknown outcome stops recovery**:
   investigate; do not retry, reset the ledger, invent a receipt or blindly resume.
3. Fence and stop both production Deployments again; verify every old writer is
   gone. Restore the approved journal, receipt store and model ledger as one set.
   Retain the exact model-policy `runID`/ledger association; a new budget/run ID
   must not be pointed at an old journal/ledger. Reconcile consumed budget too.
4. Only after reconciliation, prepare a separately reviewed chart release in the
   target namespace using `persistence.existingClaim`, the restored `subPath`,
   exact images and saved policy. PVCs are namespace-scoped: do not pretend the
   original release can reference a recovery-namespace claim. Re-provision auth,
   TLS, workload identity and network policy through the normal deployment recipe.
   Start dormant, validate node marker/co-location and policy, then enable both
   workloads. Review traffic/client switch separately; keep the old PVC retained.
   Helm `workloads.enabled` controls replicas, so do not unfreeze upgrades early.
5. After explicit acceptance, delete the isolated drill/recovery namespace using
   the pinned context and the operator's PVC/PV retention policy. Never delete
   the production claim as part of this script.

## Local kind rehearsal

Supply the matching operator-built static fixture and native driver; they are
not vendored into this repository. Their source/build recipe is not supplied;
this is not a self-contained public distribution. No Azure access or real model
is used. Images must expose the fixture as `/session-fixture`; update older
operator-built images and launchers for that path and the `ADA_FIXTURE_BINARY` /
`ADA_NATIVE_BINARY` environment inputs. Keep existing data and ledger identities
unchanged; renaming an example is not a retained-data migration.

```sh
python3 -B -m unittest discover -s ops/backup -p 'test_*.py'
python3 ops/backup/drill.py --fixture /absolute/path/session-fixture \
  --client /absolute/path/sessions-rpc --evidence /private/path/kind-backup-evidence
```

The drill builds a **local-only** host with an injected fake credential/TLS model
and uses the real host assembly and chart. The injection lives in the internal
host package; normal host flags, environment and auth JSON cannot set it. The
production Dockerfile and host CLI have no fake-model switch. Local drill images
must not be published or used for a real deployment.

The drill applies the chart's exact rendered workload resources on cached kind
Kubernetes **1.32.2**, using Helm's `--kube-version 1.37.0` to render. The chart's
metadata requires 1.37; this rehearses data recovery, **not Helm-install or AKS
1.37 qualification**. It does not change the chart's version floor.

The drill-owned cluster uses a private kubeconfig, installs the seccomp profile,
records a completed session/receipt, exercises live-writer refusal, backup and
isolated strict replay, and is deleted in a `finally` block. Evidence stays
outside Git. See the drill output for actual measured results and negative tests.
