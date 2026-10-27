# GitHub call records

`internal/githubtools` is a non-serving persistence foundation for a native
Sessions approval adapter, release evidence and GitHub comment intent/outcome
records. It is **not the [decision ledger](decision-ledger.md)**. That ledger's
parallel records remain non-executing and must not be used as native Sessions
Approve/Resume authority. This store does not change that contract or extend the
ledger schema. It follows the ledger's private-file, lifetime-lock, store-identity
and host-lineage conventions instead. This package has no host route,
credential, token-client or GitHub-call integration.

## Evidence and recovery

Trusted host code supplies the exact recorded call, verified requester and
approver, acting App/installation/repository identifiers, native request/decision
sequences and configuration digest. Constructing a value or persisting it does
not authenticate anyone or replace Sessions' decision and exact-call checks.
The host must serialize journal inspection, approval/recovery and dispatch.

A pending approval retains attribution before native Approve. Linking an exact
native decision commits its sequence without changing the original approver.
An abandoned pending attempt remains in audit history. The host may abandon it
only while holding its gate and after verifying that **no native decision**
exists; an RPC failure or timeout does not establish that. A committed attempt
cannot be abandoned. Replacement attempts keep identical call evidence.

`Reserve` atomically retains release evidence and intent before POST. Only its
`created=true` result permits that invocation to send. A stored success or
failure is returned on re-entry; a reservation without a terminal result is
unknown, including a crash before send. An unknown hold blocks further writes
in that session and the identical semantic operation under new keys/sessions.
The host computes that operation digest from the exact account, repository,
issue and comment, not a harness-supplied key. There is no automatic repost,
hold-clearing or reconciliation command. A definitive terminal outcome is not
global text deduplication: separately approved new work can use identical text.
Only bounded comment identity/URL or fixed failure codes are stored as outcomes,
never raw provider errors or credential responses. This is not exactly-once
remote delivery.

## Storage contract

`Initialize(absolutePath, hostLineageID, bindingDigest)` explicitly creates a new
store and random ID. Retain the expected ID, host lineage and configuration
digest separately with the journal's recovery configuration. `Open` requires
those expected values and never creates, adopts, repairs or migrates state.
Missing, foreign, truncated, unsafe or unknown-schema state refuses to open.
The experimental schema is not stable before the serving route ships; there is
no automatic migration for these preparatory stores.

The immediate parent must be owned and 0700, files/sidecars 0600, with no symlink
components. A separate persistent `.lock` is held before opening SQLite, through
the drain of admitted operations on Close. Do not remove/replace that lock while
writers can exist. Transactions use SQLite DELETE journaling, EXTRA sync and
foreign keys; connection settings are reapplied to replacement connections.
Errors expose stable sentinels, not SQL, paths or secret material. A failed or
cancelled commit is uncertain: inspect the same record, never retry a write with
a fresh key on the assumption it rolled back.

Keep this state host-private; a harness must not mount it or its parent. Stop
all writers and back it up with the journal, model ledger, lock and separately
retained identity/configuration. Restore must reconcile the full state set and
external effects since the snapshot before enabling writes; a point-in-time
restore cannot undo a GitHub comment. Unit tests do not qualify that deployment
or restore workflow. There is no HA, tamper-proof-audit or privacy-compliance
claim; identity/feedback records stay with the experimental recovery set without
automatic pruning, especially while an outcome remains unknown.
