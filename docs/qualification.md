# Qualification record foundation

[Docs index](README.md) · [Host boundaries](host.md)

`internal/qualification` is an **unwired internal foundation**, not an operational
candidate runner. The host executable does not open this store or expose its
methods. No RPC accepts a verdict, no suite is loaded, and no model or tool is
called. Tests use synthetic host-owned plans and Sessions journals; they do not
qualify a candidate or deployment.

## Trusted inputs and verified references

The future trusted host runner supplies an immutable plan containing the exact
suite, binding, runtime profile, model, judge and policy digests; complete member
inventory and selected member/composition/platform; case/input digests; explicit
repetition counts and thresholds; assertions; and expiry. Missing, duplicate or
unsupported inventory refuses admission rather than being omitted. The package
does not independently resolve an OCI artifact: that remains a runner prerequisite.

Admission is idempotent by workspace, target and request key. An exact duplicate
returns the original record, including after restart or terminalization. Changed
inventory, binding or requester conflicts. These fields are trusted host inputs,
not authenticated caller claims or proof of resource authorization.

The package-private completion path retains journal observations and derives the
verdict; it does not accept a passing-result flag. Every case repetition must be
present in order. It checks dedicated session/execution uniqueness, record count,
contiguous sequence, hash chain and independently retained terminal head.
Session IDs are host-retained labels, not independently attested fields inside
Sessions event records; execution IDs are checked against every event. The
narrow journal profile requires execution start, one input, one model call, one
text output, optional usage and a completed end. Tool/approval/lifecycle/error
records, incomplete executions or alternate payloads cannot pass.

Text contains/notContains/RE2 checks are recomputed. Tool-not-called checks require
the entire tool-free profile. Each judge assertion needs two separate retained
score calls, bound to assertion, candidate-output digest and expected judge model.
The recorded host model-call identity must also match the expected judge model;
matching only the model name inside score text is insufficient.
The current synthetic judge input is a closed version-1 JSON binding object,
not a production judge prompt. Both scores at/above threshold pass; both below
fail; disagreement, malformed scores or missing evidence make the run incomplete.
Known assertion failures count against each case's explicit minimum passes; any
incomplete observation vetoes the whole run.

`VerifyForActivation` rereads the retained bytes, recomputes the derived pass and
requires an independently supplied exact expected plan and unexpired time. It
returns only a checked record reference. It does **not** authorize activation.
A future activation controller must call it inside its current-policy/target gate;
a historical passing record must not be cached as unconditional eligibility.
`Read` checks record integrity only, not complete evidence or current eligibility.
Neither method advances work or dispatches model/tool calls.

The trust root is host-owned storage and future trusted runner provenance.
Hashes detect corruption and partial tampering relative to retained anchors, not
an operator rewriting the database and every evidence object. Journal chains
alone do not detect tail deletion or a fully rewritten chain. There is no external
attestation, anti-rollback, malicious-host resistance or sandbox guarantee.

## Storage and recovery

`Create` exclusively initializes a new private directory. `Open` only opens existing
state with an independently retained expected lineage; it never initializes missing
or empty state. Keep that lineage in host configuration/recovery metadata, not
inferred from an untrusted directory. Failed initialization leaves an unusable
partial directory requiring operator investigation, not automatic adoption.

Schema version 1 uses a separate SQLite database, private lineage anchor, writer
lock and hash-addressed evidence directory. Existing Sessions/model/executor
schemas are untouched. On Linux/POSIX, the store requires 0700 private directories
and 0600 regular files (including a 0700 parent directory for creation), refuses
symlinks and unsafe SQLite sidecars, and holds an
exclusive nonblocking file lock for its lifetime. It uses FULL synchronous DELETE
journaling and connection-local settings survive connection replacement. Foreign
lineage/future schema refuses before writable database PRAGMAs. There is no
active-active writer or old-writer fencing guarantee across restored copies.
Persisted field names and UTC time encodings are part of schema version 1;
renaming them requires an explicit format/compatibility change.

Evidence objects are synced before a terminal transaction references them.
An abandoned temporary file or unreferenced object is inert; a missing/corrupt
referenced object refuses eligibility. Database transactions and filesystem writes
are not one atomic operation. Per-run bounds are 64 planned journal slots, 256 KiB
per blob and therefore at most 16 MiB of planned evidence. Admission also bounds
metadata before execution; oversized plans refuse rather than truncate.

The lifecycle is admitted → running → verifying → passed/failed/incomplete.
Interruption explicitly records incomplete and advances the generation so a delayed
worker cannot finish it. Terminal records are immutable; exact completed retries
read the saved result. Restart does not auto-Resume, allocate sessions, retry calls
or infer that an uncertain attempt was safe. A failed completion transaction needs
same-key read-back and reconciliation, not a new automatic run.

Stop and fence all writers before backup or restore. Retain this store, its anchor,
evidence, expected lineage, original Sessions journals and model-attempt ledgers
in one coordinated recovery set. Existing backup recipes do not provide semantic
integration or prove this set's continuity. Restore offline and reconcile before
allowing new work; do not erase missing/corrupt state to obtain a new lineage.
A crash during an uncommitted SQLite write can leave a hot rollback journal.
The read-only identity preflight intentionally refuses such a store as an integrity
failure rather than performing recovery writes before identity verification. Keep
it fenced and preserve the full set for offline operator recovery or restore from
a verified coordinated snapshot. This package does not supply that recovery tool;
ordinary post-commit restart is tested, not automatic recovery from every crash.
Private journals may contain sensitive inputs/outputs: do not log them or publish
them as default diagnostics. Production retention/export/deletion remains a
release gate; this foundation does not garbage-collect evidence.

## Prerequisites for an operational runner

The following remain separate work, not functionality supplied by this package:

- Verified immutable artifact handoff and suite-derived complete inventory;
  exact runner renderer/harness/runtime profile matching the intended live target.
- Candidate/live isolation, deny-effects dispatch, scoped request/read/service
  authorization and no service self-approval.
- Reviewed repeated/duplicate-call identity and retry semantics in the model
  ledger **without weakening double-spend protection**. Current normalized-body
  hash uniqueness blocks identical repetitions and independent identical judge
  requests; fresh session IDs do not fix that. No prompt nonce or fresh ledger per
  duplicate may silently evade the restriction.
- An explicit aggregate qualification budget for separate candidate/judge model
  deployments. Multiple independent per-deployment caps are not one bounded run.
  Host-created policies and ledgers must bind to the run and frozen binding;
  failed/unknown calls remain stop conditions, not ordinary assertion failures.
- Real runner-to-store evidence, current-policy activation integration and
  separately approved live-model/deployment/restore qualification.

Until those boundaries are implemented and tested, an internal synthetic pass
cannot make an unactivated suite eligible on the running host.
