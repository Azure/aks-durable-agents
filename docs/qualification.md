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

Workspaces use the host evidence namespace: nonempty, valid non-control UTF-8,
at most 256 bytes, retained without renaming, truncation or normalization. Request
keys and other identifiers retain their narrower existing validation. Existing
valid records remain readable. Binaries with the former ASCII/128-byte workspace
restriction cannot reopen a store after a newly supported workspace is retained;
do not downgrade such a store to those binaries.

Admission is idempotent by workspace, target and request key. An exact duplicate
returns the original record, including after restart or terminalization. Changed
inventory, binding or requester conflicts. These fields are trusted host inputs,
not authenticated caller claims or proof of resource authorization.

The package-private completion path retains journal observations and derives the
verdict; it does not accept a passing-result flag. Every case repetition must be
present in order. It checks dedicated session/execution uniqueness, record count,
contiguous sequence, hash chain and independently retained terminal head.
Session IDs are host-retained labels, not independently attested fields inside
Sessions event records; execution IDs are checked against every event. Uniqueness
is enforced only within one qualification record, not across records. Binding the
journals to the exact subject/frozen binding and preventing cross-run execution
reuse are the trusted runner's responsibility; a structurally valid journal alone
does not establish those bindings. The
narrow journal profile requires execution start, one input, one model call, one
text output, optional usage and a completed end. Tool/approval/lifecycle/error
records, incomplete executions or alternate payloads cannot pass.

Text contains/notContains/RE2 checks are recomputed. Tool-not-called checks require
the entire tool-free profile. Each judge assertion needs two separate retained
score calls, bound to assertion, candidate-output digest and expected judge model.
The recorded model-call label must also match the expected judge model;
matching only the model name inside score text is insufficient. Sessions records
the harness's `req.Model` label before the host substitutes its selected
deployment. This label check is not proof of which deployment answered. The
future runner must independently bind both candidate and judge calls to their
host-selected deployments under the frozen binding.
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

## Pure candidate preparation

`internal/agentcontroller.PrepareCandidate` is a separate **unwired** adapter.
Given one already verified `agentpackage.Package` and host-selected expectations,
it derives a complete qualification plan and a non-authorizing summary. It does
not open this store, admit a request, register a harness, create a listener, call
a model/tool or alter live state. Existing host entry points do not call it.

Manifest, member, composition and platform expectations must match exactly.
An optional profile digest must match the derived native profile. The adapter
calls the existing pure `packagedHarness` validation/renderer directly: the native
system prompt, JSON escaping and host-selected deployment remain identical to
ordinary hosting. The summary distinguishes the authored model from that actual
deployment and retains exact verified source references/bytes and case inputs.
Deployment labels must fit qualification journals: 1–128 non-space printable
ASCII bytes. A label outside that contract refuses preparation.

Only the native one-member, tool-free profile with one evaluation index is
supported. Index/case/assertion order is preserved. Contains, notContains, regex
and toolNotCalled operands map without rewriting. Omitted runs default to one;
omitted minPasses defaults to runs. Any explicit `critical:false` refuses the
whole candidate with a plain reason: the current plan cannot preserve advisory
meaning. Judges, toolCalled, unknown assertions, absent inventory and any tighter
qualification bound also refuse wholly; no assertion is silently dropped.

The host and adapter share the existing capitalized frozen binding JSON shape
and serialization. BindingDigest hashes its retained-manager JCS bytes.
PolicyDigest hashes canonical policy bytes; ModelDigest binds endpoint,
deployment and effective scope, never the authored model. ProfileDigest binds
RunnerABI and exact native config; JudgeDigest identifies the fixed no-judge
profile. SourceDigest is domain-separated over the manifest and selected
member/composition/index digests: it identifies retained bytes, not Git provenance,
publisher trust or authority. Explicit expiry is normalized to UTC; no current
time is consulted. Returned plans and summaries are independently owned.

`qualification.ValidatePlan` reuses admission validation without storage or
schema changes. It reserves worst-case JSON-escaped valid request identities
alongside the plan, including the existing request/record metadata bounds.
Preparation does not qualify or activate anything; isolated execution, budgets,
evidence production and current-policy authorization remain separate work.

## Storage and recovery

`Create` exclusively initializes a new private directory. `Open` only opens existing
state with an independently retained expected lineage; it never initializes missing
or empty state. Keep that lineage in host configuration/recovery metadata, not
inferred from an untrusted directory. Failed initialization leaves an unusable
partial directory requiring operator investigation, not automatic adoption.

Schema version 1 uses a separate SQLite database, private lineage anchor, writer
lock and hash-addressed evidence directory. Existing Sessions/model/executor
schemas are untouched. On Linux/POSIX, the store requires 0700 private directories
and 0600 regular files, owned by the current effective UID (including a 0700,
current-owner parent directory for creation). Shared ancestors need not have that
owner or private mode. It refuses symlinks and unsafe SQLite sidecars, and holds an
exclusive nonblocking file lock for its lifetime. It uses EXTRA synchronous DELETE
journaling (including directory synchronization after journal removal) and connection-local settings survive connection replacement. Foreign
lineage/future schema refuses before writable database PRAGMAs. WAL-format
databases are rejected by their file header before SQLite opens them, because even
read-only SQLite access can create WAL/SHM sidecars in a writable directory.
Any existing WAL/SHM sidecar also refuses Open without modifying the recovery set.
Admission cancellation retains its context error rather than reporting corruption.
`ErrUnavailable` identifies closed storage and operational resource/I/O failures;
`ErrIntegrity` identifies failed identity, safety, content and recovery checks.
Errors expose no raw filesystem paths or SQL values. Unavailability does not prove
that a commit failed or make a new run safe: use same-key read-back/reconciliation.
There is no
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
same-key read-back and reconciliation, not a new automatic run. If completion
retained its verifying intent before cancellation or an I/O failure, an explicit
same-lease retry resumes only when the observations digest matches that intent.
It rereads the evidence and checks expiry again; changed observations or a fenced
generation conflict. Opening the store does not resume verification.

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

## Workspace conformance test

`TestQualificationWorkspaceJoin` uses the real decision ledger to record a
synthetic decision, then admits a qualification plan in the same workspace.
Both packages are now in the same source tree, so the test runs in ordinary CI
without a build tag. It checks namespace compatibility only, not an adapter or
activation authority. To run it directly:

```sh
go test -race ./internal/qualification -run '^TestQualificationWorkspaceJoin$' -count=1
```

Other qualification tests cover the UTF-8/byte-length boundaries and exact
workspace round-trip independently.
