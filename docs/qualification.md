# Qualification record foundation

[Docs index](README.md) · [Host boundaries](host.md)

`internal/qualification` is an **unwired internal foundation**, not an operational
qualification service. The host executable does not open this store or expose its
methods. No RPC accepts a verdict. A separate, unwired native execution seam in
`internal/agentcontroller` produces original candidate journals. Its durable
factory and `Store.Run` can retain and evaluate a complete no-judge run. Tests use host-owned plans, real
Sessions controllers and local fake models as well as synthetic fixtures; none
qualifies a live candidate or deployment.

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

Normal qualifying events must have the native reference host's unset schema tag
(`0`), as specified by Sessions LOG-4. The former schema-1 normal-event fixtures
were synthetic, not a supported producer compatibility profile. They are no
longer eligible; existing record integrity readback does not replace
`VerifyForActivation`'s current evidence check. No stored records are retagged or
migrated. LOG-4's `LIFECYCLE_DELETE` marker legitimately carries tag `1` in a
Sessions journal, but lifecycle/deletion tails are outside this narrow execution
profile. This is not a blanket rule that mixed tags invalidate a Sessions journal.

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
Preparation does not qualify or activate anything. Run-budget preflight and the
native execution seam below are separate library operations; durable evidence
orchestration and current-policy authorization remain separate work.

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

## Run-budget preflight

`qualification.PrepareRunBudget(BudgetRequest)` validates the existing Plan
bounds and derives the entire ordered call inventory: case, repetition (1-based),
candidate, then each judge assertion with samples 1 and 2. Missing/extra judge
bindings, conflicting binding IDs, over-budget or oversized inventory refuse
intact. Repeated equal requests retain distinct opaque semantic slot IDs; no
prompt nonces or per-case budgets. This is pure preparation, not model execution.

The result includes a typed `modeltransport.RunConfig` and semantic `BudgetCall`
mapping. One version-4 run policy reserves all calls across all supplied candidate
and judge bindings under the unchanged USD 2 ceiling and conservative per-call
8192 input (or explicit 32768) / 4096 output bounds. The existing 64-slot,
256-KiB blob and metadata/row bounds remain. Expensive plans may fit fewer than
64 slots; failure does not reduce inventory or allocate another cap.

Native callers use `agentcontroller.PrepareRunBudget` to take inventory from the
PreparedCandidate and check the candidate endpoint/deployment/scope against its
frozen native ModelDigest before delegating. The generic qualification function
alone does not verify that native tuple. Judge request labels must match explicit
host-supplied deployments, but the package-derived judge binding/digest preimage
is still undefined. Neither function proves judge provenance or supplies a
production judge prompt/rubric. Native PrepareCandidate still refuses judged
packages; synthetic judged plans exercise budget accounting only.

The run's PlanDigest is the existing normalized `qualification-plan-v1` digest,
matching Record.PlanDigest. Plan.Subject.PolicyDigest stays the original serving
policy digest. Dependencies go plan → run snapshot, never back into Plan; any
future runner/record linkage belongs outside that immutable Plan. Creating a
budget is not qualification, eligibility or authority to send. See the
[transport budget contract](../modeltransport/README.md#shared-run-budget-library-only-version-4).

## Native execution seam

`agentcontroller.NewCandidateExecutor` takes a verified package, frozen
expectations and trusted `ExecutionConfig`: an explicit run ID, already-open v4
Policy, injected model credential, optional transport and private journal factory.
It reconstructs the native renderer and complete no-judge inventory, then compares
the entire compiled v4 snapshot to the supplied immutable policy before any
journal, token or provider I/O. It does not accept a mutable preparation summary
as executable instructions. Prices are frozen operator inputs, not verified
provider billing.

`Execute` accepts only the next planned slot. Each repetition uses a fresh,
run-scoped Session UID, empty journal and actual native harness/controller, with
the frozen deployment and host-side 25-second model callback. Legitimate identical
bodies use distinct slots in the same shared ledger. Returned original records,
head and execution anchors carry no verdict. Mechanical failure, cancellation or
unknown dispatch stops later calls; completed wrong answers remain observations
for the qualification evaluator, not an execution short circuit.

The host-owned journal factory must supply candidate backing, never the serving
store. The adapter checks freshness, not the physical identity of an opaque
`eventlog.Store`. It creates no registry entry, Sessions service, listener or
runtime socket and exposes no ordinary Exec/Resume/Fork path. It executes only
the existing tool-free built-in harness; packages cannot run scripts or select
credentials/routes. Model credentials stay behind modeltransport. This is logical
Session/data separation inside the trusted process, not an OS, pod, network or
hostile-UID sandbox. Model labels are not provider attestation.

`Close` rejects new work, cancels and drains its active execution. The caller must
keep its Policy and journal backend open until that finishes, then close its own
resources. Original partial journals remain with their owner; there is no retry,
recovery adoption, automatic deletion or GC. No host entry point calls this seam;
authenticated request handling remains unwired. Durable ownership and evidence
completion are separate host-only operations below. Registration, activation and Ready behavior are unchanged.

## Durable no-judge orchestration

`Store.Run(ctx, recordID, factory)` starts an admitted record once, then supplies a
non-authorizing `ExecutionScope` to a trusted host `ExecutorFactory`. The run ID
hashes store lineage, record ID and lease generation; session IDs additionally
bind each planned slot. Different records may have identical plan/slot IDs but
must own different ledgers and journals. The runner compares the executor's
plan, model labels and complete ordered no-judge inventory before execution. Each
returned journal is checked against its scope, slot, original anchors, target
model and input digest and retained before another call. Existing completion
logic re-verifies the original chains and derives assertions and thresholds; it
does not accept a pass flag. Wrong answers do not truncate the inventory.

`agentcontroller.NewDurableCandidateExecutor` reconstructs the verified native
plan and shared reservation, exclusively creates its NEW `Directory` under a
private parent and owns one Sessions SQLite backend plus one v4 budget Policy.
Its private version-1 `scope.json` freezes scope, authored/effective model labels
and the immutable policy snapshot, without credentials. Roots are 0700, database
and manifest files 0600, including active journal WAL sidecars. Existing roots,
including partial initialization artifacts, are not adopted or deleted. Close
cancels/drains execution before closing policy and journal storage.

The host factory must derive the new root deterministically from its configured
private parent and the scope's 64 lowercase run-ID hex digits, stripping the
`sha256:` prefix. `ExecutionScopeForRecord` recovers the original scope on status
readback, including the preceding lease generation fenced by interruption. For
example the factory sets `Directory = filepath.Join(privateParent,
strings.TrimPrefix(scope.RunID, "sha256:"))`. Persist the configured parent with
host configuration. Readback does not construct an executor or adopt a directory.

Terminal repeated calls are readback only. Concurrent Run calls conflict without
starting another executor. An explicit Run after reopen interrupts an orphaned
Running record to Incomplete; a retained Verifying intent is re-evaluated without
calling the factory or model. Open and Read alone neither recover nor dispatch.
Factory failure after start also ends Incomplete, permanently: no return to
Admitted. On completion failure a retained Verifying intent is preserved, rather
than being discarded by blanket interruption. Store.Close gates new runs,
cancels active ones and waits without holding its database mutex, then releases
the database and ownership lock.

Partial/error journals and budget ledgers remain in their private run root.
Completed original record sets are additionally retained as qualification blobs.
The existing 256 KiB per-blob limit is unchanged: an oversized journal ends
Incomplete and is not resent. There is no GC, migration, automatic retry or
execution resumption. Literal filenames containing `?`, `#`, `%` or non-ASCII
characters are URI-escaped at SQLite connection boundaries, never interpreted as
caller connection options. Existing ordinary ledger snapshots and schemas remain
unchanged; old empty ledger artifacts still refuse and are never repaired from a
guessed prefix filename.

This path is tested with actual verified packages, native controllers, SQLite
and fake TLS models, not a live deployment. It changes no host entry point,
registration, chart, activation permission, judge execution, Ready state or
monetary/token/slot limit.

## Prerequisites for an operational runner

The following remain separate work, not functionality supplied by this package:

- Verified immutable artifact handoff and suite-derived complete inventory;
  exact runner renderer/harness/runtime profile matching the intended live target.
- Durable candidate/live isolation and journal ownership wiring, deny-effects
  dispatch, scoped request/read/service authorization and no service self-approval.
- Authenticated request integration of the host-only execution and budget path.
  Multiple independent per-deployment caps are not one bounded run. Failed or
  unknown calls remain stop conditions, not ordinary assertion failures.
- Package-derived judge binding provenance, complete judge prompt/rubric contract,
  and verification of the full retained binding before dispatch. The pure budget
  preflight does not close these runner boundaries.
- Current-policy activation integration and separately approved
  live-model/deployment/restore qualification.

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
