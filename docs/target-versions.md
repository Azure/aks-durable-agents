# Target version records (internal, unwired)

The `internal/targetversions` package records ordinary-target transitions in a
private SQLite store. It has **no production callers**, listener, controller,
model/tool calls or runtime adapter. A recorded active binding is not proof of
live dispatch exclusion, traffic switching, a successful agent answer, or a
signed-in activation capability. Workflow targets are unsupported.

## Ownership and trust

Only trusted host code may supply these Go values. Shape, binding, equality,
phase and transactional consistency checks are not authentication. Store identity
fields are writable Go fields for trusted code; callers must not change them.
Supply UTC-normalized timestamps: exact saved-record equality currently retains
zone offsets, even though fingerprints normalize instants to UTC. Do not decode
untrusted HTTP/RPC/JSON snapshots directly into this API as authority.

Before Begin fences a live target, a future adapter must read back the exact
host decision and verify current delegated-person/resource/action authority.
Before Reserve it must hold the common target/policy/dispatch serialization gate,
authenticate current Q evidence, validate retained package bytes and journals,
and read back runtime fences and the prepared context. Snapshot policy epoch,
grants and eligibility fields are assertions from that trusted adapter, not
cross-store checks performed by SQLite. D2 emergency holds must be honored by
that same gate, including at Commit. Separate databases are not an atomic
multi-store transaction.

The shared DTO-only [`internal/decisionrecord` package](../internal/decisionrecord/types.go) defines
non-executing historical evidence for both E1 and G1. G1 aliases these types rather
than declaring a consumer copy. Constructing a DTO authenticates nobody and grants
no authority; verification, policy, subject binding and persistence remain with
the owning packages. The decision record retains E1 names and meaning: ID, StoreID,
HostLineageID, Request (Workspace, Key, Subject, Action, Feedback), RequestDigest,
Actor (Issuer, Subject), Outcome, RefusalCode, Authorization (Actor, Subject,
Action, Role, PolicyVersion, GrantIDs), CommittedAt and Mode. SubjectRef retains
Workspace, Kind, ID, Generation and Digest. Only recorded decisions with empty
RefusalCode and non_executing_decision_v1 are accepted. G1 hashes its own ordered
copy under g1-copied-decision-record-v1; **this is not an E1 record encoder**.

The copied evidence domain follows the producer: workspace/subject/store/lineage,
policy/grant identifiers and recorded roles accept noncontrol UTF-8 up to 256
bytes, while request keys retain the producer's 128-byte printable-ASCII limit.
Actor issuer/subject, including Authorization.Actor, must also be noncontrol
UTF-8 of 1–256 bytes; invalid Go string bytes must not be normalized by JSON
persistence after fingerprinting. Retain the exact valid identity pair. Never
truncate identifiers or rewrite a policy-selected role into `Agent.Approver`.
Recorded and current policy-selected role strings are retained as evidence;
role meaning and scoped permission are checked by the trusted policy adapter,
not inferred from a hard-coded label here. Action/actor/subject/operation equality
checks remain mandatory. This package depends on the shared types supplied by
[the decision ledger](decision-ledger.md), which must land first. The ordinary
conformance test uses the real ledger Service and shared types through
Begin/Reserve/Commit and reopen, without a build tag. Sharing types does not
establish retained-subject authentication or current authority.

E1 v1 suite activation maps activate to accept. Rollback, recover and
abandon_activation records in this unwired package are synthetic future-input
contracts, **not capabilities delivered by E1 v1**. Those typed actions and
subjects require an agreed E1 schema before integration.

E1 owns Subject.Reference and its digest. A future owning adapter must compare
the full retained proposal against G1: TargetID to resource, operation key,
intent, exact expected predecessor/revision, explicit historical source,
package/member/composition/platform/inventory/cases/source, qualification and
binding identities. It must compute/compare agreed predecessor and binding
digests, not invent another E1 subject encoder. The subject excludes the
resulting decision; the complete G1 retry fingerprint includes its exact copied
decision. This avoids a recursive approval hash. For operator abandonment, that
adapter must likewise verify the retained operator subject's exact failed
operation/generation, observed revision/phase, predecessor, key and reason.
Current AuthorizationSnapshot also binds OperationID, Generation,
OperationRevision and Phase explicitly; substitutions refuse.

## Storage and identities

Create exclusively initializes schema 1. Open requires an existing, nonempty
database and the exact expected StoreID. It never initializes, repairs, migrates
or adopts a missing Sessions store. Future schema versions refuse without
conversion. Shared record types are persisted as JSON and re-encoded during
CAS and verification. Changing their serialized fields/order/types/JSON tags,
including `internal/decisionrecord` structs, requires an explicit store schema
bump and reviewed migration/refusal plan, not just a package update. The frozen
schema-1 SQLite fixture must keep opening unchanged; do not regenerate it to
hide incompatible type changes. Moving an unchanged type between packages does
not change its serialized schema. IDs are opaque, not paths. RegisterTarget creates an ordinary,
unavailable genesis at revision 1 with no active version.

Use an absolute clean filename under a private 0700 directory. Existing path
components and SQLite sidecars must not be symlinks. The main database is
owner-checked, regular, single-link and 0600; sidecars are checked for regular
file type and 0600 mode, not link count. Create syncs the private directory's
containing directory as well as the database's containing directory. A failed
Create removes only the database inode it exclusively created; it never removes
a pre-existing or subsequently replaced file. Process termination may still leave
partial initialization requiring operator reconciliation, not automatic adoption.
Existing operator permissions are never chmodded. These checks follow the private Linux/POSIX
store convention, not OS containment against another same-user writer.

SQLite uses DELETE journaling and EXTRA synchronization. Unlike FULL in DELETE
mode, EXTRA also syncs the journal directory after unlinking a committed journal.
EXTRA, foreign_keys and
busy_timeout are configured through DSN pragmas for **every** connection,
including replacement connections. New databases default to DELETE; Open
checks this persistent mode without changing an unsupported database's mode.
Each mutation uses a short BEGIN IMMEDIATE transaction, revision/generation
checks and affected-row checks, without network calls or a process-local lock
as correctness authority. Random store/backend/operation/version/context IDs
are allocated once. Caller keys are retained for the lifetime of history.

Immutable operations, versions, qualifications, keys, claims, links, tombstones,
abandonment intents and ordered events accompany mutable target/operation
projections. Application code only appends immutable rows; SQLite file access
is not an adversarial tamper-proof boundary. Events retain complete post-state
snapshots, receipts and reciprocal links so Open/Verify can replay projections
and compare local references. Versions can exist as pending candidates; their
local recorded active binding changes only after Commit. That does not establish
a live runtime switch. There is no public version-by-ID read API: ReadOperation
exposes its immutable candidate; History supplies lifecycle facts.

ArtifactTuple requires suite OCI manifest SHA-256, member, composition, platform,
inventory/cases, harness/runtime/model/config, judge/settings and binding
identities. Digests are 64 lowercase hexadecimal characters (without sha256:).
Use explicit none for no composition. Candidate source provenance is separate
from the suite digest. Qualification retains a store/record ID, digest,
evidence/journal hashes, the full artifact tuple and current policy eligibility
assertions. Reusing a retained Q identity with changed contents conflicts.
Fresh Q can permit changed qualification context while retained package,
member/composition/platform/inventory/cases/source stay exact.

Store-owned operation keys and identifiers are at most 128 printable ASCII
bytes; copied producer evidence uses the broader domain above. Reasons are
nonempty UTF-8 up to 4096 bytes; request, authority and receipt metadata are
bounded to 64 KiB. Evidence bytes live in separately retained stores. G1
fingerprints use versioned domain-separated SHA-256, fixed field order,
length-prefixed strings and explicit list counts, never caller maps.

## Transitions and retries

Every transition supplies OperationID, expected operation revision and generation.
The target's revision advances once per event; its fence generation advances
once per Begin. Exact target-scoped keys share a namespace between Begin and
abandonment. Altered semantics conflict, including after terminalization and
restart. Decision (StoreID, ID) is claimed at Begin, before fencing, across all
targets; abort never releases it. Operator decisions use the same claim table.

| Phase | Durable behavior |
| --- | --- |
| preparing | Begin freezes request, candidate/context, expected predecessor and generation; records a target fence. |
| prepared | Operation-bound prepared receipt identifies admission fence, context, Q and evidence. |
| reserved | Exact Begin decision plus same-person current authority and unexpired credential/authorization are saved at the irreversible boundary. |
| predecessor-retired | Exact retirement/no-source/already-retired proof is retained. |
| committed | Commit receipt matches prepared context/fence; target active pointer changes and occupancy clears transactionally. |
| aborting | Pre-boundary abort intent excludes Reserve; uncertainty remains fenced. |
| aborted/refused | Exact release receipt clears occupancy; only an existing committed predecessor becomes ready. |
| abandoning | Fresh operator intent, decision claim and capability tombstone commit together, excluding old forward operations. |
| abandoned-unavailable | Required predecessor proof and successor-disabled receipt clear active pointer/occupancy, preserving tombstone and source chain. |

A receipt binds kind, operation, target, generation, backend lineage, candidate,
execution context, qualification and exact predecessor, with evidence/fence/
context hashes. Normal retired, no_source and already_retired receipts are
distinct. No-source proof names the exact genesis or no-source terminal
predecessor. Already-retired proof names the exact terminal predecessor and its
retained retirement evidence. Abandonment uses distinct abandon_retired,
abandon_no_source or abandon_already_retired cleanup receipts, plus
successor_disabled; all are bound to IntentID. Cleanup cannot commit the failed
candidate or enable dispatch.

Exact saved receipt/snapshot retries return the saved operation even with an old
expected revision. Other stale steps conflict. Cancellation or an SQL/ambiguous
commit error is not success or rollback evidence: explicitly read the same
operation/key before deciding how to continue. No API automatically retries,
continues, executes, abandons, recovers or releases a fence. Reopen and history
reads never advance a phase.

Reservation checks credential validity after waits. Before Reserve, continuation
requires explicit same-operation delegated credentials and current authority;
no background reacquisition. After Reserve, exact forward completion retains
the saved authority despite later credential expiry. New execution remains
subject to then-current policy and the future adapter's durable fences/holds.

## Source and recovery rules

* Genesis permits activate with no SourceVersionID and explicit no-source proof.
* A current committed predecessor permits activate, or rollback from an explicit
  **different committed historical version of the same target**. Rollback
  creates a fresh VersionID/context and reciprocal source links; it never
  reopens the historical version.
* An abandonment with retained source permits recover only, with fresh approval,
  key and context, exact retained package/source and full matching Q. Changed
  harness/runtime/model/judge/binding context requires fresh matching Q.
* A genesis-descended terminal without source permits a freshly approved initial
  activate, **not recover or rollback**, against that exact terminal predecessor.

FrozenSource records the predecessor to restore after failure, not the selected
candidate. In particular a failed rollback X to historical Y retains X for
post-abandon recovery, while SourceVersionID and its source edge name Y.
Repeated recovery abandonment preserves the original frozen source explicitly.
A recovery abort stays unavailable; another freshly authorized key can create
another linked attempt without overwriting the earlier attempt.

Missing or unknown cleanup evidence stays abandoning/unavailable. Old commits
and forward callbacks reject tombstones. No automatic thaw, lease expiry,
package rebuild, inherited sessions/documents/decisions/effects or runtime Resume
exists.

## Verification, history and release gates

History is ascending, read-only and paged by target sequence. Default and maximum
page size are 100. Verify and Open check SQLite integrity/expected table schema, event sequences,
legal transitions, exact projections, immutable snapshots, qualifications, keys,
decision claims (including operator claims), links and tombstones. Extra views or
triggers are not checked; this is not protection from an administrator changing
SQLite behavior. A detected verification mismatch latches that Store handle
before releasing its connection, even if the request is cancelled after detection.
A failed or cancelled read alone is not proof of a mismatch. Lock contention
returns ErrBusy; operational storage failures such as SQLITE_FULL/IOERR or a
closed handle return ErrUnavailable, without latching corruption. Neither says
whether an uncertain commit completed: reconcile the same request/operation.
ErrOccupied means a target already has a pending operation, not SQLite lock
contention. Unknown target/operation references and mismatched receipt bindings
return ErrConflict. All public refusal paths return fixed sentinel/context messages,
without raw parser, SQL, path or stored-identity diagnostics in their error chains.
Neither Open nor Verify repairs corrupt state.

These are **local consistency checks**, not artifact authenticity, authority,
anti-rollback or coordinated restore proof. A coherently older snapshot cannot
prove that later capabilities were never issued. Before enabling an integration,
stop old writers and verify one fenced recovery set including version store,
packages/source, Q evidence/journals, E decisions, D2 policy/grants/holds/epochs,
Sessions journals and harness/model/executor ledgers/counters. Invalidate old
workload capabilities through an external recovery epoch.

The existing format-1 backup tool is unchanged and does not certify this
cross-store continuity. Enabled integration requires a backup-manifest capability/
version upgrade and refusal by incompatible old host/restore tools. No production
retention/export/deletion policy, deployment, chart, CLI, public RPC or signed-in
milestone is provided here. Audit issuer/subject identifiers are personal data;
no tokens, credentials, raw claim maps or transcripts belong in these records.

Offline tests exercise SQLite on temporary files, replacement connections,
reopen/phase read-back, two handles and synchronized subprocess races. Process
exit before/after transactions is not hardware/power-loss durability certification.
