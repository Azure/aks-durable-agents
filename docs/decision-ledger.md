# Host decision ledger

The `decisionledger` Go package records exact, delegated-human decisions for
host-retained suite-version proposals and effect-approval subjects. It is a
**non-serving foundation**: the host command does not construct it, no endpoint
is registered, and no production scoped-policy adapter is supplied. Importing
this package changes neither Sessions nor running targets.

A `recorded` decision means the entitled person made the bound choice. It does
not mean an agent was activated, a native tool approval was applied, or an effect
was continued or executed. Offline tests do not qualify signed-in hosting.

## Authority and API

Trusted host code registers an immutable `Subject` using `RegisterSubject`.
Exactly one of `SuiteProposal` and `EffectApproval` must match its kind:

- Suite proposals bind target, expected predecessor/version revision, activation
  operation key, candidate suite digest, selected member/composition/platform,
  complete inventory/cases, qualification/evidence/source digests, and the digest
  identifying the complete runtime/model/harness/binding tuple.
- Effects bind session, execution, pending request sequence, tool call, operation,
  active version, accepted input revision/hash and exact argument digest.

Every digest is a lowercase 64-character SHA-256 hexadecimal value without a
`sha256:` prefix. Referenced bytes and qualification verdicts are the owning
adapter's responsibility: registering a value does not authenticate external
evidence. V1 supports ordinary activation subjects with a nonempty predecessor
and positive target revision; genesis, rollback, recovery, abandonment and
Canvas workflow lifecycle subjects require separately reviewed schemas.

`Subject.Reference()` produces a domain/version-separated digest over fixed,
length-prefixed fields. There are no maps, URL fetches, package builds or
caller-supplied approval attestations. Scope, expiry, registration source and all
variant fields participate. Changing source/evidence requires a new subject
reference. There can be only one open generation of a workspace/kind/subject ID;
supersede it before registering a newer generation. A decided subject cannot be
superseded. Re-registering identical retained content reads its existing identity.

`NewService(store, verifier, policy)` requires explicit trusted dependencies:

- `entraauth.Verifier.VerifyHuman(ctx)` verifies exactly this request's incoming
  delegated credential using the existing issuer/audience/tenant/client/scope
  checks and configured role/group/member admission. It requires `oid` mapping
  and wholly well-formed, nonempty roles. Existing `Verify` and `VerifyApproval`
  retain their compatibility behavior. Raw claims/tokens are not returned.
- `DecisionPolicy.AuthorizeRead` checks current visibility for the exact stored
  subject. `WithDecision` must hold resource-policy/revocation serialization over
  one synchronous callback and propagate its commit error. It supplies an exact
  actor/subject/action/role/policy-version/grant snapshot. There is no default
  policy, subject-allowlist fallback or production test policy. Durable policy
  enforcement must exist before a serving assembly is enabled.
- `Service.Decide` takes workspace, request key, exact subject reference, action
  and optional bounded feedback. There is no request actor/role field. Suite
  actions are `accept`, `reject`, `request_changes`; effect actions are `approve`,
  `deny`. Other actions, including Continue, cannot record an accepted decision.
- `Service.Get` verifies the current request and reads only that person's
  workspace/key namespace, subject to current visibility. Cross-person history
  and read-only workload access require a separate scoped-policy API.

The future browser adapter must forward the credential from the exact signed-in
browser request, not a process-global token source. Browser sign-in, secure
session association, CSRF/Origin protection, engine-audience read authentication
and workload credentials are not implemented by this library. Synthetic
request-isolation tests do not establish those browser properties.

## Decisions, retries and failure

Request keys are unique within `(workspace, verified issuer, verified oid)`.
Another person using the same literal key has an independent request namespace:
they cannot occupy or read someone else's key. The **subject decision CAS is
cross-person**, including kind and generation, so concurrent contradictory
choices can yield only one recorded human decision. Refusals leave the subject
open. A host policy refusal is distinct from an authorized human rejection.

An exact retry returns the original immutable result after current identity and
read checks. Changing action, reference or feedback at the same person's key
conflicts. A refused key stays refused after policy changes; a new explicit
request needs a new key. Authentication failures and invisible subjects do not
create attributable decision records. Once visibility is established, fixed
refusal codes distinguish policy denial, closed/expired subject and invalid action.

Both credential and subject expiry are checked within the write transaction
after policy/database waits, immediately before commit. Expired credentials
roll back the whole transaction without a request record or consumed subject.
If a subject expires at the last commit check, the transaction is also rolled
back and returns conflict. A timestamp is a host clock sample near commit, not
an external trusted-time attestation.

The policy guard serializes revocation against decision commit. Revocation
winning first refuses; commit winning first retains its historical snapshot.
That snapshot is not permission for future execution. A misbehaving policy
adapter cannot invoke a saved callback after return or hide a callback error.
Adapters remain trusted host code, not a sandbox or a distributed-lock protocol.

Cancellation, a failed COMMIT or a lost reply is not proof of rollback. Reconcile
the exact request with `Get` against the same store identity; do not automatically
retry as a new human action. A later authentication/read failure can hide an
already committed outcome until the person explicitly reads with valid access.
Any failure after a successful commit is returned as `ErrUnavailable`, never as
an ordinary pre-commit authentication/permission refusal. `Get` distinguishes
explicit read denial from unavailable policy; unknown policy errors are sanitized.
Read, reopen and duplicate requests dispatch no work. Errors do not echo token,
SQL, parser or arbitrary policy diagnostic text.

## Activation and native effect integration

A future Accept & activate operation must keep one explicit human request across
decision recording and reversible activation preparation. The v1 subject digest
is the exact binding the activation controller must consume; an alternative
activation-subject codec requires explicit schema agreement. The subject excludes
its own decision record/hash. The activation retry fingerprint can then include
that subject and the returned decision reference without a hash cycle.

Before fencing a target or reserving its transition, the controller must verify
exact decision read-back, actor/action/candidate/predecessor/revision/operation
bindings, current scoped policy, qualification and readiness. At irreversible
reservation it persists its own authorization snapshot and single-operation
consumption of the decision under the common target/policy gate. The decision
receipt alone can never begin, fence or reserve an activation.

“Still valid at reservation” means the credential expiry from the same
synchronous human request, not a retained bearer for background preparation.
Disconnect before reservation leaves recorded intent/pending preparation, not an
active target; explicit continuation requires current delegated credentials and
authorization. After a durable irreversible reservation, exact forward recovery
uses the activation store's reserved snapshot without reacquiring human tokens.
No controller, consumption store or activation protocol is wired here.

Effect records are **parallel, non-executing evidence**. They are not consumed by
existing Sessions.Approve or Resume and can disagree with native approval state.
They neither replace native Sessions decision authority/audit nor grant a tool
consent/use reservation. Future integration must join exact native decision
read-back and protected dispatch checks. Continue will require its own action
and explicit schema revision, not reuse of `approve`; direct Resume must enforce
the same dispatch boundary. Until then a consumer must not display these records
as native-approved, continued or executed.

Any review client must compare exact host/store lineage, subject/hash/generation,
request/action/actor and policy snapshot against retained intent, then persist
host evidence with its own local decision transition. Unknown/absent/mismatched
read-back never advances a workflow. For example, Canvas also retains ownership
of document path/schema/review-scope validation; this package has no document
subject or client dependency. No cross-store atomic commit or execution authority
is claimed.

### Lossless copied evidence

A consumer must copy every recorded field unchanged, including the policy-selected
historical role, issuer/subject, workspace, subject ID, policy version, ordered
grant IDs, request digest, lineage and timestamp. Never rewrite a role to
`Agent.Approver`, truncate an identifier or normalize Unicode to fit a narrower
consumer. Projected identifiers and roles retain this producer's noncontrol
UTF-8/256-byte domain; request keys remain printable non-space ASCII/128 bytes.
The actor remains the exact verified identity pair. Grants remain sorted, unique
and bounded to 64 entries. Consumer-specific operation/target keys may have a
separate narrower domain, but cannot silently narrow retained decision evidence.
Current scoped policy and entitlement are checked separately; a recorded role
string does not itself grant current authority. Whole request/authority envelope
limits still apply in addition to the producer's record bound.

The opt-in `decision_projection_conformance` test issues decisions through the
real service with synthetic request verification/policy and consumes their
unaltered projection through the real target-version Begin/Reserve/Commit/reopen
path. It is build-tagged while the consumer package is developed separately;
run it in a combined source checkout containing both packages:

```sh
go test -race -tags=decision_projection_conformance ./internal/targetversions \
  -run '^TestDecisionProjectionConformance$' -count=1
```

This checks representation and immutable persistence, not the absent owning
adapter, live Entra, qualification, runtime fencing or effect consumption.

## Storage, compatibility and privacy

`Initialize(absolutePath, hostLineageID)` exclusively creates a new schema-1
store and random store ID. Its immediate parent is private (0700), and DB files
are 0600 and owned by the current user. Existing parents/files are not repaired;
symlink components and unsafe SQLite sidecars are refused. Linux/POSIX file and
lock semantics apply. `Open(path, expectedStoreID, hostLineageID)` never creates
or migrates state: retain the expected store identity independently. Reopening an
existing empty/truncated, foreign, inconsistent or unknown-schema DB refuses.
Schema 1 requires the exact library-owned table/index definitions as well as both
version markers, identity and data-coherence checks. Reopen rejects missing
indexes, added columns/objects and replaced constraints even when the markers
remain 1; SQL definitions must match the library DDL, not merely an equivalent
external spelling. SQLite's own internal objects are excluded from that identity.
There is no schema repair, in-memory fallback or automatic state adoption.

A separate persistent 0600 `<database>.lock` file carries a lifetime exclusive
lock and rejects another cooperating writer **before opening the DB file**.
Never unlink/replace this lock file while writers may exist; include it with the
stopped-writer recovery set. `Open` refuses a missing/unsafe lock file. Keeping
the lock on another inode prevents a failed duplicate Open from closing a DB
descriptor and dropping the process's SQLite POSIX locks. SQLite uses
short immediate transactions, a single connection, DELETE journaling, FULL
synchronization and foreign keys; connection-local settings are reapplied to
replacement connections. Subject CAS and immutable outcome insertion commit
atomically. This lock does not fence a stale host on another storage backend;
RWO is not an old-writer fence. No multi-host deployment is qualified.

IDs are at most 256 UTF-8 bytes without control characters; keys are at most 128
printable non-space ASCII bytes; feedback is at most 2 KiB UTF-8 (tabs/newlines
allowed). Variant fields/digests and grant count/size are bounded, keeping requests
below 16 KiB and retained subject/record JSON below 64 KiB. A future serving
assembly additionally needs positive request-rate, outstanding-subject and disk
limits. There is no network admission path here.

Audit records retain stable issuer/oid, necessary entitlement/scope/policy and
exact subject/action/feedback. They contain no names/email, bearer tokens, raw
claim maps or transcripts. Feedback may contain sensitive text: keep access
private. There is no logging or cross-person listing endpoint. Records remain
with the experimental recovery set without automatic pruning; production
retention, export/deletion authority and backup erasure policy are release gates,
not a privacy-compliance claim.

Stop all writers before backup/restore. Include this DB/subjects together with
host journals, policy, qualification/version state, evidence and backend lineage.
Reconcile that complete fenced recovery set before enabling mutations. A
self-consistent stale partial restore is not current authority; local integrity
checks do not establish cross-store continuity or resist a malicious host admin.
The existing backup tools are unchanged and do not qualify a ledger restore.
Schema downgrades/migrations need explicit review. No production wiring, cloud,
real model/effect or stopped-writer restore drill is qualified by the unit tests.
