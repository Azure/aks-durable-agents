# Local team proof state

This is a proof, not a product. Run the commands below from the separate
`proofs/squadbackend/` module directory, not the repository root.

The default build contains unwired synthetic ledger, executor and queue code.
The optional `squadproof` build tag adds a bounded synthetic broker and local
serving fixtures using real Sessions components, not a production coordinator. Production commands
never import this package. The tagged runtime and command are excluded from
normal builds and every production image/publication target. The production host
and its model limits are unchanged. This ledger is not a Sessions journal, a
general memory store or a production authorization service.

`OpenLedger` creates a version-1 proof database only at a new file in an existing,
owned, nonsymlink mode-0700 directory. Files must be private, regular and owned.
A known proof database may be reopened; empty, foreign, unsupported-version or
incomplete existing databases are refused without repairing or replacing the
original database or its sidecars. Preflight validates a private copy, allowing
SQLite to recover that copy before the identity/schema check. Only recognized
proof storage may recover its original hot rollback journal; WAL is unsupported.
Initialize from one owner, and open quiescent retained storage; this is not an
online snapshot protocol. If initialization leaves an empty/incomplete file,
retain it as evidence and start a fresh private case directory, not an overwrite.
SQLite transactions use immediate writer admission and full synchronous commits.
No old fixture, model-budget or production journal is adopted.

Trusted host setup admits the lead and binds returned Session UIDs. Tool calls
resolve their team, package and role from that persisted mapping; argument values
cannot create authority. Admission and tool retries use immutable canonical
payload fingerprints. Each tool's dedup namespace is Session UID plus idempotency
key; a changed correlation ID can receive the original output, while a changed
payload conflicts. One outstanding member is admitted per lead. Local simulated
publication and executor result commit together; this does not make arbitrary
external effects exactly once. Sessions must enforce approval before invoking
approval-mediated tools; this executor does not authenticate approval decisions.

User, scheduled-tick and member-result inputs share an ordered queue. A member
result has one fixed key per child and requires recorded terminal evidence.
Host-originated input IDs cannot use the reserved `result-` prefix.
The tagged broker's trusted journal scanner verifies the Sessions hash chain,
current acknowledged execution, request/decision/receipt correlations and head
before supplying evidence to `Observe`. The untagged ledger checks correlation
and ordering; it does not independently verify that chain.
Each confirmed execution is unique per target; its request, decision, receipt
and END positions must follow that input's durably reserved journal head.
Queue reservation requires a bound session, current epoch/head, an approval
receipt where required, and END of the current invocation. Receipt without END,
a later unresolved approval, or a delivering input holds further work. A durable
reservation is not permission to retry an ambiguous RPC: confirm only an
acknowledged execution ID. Uncertain outcomes are sticky across reopen and
cannot be cleared by guessed evidence or a replacement UID. Late acknowledgments
from retired epochs are refused. Epoch changes hold while the lead has an active
invocation or non-terminal child. The tool epoch is an argument check against
persisted scope, not an execution-bound capability: a retired execution that
knows a newer value is not fenced by this API. These checks are not a cross-host
execution lease or boot-scoped fencing of an in-flight external effect.
`queued-behind-approval` records the enqueue-time phase, not a live projection;
reservation always checks current evidence. An uncertain target holds even an
enqueue retry; its existing input can still be inspected without mutation.

Context is immutable host-seeded fixture data scoped to the lead's team/package;
there is no model-writable Scribe memory or cross-team search. Use only synthetic
private data. No credential or live provider is needed for the offline tests:

```sh
go test -race ./internal/squadproof
go test -race -count=20 ./internal/squadproof
```

These untagged tests cover durable reopen, concurrent retries, scope refusals,
uncertain reservations, receipt/END/second-approval queue holds and a subprocess
that exits immediately after its effect/result commit without closing the database.
The tagged tests below additionally exercise real Sessions components and actual
process replacement. Neither suite qualifies live identity, external publication,
a kind cluster or AKS deployment.

## Non-shipping runtime fixtures

The explicit tag enables a separate proof-only host built from the same pinned
Sessions `sqlitelog`, remote harness backend, placement/registry, service and
auth-off interceptors as production. It uses the real OpenAI adapter, a private
TLS fake with certificate/destination pinning and synthetic credentials, and the
existing Unix tool adapter with exact durable-dedup declarations. It does **not**
call production `host.Run` or relax its required model-policy gate. The fake has a
separate durable case-wide ceiling: only the first 16 attempts may complete.
Invalid and refused attempts are counted and consume that budget too; reopening
the host does not reset it. This is not a production spending or pricing
qualification.

The proof copies the production 25-second model and 30-second RPC bounds, handler
waiting and bounded shutdown. It has no separate production health listener or
configurable TLS/identity/provider surface. Every listener is literal loopback;
all serving roles require explicit `--proof-only`. Use only fresh private case
directories. Initialize the executor first and wait for its readiness record
before starting the host: storage initialization has one owner. Harness processes
need no mutable state. Stale sockets are refused, not silently replaced; verify
that their owner is stopped before removing a retained socket. An interrupted
initial host setup may leave an unmarked journal: retain it and start a fresh
case rather than repairing or adopting it.

```sh
go test -tags squadproof -list '^TestProofBuildBoundary$' ./internal/squadproof
go test -race -tags squadproof ./internal/squadproof
go build -tags squadproof -o .build/squad-proof ./cmd/squad-proof
```

The three blocking serving commands are run separately. For a new mode-0700
absolute `CASE_DIR`, start the executor first, then both harnesses and the host:

```sh
.build/squad-proof executor --proof-only --data "$CASE_DIR"
.build/squad-proof harness --proof-only --role lead --addr 127.0.0.1:9000
.build/squad-proof harness --proof-only --role member --addr 127.0.0.1:9001
.build/squad-proof host --proof-only --data "$CASE_DIR"
```

Readiness is one JSON record on stdout. The host defaults to `127.0.0.1:8080`;
`--addr 127.0.0.1:0` selects an ephemeral port reported in that record. Provider,
credential, model, package, hosted-auth and external-network options are not
exposed. This binary is not added to production or reference image builds.

Tagged tests explicitly admit/bind sessions and drive the SDK. They prove
stateless mediated lead/member execution, durable asynchronous dispatch before
member allocation, independent model/executor entry counts, approval/denial and
canonical controller replay with denying live callbacks and complete invocation
coverage. An unfinished invocation or changed package cannot pass completed
replay. The replay controller uses an isolated in-memory journal copy; it never
seals or rewrites the live store.

## Bounded broker and controlled restart

`broker` performs one eligible action. Admission returns a durable member handle;
the broker later allocates a distinct member session and queues its terminal
result as a new lead input. Only an SDK `EXECUTION_START` acknowledgment confirms
an input. An allocating session without a mapped UID or a delivering input without
that acknowledgment becomes sticky `uncertain`, including an explicit pre-start
Exec refusal. A witness-visible orphan or execution is not adoption authority.

Explicit synthetic decisions persist an intent, send `Approve`, then leave a
matching durable `Resume` obligation for the next broker action. Continuations
outrank new input. Historical retries do not rearm them. A rejected Resume CAS
holds without automatically advancing its cursor. A known acknowledged invocation
interrupted without a rejected CAS may resume its verified unfinished suffix;
that recovery can make live suffix calls and is not zero-call completed replay.

**Controlled restart only:** quiesce all execution writers before opening retained
ledger storage. A one-step broker opens between completed RPCs while host and
executor are idle, with no RPC in flight. After an interrupted action, stop/drain
old host, executor and broker processes, verify their exit, then reopen roles in
readiness order before sending RPCs. The offline test
manager uses already-open control handles at live barriers and a read-only observer.
Hot broker-only restart and online ledger reopening are not proven. Do not remove
a retained socket until its owned process is stopped. No production storage
migration or new takeover protocol is supplied.

For a fresh, idle serving setup, run one fixed positive scenario or individual
broker actions (replace the server address with the host readiness address):

```sh
.build/squad-proof scenario --proof-only --case queue --data "$CASE_DIR" --server 127.0.0.1:8080
.build/squad-proof broker --proof-only --data "$CASE_DIR" --server 127.0.0.1:8080
```

`scenario` accepts only `happy`, `deny` and `queue`, on an empty proof ledger, with
at most 64 actions. Decisions are fixed by that synthetic script, never inferred
from arbitrary user input. `broker --operation ID --decision JSON` accepts an
explicit synthetic `api.ApprovalDecision`; it does not authenticate a person.
There is no permanent model loop or generic coordinator endpoint. Output reports
cancellation as unsupported; native Cancel remains `UNIMPLEMENTED` and Suspend is
not a cancellation substitute.

After stopping writers, inspect or replay private copies, never the original
SQLite files:

```sh
.build/squad-proof inspect --proof-only --writers-stopped --data "$CASE_DIR"
.build/squad-proof replay --proof-only --writers-stopped --data "$CASE_DIR"
```

Completed replay checks every invocation in both sessions with denying live
callbacks. Pending, uncertain, changed-package or incomplete histories cannot
claim completed replay. Copy recovery/checkpointing occurs only in a private
scratch directory; the original journal, ledger and sidecars remain unchanged.
A killed inspector can leave a private `.proof-snapshot-*` sibling directory;
remove only its owned copy after verifying that inspector has stopped.

The full offline process matrix is in the tagged Go tests. It includes admission
cuts, lost Create/Exec acknowledgment, known invocation and pending-approval
replacement, decision-before-Resume (approve and deny), effect-before-receipt
redrive, terminal/result enqueue/delivery acknowledgment cuts, user/result/tick
queue order, receipt-before-END and second approvals, historical decisions,
stale Resume CAS, scope/payload refusals, cursor reconnect, unsupported Cancel and
strict completed replay. At the effect cut, the executor pauses after committing
its effect/result; the host is killed before it can write a receipt. Killing only
the executor could produce a failure receipt and would not test that window.
Independent RPC/model/executor counts do not come from the replayed transcript.

These are trusted-local synthetic safety checks, not live Squad/client
interoperability, hosted authorization, HA, external exactly-once effects or AKS
qualification. Kind coverage is separate. Tools' epoch arguments remain scope
checks, not execution-bound fencing.
