# Local team proof state

This is a proof, not a product. Run the commands below from the separate
`proofs/squadbackend/` module directory, not the repository root.

The default build contains unwired synthetic ledger, executor and queue code.
The optional `squadproof` build tag adds local serving fixtures using real Sessions
components; it does not add an automatic team coordinator. Production commands
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
The future trusted journal scanner supplies evidence to `Observe`; the ledger
checks correlation and ordering, but cannot verify the Sessions hash chain.
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

The tests cover durable reopen, concurrent retries, scope refusals, uncertain
reservations, receipt/END/second-approval queue holds and a subprocess that exits
immediately after its effect/result commit without closing the database or
producing a Sessions receipt. They do not qualify a running host, coordinator,
client, live identity flow, external publication, kind cluster or AKS deployment.

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

The serving fixtures expose no broker, queue scanner, scenario runner or offline
replay CLI. Admission, approval and result-delivery control belongs to a trusted
external driver. These fixtures do not prove automatic result delivery,
process-crash recovery, broker reconciliation, live Squad/client interoperability,
hosted authorization or AKS.
Tools' epoch arguments remain scope checks, not execution-bound fencing.
