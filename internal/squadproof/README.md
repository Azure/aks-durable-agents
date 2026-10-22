# Local team proof state

This package is unwired synthetic fixture code. It does not run a team, serve an
API, call Sessions or publish an external effect. The production host does not
import it. Its ledger is not a Sessions journal, a general memory store or a
production authorization service.

`OpenLedger` creates a version-1 proof database only at a new file in an existing,
owned, nonsymlink mode-0700 directory. Files must be private, regular and owned.
A known proof database may be reopened; empty, foreign, unsupported-version or
incomplete existing databases are refused, not migrated, repaired or replaced.
Initialize from one owner. If initialization leaves an empty/incomplete file,
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
