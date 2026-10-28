# GitHub call records

`internal/githubtools` retains native Sessions adapter attribution, release
and GitHub comment intent/outcome evidence. It is not the
[decision ledger](decision-ledger.md): that ledger stays non-executing and its
parallel records must not become native Approve/Resume authority. Neither store
replaces Sessions' native decision or exact-call checks. The store and client
are not wired into the serving host.

## GitHub client

`NewClient` loads an operator-provided RSA PEM key for one App/installation/repo.
`Preflight` requests only that repository and Issues read or write, validates the
returned scope/expiry, and returns in-memory `Access`. Its `GetIssue` and
`CommentOnIssue` never mint/refresh credentials. The host must preflight before
recovery and bind access to native evidence; access alone is not approval.
Requests use only `https://api.github.com`, with no redirects or automatic retry,
fresh HTTP/1 connections, a 10-second deadline and 1 MiB JSON-body limits.
A lost/malformed comment response is `ErrUnknownOutcome`, never permission to
repost. Explicit comment rejections are `ErrGitHubRejected`; failed reads are
`ErrGitHubRead`. Access unavailable before the issue/comment operation is sent
is `ErrGitHubAccess`. Tests use fake GitHub and qualify no live App deployment.

## Executor (not yet serving)

`NewExecutor` captures the original Exec/Resume context and preflighted access;
its trusted host `Lookup` reads the
committed call by session/call/key and supplies immutable write-release evidence.
Lookup must not mint credentials, acquire gates or call Sessions RPCs. The
executor rehashes the complete recorded event/envelope against the incoming call,
checks account/mediation and reserves durable intent before POST. Only the new
reservation owner sends; saved outcomes repair lost receipts without another POST.

Ordinary reads have separate audit/cache records, no invented approval sequences.
Completed reads return the first saved result/error; interrupted uncached GETs may
repeat with externally preflighted access. Terminal read errors are error
ToolResults, not Go errors that v0.3.0 would leave unanswered. A cancelled child
call is a terminal outcome while the host lives; only host cancellation leaves
an unanswered call. Durable completion retains the original host deadline.
The declaration
`DurableDedup` is for these reads; approved-write recovery is native Sessions work.
Host authorization, genuine journal membership and recovery head CAS remain
unwired host responsibilities, not guarantees supplied by a lookup value.

## Evidence and recovery

Trusted host code supplies the verified identities, exact call, acting account
and native request/decision sequences under its session gate. Stored values do
not authenticate anyone. `PrepareApproval` retains attribution before native
Approve; `CommitApproval` links an exact decision the host has verified, without
changing the original approver. Audit timestamps are samples, not ordering rules.

The host may abandon an uncommitted pending attempt only after proving there is
no native decision under the SAME gate. Timeout is not proof. The abandoned
attribution remains; replacement attempts retain identical call evidence.

`Reserve` persists release evidence and intent before POST; only `created=true`
permits that invocation to send. Re-entry returns a saved terminal outcome, or
unknown if none was saved, including a crash before send. Unknown holds block
that session and the identical account/repository/issue/comment operation under
new keys/sessions. The host computes this semantic digest, not the harness.
There is no automatic repost, hold-clearing or reconciliation command, and no
exactly-once delivery claim. Comment outcomes contain bounded identity/display
URL or fixed failure codes, never raw provider/credential responses. The store
does not dereference the URL.

## Storage

Follow the ledger's [private-storage and lineage conventions](decision-ledger.md#storage-compatibility-and-privacy).
`Initialize` creates a new store and random ID. Retain the expected ID, host
lineage and configuration digest separately with the journal recovery set.
`Open` requires those values and never creates, adopts, repairs or migrates state.
The experimental native-store schema is now **2**, adding read audit/results.
`Open` refuses schema 1 without modifying it; there is no automatic migration.
Retain older evidence; do not delete/reinitialize it to clear an unknown outcome.
Read caches contain issue text and belong to the same host-private recovery set.

Keep the state host-private. Stop writers and back it up with the journal,
model ledger, lock and independent identity/configuration. Before enabling
restored writes, reconcile external effects since the snapshot: restoring local
state cannot undo a GitHub comment. Unit tests do not qualify that deployment.
