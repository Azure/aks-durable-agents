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
exactly-once delivery claim. Outcomes contain bounded comment identity/display
URL or fixed failure codes, never raw provider/credential responses. The store
does not dereference the URL.

## Storage

Follow the ledger's [private-storage and lineage conventions](decision-ledger.md#storage-compatibility-and-privacy).
`Initialize` creates a new store and random ID. Retain the expected ID, host
lineage and configuration digest separately with the journal recovery set.
`Open` requires those values and never creates, adopts, repairs or migrates state.
The preparatory schema is experimental, without automatic migration.

Keep the state host-private. Stop writers and back it up with the journal,
model ledger, lock and independent identity/configuration. Before enabling
restored writes, reconcile external effects since the snapshot: restoring local
state cannot undo a GitHub comment. Unit tests do not qualify that deployment.
