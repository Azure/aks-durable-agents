# Preview 0 checklist

[Back to overview](../README.md)

Preview 0 is the acceptance bar for a **preview release**, not a gate on public
experimental source. Preview 0 is **not yet qualified**. Public source can be
inspected and built with the documented development pins while these requirements
remain open. It is not a production-readiness or support commitment.
Status checked **2026-10-20**. **Done** means the stated scope has evidence;
**in progress** covers unfinished work, including planned tasks, not a claim
that a live run has started; **blocked** means a named prerequisite is missing.
Offline tests do not close live qualification items.

## 1. Proof on real AKS — blocked

- **Blocked — real-model lifecycle proof.** Demonstrate park → restart → approve
  → resume → exactly one effect → replay with zero model/tool calls, on real AKS
  with a real model. The current [host](host.md) has offline evidence, not this
  end-to-end qualification. The separate fake-model, unauthenticated AKS proof
  described in the [validation status](status.md#what-has-been-tested) does not meet this target.
  Complete the signed-in approval and released-dependency prerequisites below
  before qualifying the assembled path.
- **Blocked — signed-in approver from a test tenant.** The
  [Entra verifier and tenant prerequisites](entraauth.md) and the host's explicit
  approver sources exist. Required mode now enforces owner/approver permissions
  through `WithAuthorization`; live tenant qualification, journal-wide activation
  and server-derived approval attribution remain open. Rollout needs a new private
  journal and a published, verified and pinned image containing this change;
  ownerless sessions are denied without migration. Authentication alone is not
  ownership or approval authority; see [remaining authorization work](host.md#what-still-belongs-upstream)
  and [sessions authorization tracking](https://github.com/agent-primitives/sessions/issues/127).
- **In progress — backup/restore qualified on AKS.** The
  [stopped-writer recipe and local kind rehearsal](../ops/backup/README.md) exist;
  the [backup implementation](../ops/backup/backup.py) has local evidence. Repeat
  backup and isolated strict replay on AKS with Azure Disk, including writer fencing, receipts and model-ledger reconciliation.
  Kind results are not Azure Disk qualification or an RPO/RTO guarantee.
- **Blocked — preferred isolation: single-host Substrate with gVisor.** This
  chart does not install Substrate; its fixture pod is not a sandbox. Preview 0
  keeps this path eligible if these prerequisites land in time:
  - Release and qualify the [snapshot-fidelity change](https://github.com/agent-primitives/sessions/pull/181)
    plus held-snapshot validation: exact recorded checkpoint, suspended state,
    observed fidelity and newest-generation durable completion; no fallback to
    an older completed snapshot.
  - Qualify compatible released sessions, Substrate adapter, runtime and Blob
    plugin in this assembly, including real AKS lifecycle and backup/restore.
  - Keep one serving host, one writer and no surge, with explicit writer fencing.
    Label this path **“single host; recovery authority not yet boot-scoped”**.
    Client-side held-snapshot checks are accepted for this limited preview,
    not an atomic restore guarantee. A router auto-resume or competing operator
    lifecycle call can still race the check: avoid those operations during
    recovery and stop/reconcile unexpected Actor state rather than retrying.

The [atomic expected-snapshot restore proposal](https://github.com/agent-substrate/substrate/issues/2832)
**gates multi-host deployment, not Substrate inclusion in single-host Preview 0**.
One host alone does not prevent every runtime lifecycle race. Boot-scoped grants
and stale-authority refusal remain deferred: the
[pre-dispatch policy-hook discussion](https://github.com/agent-primitives/sessions/issues/168)
is related work, not a shipped guarantee. Do not claim old boot credentials are
revoked, that stale callers cannot read receipts, or that this preview is safe
for mutually untrusted tenants.

If those Substrate prerequisites slip, Preview 0 may instead ship explicitly
labelled **“no sandbox isolation yet”**. Do not imply released execution compute,
snapshot recovery or agent isolation was proved by the fixture pod. **Both paths**
still require signed-in approval and per-RPC authorization/attribution, the
real-model lifecycle proof, backup/restore and released sessions. Substrate-specific
release and recovery checks are conditional on including Substrate.

## 2. No unreleased dependencies — blocked

- **Released library selected — Sessions v0.3.0.**
  [The current module](../go.mod) selects the canonical
  [v0.3.0 release](https://github.com/agent-primitives/sessions/releases/tag/v0.3.0),
  including the [authentication seam](https://github.com/agent-primitives/sessions/pull/180)
  and [per-RPC authorization seam (#190)](https://github.com/agent-primitives/sessions/pull/190),
  without fork replacements. The dependency-release prerequisite is met, not the
  host's journal-wide activation/attribution or live qualification gates. The host
  installs the authorizer only in required mode; its journal marker stays `off`
  and unenforced writers can bypass it. Retain the [authorization requirements](https://github.com/agent-primitives/sessions/issues/127)
  and the other checks in this document.
- **Blocked if Substrate is included — released adapter, Substrate and Blob.**
  The separately tagged Sessions `integrations/substrate` **v0.3.0** and compatible
  Substrate [v0.5.0](https://github.com/agent-substrate/substrate/releases/tag/v0.5.0)
  are selected, including the fidelity/held-snapshot adapter fixes. A root release
  alone does not release a nested module. The [Azure Blob object-store plugin](https://github.com/agent-substrate/substrate/pull/2595)
  is still an open PR. Select compatible released versions of all components,
  not just the selected Go libraries. Check actual selected modules with
  `go list -m all` and `go mod graph`, pin images/assets, and qualify workload
  identity, durable upload and recovery. A development adapter/server pin or
  S3-compatible kind store does not meet Preview 0's released-Blob gate.

## 3. Usable by someone else — in progress

- **Blocked — fresh-eyes install on clean AKS from the README only.** The
  [overview](../README.md#getting-started) links the
  [chart prerequisites and policy-first procedure](../charts/aks-durable-agents/README.md).
  Probe-capable images and matching fixture/client binaries still need operator
  preparation; they are not a self-contained distribution. Close that packaging
  gap, then have someone outside the implementation install from the README and
  its linked instructions on clean AKS. Record the versions, inputs and outcome.
- **In progress — troubleshooting and limits pages.**
  [Host/security limits](host.md), [transport limits](modeltransport.md),
  [bounded-policy behavior](../modeltransport/README.md) and
  [storage/recovery limits](../ops/backup/README.md) are documented. Dedicated
  troubleshooting and consolidated limits pages still need to be written and
  checked against the fresh-eyes install; this checklist is not those pages.
- **Blocked — one tested chart upgrade.** Offline rendering/golden checks exist;
  no live chart upgrade is qualified. First complete a usable baseline install,
  then test an upgrade with retained journal, receipts and ledger, writer fencing
  and policy checks. Preserve the [schema rollback warning](host.md#configuration-and-local-build);
  changing an image back is not a data rollback.

## 4. Publication hygiene and security review — in progress

- **In progress — sanitized snapshot and publication hygiene.**
  Resource-specific examples use placeholders. Check the complete final candidate
  for internal resource names, subscription IDs and personal paths. Import one
  sanitized source snapshot commit on top of the Azure repository's template
  history; do not import private development ancestors, branches or review records.
  Scan the final files and intended public history for secrets and identifiers,
  including test fixtures and generated content. No completed repository/history
  scan or history rewrite is claimed here.
- **Done — offline CI.** [CI](../.github/workflows/ci.yml) runs Go
  build/vet/race/static/vulnerability checks and offline Helm checks on PRs and
  main. This does not exercise a live tenant or cluster.
- **In progress — dependency and code scanning.** CI provides vulnerability
  checks. [Dependabot](../.github/dependabot.yml) is configured for module, Actions
  and chart-test Python dependencies; [CodeQL](../.github/workflows/codeql.yml)
  analyzes the Azure repository with licensed code scanning and public copies.
  Other private copies skip; a skipped job is not analysis. Inspect actual
  Dependabot and CodeQL results before claiming this gate complete.
- **Blocked — security review of the auth path.** Offline negative tests and
  [documented trust boundaries](entraauth.md#trust-and-failure-contract) exist,
  but they are not acceptance of the final auth path. Review the required-mode
  host-RPC policy, full approver read disclosure and new-journal rollout; complete
  durable activation, verified approval attribution and caller-bound retry work.
  Review caller verification, approval authority, TLS, credential lifetime and
  failure behavior end to end. No final
  security sign-off is claimed.

## Experimental source and release administration

- Experimental source may be public before Preview 0 is qualified. Do not tag or
  describe it as a qualified preview release while the technical gates remain open.
- **In progress — OSS release registration.** Registration may follow experimental
  source publication; it has not been completed by this checklist. The maintainer
  tracks it separately, respects any organization-required publication approvals,
  and completes release administration before a preview release. Source availability
  is not a claim that release approval exists.
- The canonical source location is `Azure/aks-durable-agents`. Experimental source
  and Preview 0 validation do not establish Microsoft product support or an SLA;
  see [support guidance](../SUPPORT.md) and [current limits](status.md).
