# Current status and limits

[Docs index](README.md) · [Project overview](../README.md)

**Experimental, pre-release.** Public source availability is not a preview release.
Preview 0 is not yet qualified. Do not use this assembly in production or expose
its API to untrusted users.

## What has been tested

- Offline Go and Helm checks.
- A local kind stopped-writer backup and isolated strict replay with zero
  model/tool calls.
- A separate AKS Sessions approval/replay proof used a fake model and
  unauthenticated, scripted decisions. It did not validate this chart or this
  Azure host assembly.

These checks do not validate a live Entra tenant, live keyless model inference
through this host, Substrate isolation/snapshot recovery in this assembly, or an
AKS 1.37 chart install. There is no high-availability or production-readiness claim.

The [Preview 0 checklist](preview-0.md) is the acceptance bar for a preview release.
Publishing source does not close its unfinished requirements.

## Access and execution limits

The current host is a **loopback-only proof**. Required mode installs Sessions'
`WithAuthorization`: new sessions belong to the verified caller, ordinary
operations are owner-only, and listed subjects OR verified approver roles can
read and approve any valid owned session. Ownership does not grant approval.
Approvers can read full prompts, outputs and tool arguments; no other cross-owner
operation or listing is granted. UIDs must reach approvers out of band; there is
no inbox or notifier. Listing remains owner-only and required-mode Fork is refused.
Approve records a decision only, never an implicit Resume.

Required mode must start on a **new private journal**. Ownerless sessions are
denied to everyone, without automatic binding or migration. Deployment needs a
published, verified and pinned image containing this change; the existing digest
alone is not evidence. Auth-off is unchanged: anyone reaching the host can read,
act and approve. See [rollout and disclosure](host.md#read-disclosure-and-rollout).

Isolation is limited to this host's RPCs. The journal marker remains `off`, so
unenforced writers can bypass it. Keep the journal private and exclusive; verified
approval attribution and caller-bound retries are not implemented. Keep TLS,
loopback and NetworkPolicy restrictions. It is not safe for untrusted users or
multiple mutually untrusted tenants. See the [remaining limits](host.md#what-still-belongs-upstream).

[Sessions](https://github.com/agent-primitives/sessions) supplies the journal,
approvals, replay without new model/tool calls, and forks. It stays cloud-neutral.
This repository adds Entra caller identity, model access through workload identity,
network policy, Helm packaging and backup/restore recipes. Optional app-role,
group and member admission checks and subject-OR-role approval are implemented
([configuration and limits](entraauth.md#optional-caller-and-approver-checks));
the host combines them with owner checks, but not verified approval attribution. A
supported Helm installation and approval-bound delegated tool access remain
planned, not current guarantees. See [architecture and trust boundaries](architecture.md).

The chart's fixture pod is not a sandbox. The chart does not install Substrate;
its optional host backend needs separate infrastructure. The intended Substrate
assembly provides isolated execution and snapshots, but this assembly's recovery
and isolation still need qualification. The native document producer profile is
also not a standalone public deployment. See [Substrate prerequisites and limits](substrate.md)
and [external producer inputs](../ops/canvas/README.md#scope-and-prerequisites).

## Development dependencies

The Sessions/Substrate assembly selects **released upstream versions**:

| Component | Selected version |
| --- | --- |
| Sessions root | `github.com/agent-primitives/sessions v0.3.0` |
| Sessions Substrate adapter (separate module) | `github.com/agent-primitives/sessions/integrations/substrate v0.3.0` |
| Substrate runtime/client | `github.com/agent-substrate/substrate v0.5.0` |

All modules use canonical upstream sources, with no fork replacements. Released
libraries do not qualify this host assembly; required-mode authorization is host
wiring, not a consequence of selecting those versions.
Root and adapter have separate v0.3.0 tags; the runtime/client must match the
adapter's v0.5.0 contract. See the [version set and fresh-state warning](substrate.md#version-set).
Main image publication and verified digest-pin updates remain separate from this
source dependency refresh; no new image receipt or live proof is implied.
