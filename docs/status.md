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

The current host is a **loopback-only proof**. Authentication and an explicit
approver policy are wired; Sessions resource authorization is not yet enforced.
It is not safe for untrusted users or multiple mutually untrusted tenants.
See the [host's remaining authorization work](host.md#what-still-belongs-upstream).

[Sessions](https://github.com/agent-primitives/sessions) supplies the journal,
approvals, replay without new model/tool calls, and forks. It stays cloud-neutral.
This repository adds Entra caller identity, model access through workload identity,
network policy, Helm packaging and backup/restore recipes. Role mapping, a
supported Helm installation and approval-bound delegated tool access are planned,
not current guarantees. See [architecture and trust boundaries](architecture.md).

The chart's fixture pod is not a sandbox. The chart does not install Substrate;
its optional host backend needs separate infrastructure. The intended Substrate
assembly provides isolated execution and snapshots, but this assembly's recovery
and isolation still need qualification. The native document producer profile is
also not a standalone public deployment. See [Substrate prerequisites and limits](substrate.md)
and [external producer inputs](../ops/canvas/README.md#scope-and-prerequisites).

## Development dependencies

This source selects these **released module versions**:

| Component | Selected release |
| --- | --- |
| Sessions root | `github.com/agent-primitives/sessions v0.3.0` |
| Sessions Substrate adapter (separate module) | `github.com/agent-primitives/sessions/integrations/substrate v0.3.0` |
| Substrate runtime/client | `github.com/agent-substrate/substrate v0.5.0` |

All modules use canonical upstream sources, with no fork replacements. Released
dependencies do not make this a released or qualified assembly. Sessions core and
its separate Substrate adapter have distinct release tags and commits; the adapter
requires Sessions v0.3.0 and Substrate v0.5.0. See [the version set and fresh-state
reinstall warning](substrate.md#version-set) and the [journal upgrade warning](host.md#configuration-and-local-build).
