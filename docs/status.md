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
network policy, Helm packaging and backup/restore recipes. Optional app-role,
group and member admission checks and subject-OR-role approval are implemented
([configuration and limits](entraauth.md#optional-caller-and-approver-checks));
these do not supply per-resource authorization or approval attribution. A
supported Helm installation and approval-bound delegated tool access remain
planned, not current guarantees. See [architecture and trust boundaries](architecture.md).

The chart's fixture pod is not a sandbox. The chart does not install Substrate;
its optional host backend needs separate infrastructure. The intended Substrate
assembly provides isolated execution and snapshots, but this assembly's recovery
and isolation still need qualification. The native document producer profile is
also not a standalone public deployment. See [Substrate prerequisites and limits](substrate.md)
and [external producer inputs](../ops/canvas/README.md#scope-and-prerequisites).

## Development dependencies

This source depends on **unreleased development versions**:

| Component | Selected development version |
| --- | --- |
| Sessions root | `github.com/agent-primitives/sessions v0.2.1-0.20261019224537-f18a2cb1454d` |
| Sessions Substrate adapter (separate module) | `github.com/agent-primitives/sessions/integrations/substrate v0.0.0-20261019224537-f18a2cb1454d` |
| Substrate runtime/client | `github.com/agent-substrate/substrate v0.4.1-0.20261013053953-96dffb287919` |

All modules use canonical upstream sources, with no fork replacements. These are
public development pins, not a released or qualified assembly. Sessions core and
its separate Substrate adapter select the same commit. The runtime/client pin
remains the adapter's compatible version; see [the version set](substrate.md#version-set).
