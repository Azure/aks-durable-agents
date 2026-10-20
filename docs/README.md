# Documentation

Azure adapters and deployment recipes for durable agent sessions on AKS.
This is experimental source, not a qualified preview release, production-ready
or sandbox-isolated deployment.
Start with the [project overview and current validation status](../README.md#status).

## Install and operate

- [Offline getting started](../README.md#getting-started): run local checks without
  Azure credentials or model keys.
- [Helm chart prerequisites and policy-first installation](../charts/aks-durable-agents/README.md):
  AKS requirements, image inputs, retained storage and NetworkPolicy limits.
- [Stopped-writer backup and isolated restore](../ops/backup/README.md): operator
  prerequisites, recovery boundaries and the local kind rehearsal.

## Understand the assembly

- [Architecture diagrams](architecture.md): current chart, opt-in Substrate backend
  and planned integration, with document, identity and recovery boundaries.
- [Embedded host configuration and security limits](host.md): authentication,
  approver policy, local build, model policy and remaining authorization work.
- [Opt-in Substrate host wiring](substrate.md): current development pins, one
  stateless harness, private runtime prerequisites and single-host recovery limits.
- [Entra caller authentication](entraauth.md): delegated token verification,
  trust/lifetime contract and real-tenant prerequisites.
- [Keyless model transport and Go wiring](modeltransport.md): workload identity,
  endpoint/scope configuration and transport failure behavior.
- [Bounded Chat policy and durable attempt ledger](../modeltransport/README.md):
  token limits, cost reservations and stops after failed or unknown outcomes.

The chart's fixture harness is not a Substrate sandbox. See the
[architecture and isolation boundaries](../README.md#how-the-pieces-fit) before
interpreting any deployment or recovery claim.

## Develop and qualify a preview release

- [Development checks and contributing](development.md): pinned toolchains,
  local verification and pull-request guidance.
- [Preview 0 acceptance checklist](preview-0.md): live AKS proof, released
  dependencies and independent installation required for a preview release,
  not for public experimental source.
- [Contributing and CLA](../CONTRIBUTING.md), [MIT License](../LICENSE),
  [Code of Conduct](../CODE_OF_CONDUCT.md) and [support limits](../SUPPORT.md).

Report vulnerabilities privately using [SECURITY.md](../SECURITY.md), not public
issues. Source availability and offline checks do not establish security sign-off
or an Azure product support commitment.
