# Documentation

Azure adapters and deployment recipes for durable agent sessions on AKS.
This is experimental source, not a qualified preview release, production-ready
or sandbox-isolated deployment.
Start with the [project overview](../README.md) and [current validation status](status.md).

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
- [AgentSuite package profile and registry access](agent-packages.md): verification
  library limits, explicit credentials and proxy-aware embedding (not host activation).
- [Embedded host configuration and security limits](host.md): authentication,
  owner/approver permissions, new-journal rollout, local build and remaining limits.
- [Opt-in Substrate host wiring](substrate.md): current development pins, one
  stateless harness, private runtime prerequisites and single-host recovery limits.
- [Entra caller authentication](entraauth.md): delegated token verification,
  trust/lifetime contract and real-tenant prerequisites.
- [Keyless model transport and Go wiring](modeltransport.md): workload identity,
  endpoint/scope configuration and transport failure behavior.
- [Bounded Chat policy and durable attempt ledger](../modeltransport/README.md):
  token limits, cost reservations and stops after failed or unknown outcomes.

The chart's fixture harness is not a Substrate sandbox. See the
[architecture and isolation boundaries](architecture.md#default-chart-host-and-fixture-harness) before
interpreting any deployment or recovery claim.

## Repository map

| Directory | Provides |
| --- | --- |
| [`cmd/host/`](../cmd/host/) | Sessions host executable; [configuration and security limits](host.md). |
| [`entraauth/`](../entraauth/) | Entra delegated caller verification; [trust and tenant setup](entraauth.md). |
| [`modeltransport/`](../modeltransport/) | Workload-identity Chat transport; [Go wiring](modeltransport.md) and [bounded model policy](../modeltransport/README.md). |
| [`internal/`](../internal/) | Host assembly, approver policy and Unix-socket executor client. |
| [`charts/`](../charts/) | Digest-pinned two-pod packaging, retained single-writer storage and NetworkPolicies. |
| [`ops/backup/`](../ops/backup/) | Stopped-writer backup and isolated, socket-denied replay restore. |

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
