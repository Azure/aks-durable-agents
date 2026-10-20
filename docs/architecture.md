# Architecture

[Docs index](README.md) · [Project overview](../README.md)

This repository assembles Sessions with Azure identity, model transport and
operational packaging. It does not replace Sessions or provide a document store.

## Why this exists

Sessions is cloud-neutral; this repo supplies Azure-specific identity and
operations: Entra caller verification with an explicit approver allowlist
(role-based mapping is planned), keyless model access, network policy, opt-in
Substrate wiring for isolation, and an Azure Disk-backed journal with a
backup/restore recipe tested locally on kind. Substrate isolation and
backup/restore on AKS, plus a qualified, supported Helm install, are planned—not
current guarantees. Also planned, via [sessions#127](https://github.com/agent-primitives/sessions/issues/127),
are approval-bound tool grants: approved tool calls use the approver's delegated
access through a host-side connector, without passing credentials to harnesses.

## Default chart: host and fixture harness

```mermaid
flowchart TB
    subgraph Chart["Default Helm packaging; not yet qualified on AKS"]
        subgraph HostPod["Host pod"]
            C["Trusted client<br/>host network namespace"] -->|"loopback TLS + delegated token"| H
            H["Sessions host<br/>Entra verifier + explicit approver policy"]
            T["Keyless model transport<br/>bounded policy + attempt ledger"]
            H --> T
        end
        subgraph FixturePod["Fixture harness / executor pod; not a sandbox"]
            F["Fixture harness<br/>turns and model/tool requests"]
            X["Socket executor<br/>simulated effects + receipts"]
            A["Inert reference fake<br/>harness-pod loopback only"]
        end
        V[("Retained Azure Disk PVC<br/>journal, model ledger, receipts + shared socket")]
        H <-->|"private plaintext gRPC harness Service"| F
        H -->|"Unix socket"| X
        H --> V
        X --> V
    end
    T -->|"HTTPS + workload identity"| M["Configured Azure model endpoint"]
    V -->|"stopped-writer fixture recipe"| B["Local backup archive<br/>isolated strict replay restore"]
```

**Legend:** solid boxes and arrows are implemented wiring or operator recipes,
not proof of live deployment. The diagram shows required authentication mode.
The local backup drill injects a host-local HTTPS fake and fake credential instead
of Azure inference; it does not call the fixture pod's inert fake.
The host API is loopback-only, with no Service or Ingress; the chart's Service is
for the harness. The fixture pod has no external egress, but it is not Substrate
isolation. Bare chart defaults cannot run: reviewed images, prepared storage,
TLS, identity, model policy and network-policy enforcement are operator inputs.
See the [chart prerequisites](../charts/aks-durable-agents/README.md).

The opt-in [native document producer profile](../charts/aks-durable-agents/README.md#native-document-producer-profile)
is a separate current remote-harness path: it replaces the fixture pod with static
producers, mounts prepared archives read-only and uses `/host health-probe`.
It does not install Substrate or qualify AKS, caller identity, effects or recovery.
Its producer source/images and private qualification inputs are not distributed
here; see [the external-input limits](../ops/canvas/README.md#scope-and-prerequisites).

## Opt-in Substrate backend and planned integration

The host also implements an opt-in [Substrate backend](substrate.md), selected
instead of remote harnesses (fixture or native producers). It routes one configured stateless harness
through a TLS control API and a private h2c router into an Actor, using
operator-supplied runtime/image settings. Model transport and socket executors remain on the host
side; the Actor is not given model credentials. This host wiring exists, but the
chart above does **not** install or configure it.

```mermaid
flowchart LR
    H["Host with opt-in<br/>Substrate backend"] <-->|"TLS control API + private h2c router"| A["Separately installed Substrate<br/>router, workers + harness Actor"]
    C["Current Helm chart"] -.->|"planned: Substrate packaging"| H
    A -.->|"planned: released Blob plugin + qualified recovery"| B[("Azure Blob snapshot storage")]
    classDef planned stroke-dasharray: 5 5
    class B planned
```

Dashed arrows/boxes mark planned integration, not a current chart or recovery
capability. Substrate's snapshot store is distinct from the fixture backup
archive; there is no built-in journal-to-Blob backup path.

## Main boundaries

- **Documents:** callers such as Canvas own their document store and review; this host owns no accepted-document history.
- **Journal:** Sessions records execution, approval and replay on retained storage; the model attempt ledger and executor receipts are separate durable state.
- **Approvals:** in `auth.mode=required`, the host verifies callers and applies an explicit approver allowlist. `auth.mode=off` disables authentication and the approval gate for trusted-network local development only. Approval and continuation remain separate Sessions operations.
- **Human identity:** Entra delegated-token verification exists, but per-RPC resource authorization and server-derived approval attribution are still required; no untrusted or multi-tenant access is supported.
- **Model access:** only the host's transport uses workload identity for Azure inference; harnesses receive model results, not Azure credentials.
- **Execution:** the chart's fixture pod is not a sandbox; opt-in Substrate wiring needs separate infrastructure and has no boot-scoped recovery-authority guarantee.
- **Recovery:** fence all writers and restore journal, receipts and model ledger as one set; the fixture recipe is not Actor snapshot recovery or Canvas whole-state backup.

Live tenant/keyless-inference validation, this chart's AKS install, signed-in
resource authorization and AKS recovery remain [Preview 0 gates](preview-0.md).
There is no HA, production-readiness or tamper-proof audit claim.
