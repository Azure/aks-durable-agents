# aks-durable-agents

Teams running agents need a way to wait for human approval and recover from restarts without losing work.

The goal is a workflow like this:

> An agent prepares a cluster change and stops for a named teammate to approve it.
>
> That person comes back the next morning. The agent's host has restarted.
>
> The agent continues from where it stopped.
>
> The team can inspect the record and replay the run without calling the model or tools again.

This is a host and deployment setup for platform teams using Azure Kubernetes
Service (AKS). It uses [Sessions](https://github.com/agent-primitives/sessions) to
record agent work and approvals. It adds the Azure pieces: Entra sign-in for approvers,
model access without keys (workload identity), network isolation, journal backup and
restore, and a Helm chart. It is not a new agent runtime or a ready-to-run service.

## Status

**Experimental source. The workflow above is not yet validated end to end on AKS. Do not use it in production or expose it to untrusted users.**

## Getting started

Run a disposable, fake-model agent on kind. You need a Linux/amd64 Docker
backend, kind v0.33+, compatible kubectl (v1.37 tested), Helm and Python 3.
No host Go toolchain, Azure account or model credentials are needed.

```sh
git clone https://github.com/Azure/aks-durable-agents.git
cd aks-durable-agents
make demo
```

The demo prepares a fictional release-note change, parks for approval, restarts
the host, then asks you to type **approve** and separately **continue**. It checks
one simulated effect, stops all writers, **seals the disposable stores in a
separate demo-only step**, replays once read-only without model/tool calls, and
deletes its owned cluster. Real hosts do not perform this sealing step.

See the [demo prerequisites, sealing caveat and evidence](ops/demo/README.md).
This is not an AKS, authenticated-approval or hostile-tenant isolation
qualification. AKS deployment still needs operator identity/model inputs.
For component checks without Docker, use the [development checks](docs/development.md).

## Go deeper

- [Current limits and validation](docs/status.md): what has been tested, missing authorization and development dependencies.
- [Architecture](docs/architecture.md): how the host, execution and storage fit together.
- [Development](docs/development.md): full offline checks and external test inputs.
- [Cluster deployment prerequisites](charts/aks-durable-agents/README.md) and [backup/restore](ops/backup/README.md).
- [Preview release checklist](docs/preview-0.md): what must be proved before a preview release.
- [All documentation and repository map](docs/README.md).

See [SUPPORT.md](SUPPORT.md) for help and [SECURITY.md](SECURITY.md) for private
vulnerability reporting. Experimental source has no production support or SLA.
This source is licensed under the [MIT License](LICENSE).

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit [Contributor License Agreements](https://cla.opensource.microsoft.com).

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

See [CONTRIBUTING.md](CONTRIBUTING.md) for development and contribution guidance.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft
trademarks or logos is subject to and must follow
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
