# Retained Agent runtime

`internal/agentcontroller` contains the Agent v1alpha1 Go types and the internal
retained native runner. The opt-in host controller below connects these to
namespaced resources. No registry administration endpoint, Ready condition or
target-qualification claim is provided.

The runtime retains verified OCI bytes by manifest digest, separately from each
namespace/name/UID/generation-owned definition. It verifies cached bytes with
AgentSuite again on load, using the recorded expected digest. Definition identity
also binds member, frozen model/policy configuration and the native runner ABI.
Deleting one owner's registration must not remove shared package bytes or another
owner's definition.

The initial native profile accepts one named-model, tool-free OpenAI-compatible
member. It refuses tools, invocations, policies, credential/endpoint overrides,
capability-selected models, runtime profiles and critical unsupported extensions.
Packaged images and scripts are not executed. The operator's bound model and the
verified instruction bytes are fixed; session config cannot replace them.

The host supplies a non-secret binding snapshot and model callbacks. Snapshots
are canonicalized; a different binding or model makes the factory refuse the old
definition, never substitute current settings. Repository authorization is also
checked offline at retention and factory admission. Revocation leaves cached
bytes/definitions inspectable and does not block loading unrelated definitions.

State uses private, same-owner directories, bounded regular files and create-only
atomic publication. Real private Unix listeners and immutable descriptor/spec
checks back the SDK registry factory. Serialize manager operations on one lifecycle
goroutine; callbacks use immutable data. Stop/join the controller and stop the SDK
registry before closing the runtime. An interrupted listener-identity publication
fails closed on restart rather than guessing ownership or deleting a foreign socket.
Unpublished temporary files are ignored. Interrupted publication recovers only a
proven two-link temporary alias inside the locked state root, never an outside link.
The state path determines socket addresses; moving it is not a supported migration
of existing registration specs. Backups must include both the journal and runtime
state; cached packages alone are not session history.

SDK-registry tests cover independent registrations and loading retired placers
without re-registering them. They do not establish controller ownership recovery,
startup admission, kind deployment or end-to-end session recovery; those require
host/controller integration.

## Opt-in host controller

Enable `agents.enabled` in the chart with exact `agents.repositories`, API server
CIDRs and registry/redirect CIDRs. Registry egress uses configured authority ports
(default HTTPS 443 or HTTP 80), plus 443 for redirects; redirect destinations must
use those ports and the configured CIDRs. Helm installs the retained Agent CRD;
its three-field spec is immutable: use a new name for changed inputs.
The host receives `--agents-namespace`, repeated `--agent-repository`, optional
`--agent-credentials-file` (JSON repository-to-ORAS-credential map), and the
credential-free development exception `--agent-http-registry`.
Only the host gets a projected API token and namespace-scoped Agent/status RBAC.
Verify API reachability under your CNI, especially CIDR matching for self-hosted APIs.
Use a durable plain journal path; state lives at `journal + ".agents"`. Substrate
cannot be combined with this controller. Feature-off static hosting is unchanged.
Before serving Sessions RPCs, the host reads a complete namespace snapshot and
retires orphaned owners. An unreadable API blocks startup; watch failures cause
relist, never deletion inferred from an error. Deleted UIDs retire independently.
The effective endpoint, deployment, scope, complete parsed model policy (including
run ID, ledger path and pricing), and runner ABI are frozen. Keep these fixed
across restarts; drift refuses the old UID, never substitutes current callbacks.
Only current matching ACTIVE registrations publish `Registered=True` and
`servedDigest=packageDigest`; `PackageVerified` alone does not mean runnable.
Status is last observed admission, not liveness or inference success. No model
calls are made by reconciliation or status reads. No tools, updates or qualification.
