# Retained Agent runtime

`internal/agentcontroller` contains the Agent v1alpha1 Go types and the internal
retained native runner. It is not wired into the host: no controller, CRD, chart
activation, registry administration endpoint or target-qualification claim is
provided by this component alone.

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
