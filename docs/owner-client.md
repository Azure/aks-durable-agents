# TLS owner/approver client

`go build -o .build/owner-client ./cmd/owner-client` builds a separate, authenticated
client. It does not change the credential-free local demo or the nightly. It knows
only Sessions RPCs and opaque Exec Config, not agent files or kmx's export format.
This is experimental operator access, not a public or multi-tenant endpoint.

## Prerequisites

Use a **new required-auth journal**. Do not migrate an auth-off demo journal. The
host needs its existing TLS certificate/key, single-tenant Entra verifier, API
audience, allowed delegated client ID and required scope. See [host configuration](host.md)
and [identity checks](entraauth.md). The same person must own the session **and**
independently satisfy the host's approver policy. Ownership alone does not permit
approval. The client never supplies an approver identity as proof of authority.

An operator must provision and consent an appropriate public-client application
for device-code sign-in and the Sessions API's delegated scope. Explicitly select
that application's client ID and tenant. Do not substitute ARM/model tokens or
Azure CLI's client application. Identity, consent, role and shared-cluster changes
need their own authorization; this command does not perform them.

Obtain the host CA and certificate name through the trusted operator channel.
Keep the host listener on literal loopback in its private Pod. Forward the **Pod**,
not a public Service or ingress, on a trusted operator machine:

```sh
kubectl --context my-private-cluster --namespace agents \
  port-forward --address 127.0.0.1 pod/my-host-pod 9443:8443
```

Keep the forward running separately. The client does not spawn kubectl or change
Kubernetes context. Every invocation requires a numeric loopback `IP:port`, a CA
file, and the TLS server name, which is verified even through the forward. There
is no insecure, plaintext, token-file, environment-token or default-credential
fallback. Access to the local forward must remain private.

## Commands

The examples use Bash and fictional identifiers. Replace the tenant, client and
scope with the exact configured identity inputs, not the host's model identity.
All sign-in instructions and outcome output are private: the pending request can
contain the full draft/tool arguments. Do not upload either stream to CI logs.

```sh
common=(--server 127.0.0.1:9443 --ca /private/host-ca.pem \
  --tls-name host.internal.example \
  --tenant 11111111-2222-3333-4444-555555555555 \
  --client-id 12345678-1234-1234-1234-123456789abc \
  --scope api://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/sessions.access)

.build/owner-client start "${common[@]}" \
  --harness demo-release-notes --model my-target-deployment \
  --config /private/config.json --input /private/fictional-input.txt
.build/owner-client inspect "${common[@]}" --session "$SESSION_UID"
```

`start` creates once, prints the session UID **before** Exec, and sends the exact
bounded Config/input file bytes. It does not parse an export or choose a model.
Retain the UID even if Exec fails. Never rerun start to recover an uncertain
outcome. `inspect` reads the session and correlated pending tool request without
model/tool execution. It searches up to 256 records before the approval request,
allowing intervening lifecycle records after recovery. If no exact execution/tool
match is found within that window, inspection stops with an unknown outcome.
Review the request and retain its head and pending tuple.

One explicit `approve-run` invocation means approve this reviewed request **and**
resume as its owner. There is no separate automatic action when inspecting:

```sh
.build/owner-client approve-run "${common[@]}" --session "$SESSION_UID" \
  --head "$REVIEWED_HEAD" --execution "$EXECUTION_ID" \
  --tool-call "$TOOL_CALL_ID" --request-seq "$REQUEST_SEQ"
```

Every invocation performs device-code sign-in once. The provider keeps its cache
only in memory and requests a current delegated access token for each RPC. It does
not serialize tokens, refresh tokens or authentication records. If another
interactive login becomes necessary during the action, it stops instead of
switching callers. The host, not the client, verifies identity and authority.

## Separate outcomes and uncertainty

Stdout is JSON lines. Approval and Resume have separate stages. A successful
approval commits only the decision. The client validates that response, writes
its approval outcome, then sends Resume with the **approved head** as the server's
`ExpectedLastSeq` precondition. A stale reviewed head/tuple stops before approval;
this client read check is not a new server-side atomic approval CAS guarantee.
A concurrent write can still make Resume refuse. See [host limitations](host.md).

A successful Resume means resumed, **not necessarily completed or published**:
a generic harness may park for another approval. Use read-only inspection and
the flow's own durable evidence to determine what happened. For the source-file
bridge, use its [publication and zero-call replay checks](demo-bridge.md).
Client output is an observation, not durable verified approver attribution.

On lost, malformed, partial or failed outcomes the client stops. An approval may
have committed even when its reply was lost; Resume may have performed an effect
before a lost reply. A failure to write output also stops the next action. There
is no application retry, replacement session or automatic recovery. gRPC may
transparently retry work it knows was unprocessed; it must not redrive a possibly
committed application mutation. Preserve all reported UIDs/outcomes and reconcile
with read-only inspection and the host's journal/publication records before any
new explicit action. Do not treat a connection error as proof nothing happened.

Local TLS/synthetic-identity tests and a private kind Pod-forward rehearsal do
not qualify live Entra consent/sign-in, Azure workload identity, AKS network
policy, image provenance or an exact tested package. A live run requires the
separately approved identity, TLS, deployment and operational preconditions.
