# Entra caller authentication

[Back to overview](../README.md) · [Host assembly and limits](host.md)

`entraauth` authenticates single-tenant Microsoft Entra **v2 delegated access
tokens** through the sessions `authn.CallerVerifier` interface. It does not grant
session ownership or authorize operations. It adds no host activation, TLS, or
authorization enforcement. Live access requires a separately assembled trusted
TLS host, the opt-in sessions authentication interceptors, and the sessions
ownership/authorization enforcement PR sequence; this package alone is not a
secure live deployment. This caller identity is separate from the keyless model
transport's workload identity.

## Host wiring and lifetime

The following is host-assembly code, not an executable example or a network test.
`hostCtx` is a `context.Context` owned by the **host lifetime**, not an RPC or a
short startup deadline. Keep the verifier alive while serving, including the
graceful drain; stop serving before its deferred `Close` runs. Do not pass a
signal context that is canceled when shutdown starts: the verifier would close
before `GracefulStop` drains, and RPCs still being verified would fail with
`UNAUTHENTICATED`. `cmd/host` lets the signal context cancel only the initial
key load and closes the verifier after the drain.

```go
import (
    "github.com/agent-primitives/sessions/authn"
    "github.com/Azure/aks-durable-agents/entraauth"
    "google.golang.org/grpc"
)

// Illustrative GUIDs only: substitute your tenant, API app, and client app IDs.
verifier, err := entraauth.New(hostCtx, entraauth.Config{
    TenantID:         "11111111-2222-3333-4444-555555555555",
    Issuer:           "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0",
    Audience:         "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    AllowedClientIDs: []string{"12345678-1234-1234-1234-123456789abc"},
    RequiredScope:    "sessions.access",
})
if err != nil { return err }
defer verifier.Close()
unary, stream, err := authn.NewInterceptors(authn.Required, verifier)
if err != nil { return err }
server := grpc.NewServer(
    grpc.ChainUnaryInterceptor(unary),
    grpc.ChainStreamInterceptor(stream),
)
// Register services and assemble trusted TLS and authorization before serving.
// Install authentication outermost, before any data-disclosing/effectful interceptor.
// Handlers read only authn.Caller(ctx), never forwarded identity headers.
```

## Trust and failure contract

- **Public cloud only.** Use canonical lowercase GUIDs for `TenantID`, `Audience`,
  and every `AllowedClientIDs` entry. `Issuer` must be exactly
  `https://login.microsoftonline.com/<TenantID>/v2.0`. Discovery is pinned to
  `https://login.microsoftonline.com/<TenantID>/v2.0/.well-known/openid-configuration`
  and JWKS to `https://login.microsoftonline.com/<TenantID>/discovery/v2.0/keys`.
  Tenant aliases (`common`, `organizations`), alternate clouds, token-supplied
  URLs, and redirects do not select trust. Only the tenant's signing keys are
  trusted. [App-specific signing keys](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens)
  (published at `jwks_uri?appid=<appId>` for an app using claims mapping) are
  **not supported**; a token whose `kid` is not in the tenant JWKS is rejected,
  normally with `key_unavailable` once a refresh confirms the `kid` is absent (a
  failed refresh reports its own code, such as `fetch` or `jwks`).
- Exactly one incoming `authorization: Bearer <token>` value is required. The
  scheme name is case-insensitive (`bearer` is accepted), and exactly one space
  must separate it from the token; tabs and extra spaces are rejected.
  Verification requires an RS256 signature, `ver=2.0`, exact `iss` and `tid`, a
  **scalar** `aud` equal to the API app's GUID, an allowlisted client `azp`, the
  exact short `RequiredScope` in `scp`, and integer-second `nbf` and `exp` claims.
  App-only tokens (`idtyp=app`), roles-only tokens, and ID tokens are not accepted
  as delegated credentials. A scope match is authentication policy, not
  per-resource authorization.
- Identity is the exact issuer/subject pair; `SubjectClaim` defaults to **`oid`**,
  with no fallback to email, UPN, or `sub`. Selecting `sub` is an explicit opt-in
  that changes ownership keys and requires an ownership/policy migration.
  Forwarded/spoofed identity metadata never substitutes for `authn.Caller(ctx)`.
- `ClockSkew` is **0 through 2 minutes**, defaults to zero, and relaxes **`nbf`
  only**. Usable expiry is exactly `exp`: no expiry grace. Both the verifier and
  sessions interceptors use wall time in normal operation.
- **Revocation is not immediate.** The verifier checks only the signed token; it
  makes no per-request call to Entra and does not support continuous access
  evaluation. A token issued before a user is disabled, unassigned, or has
  sessions revoked stays valid until its `exp`, and an admitted unary call is not
  ended at `exp`.
- `New` validates configuration and synchronously fetches discovery and signing
  keys: startup depends on Entra availability. Invalid configuration, unavailable
  trust data, or malformed metadata/JWKS fails `New`; there is no permissive
  fallback or automatic startup retry. The host owns any bounded retry policy.
  Each discovery+JWKS load has a ten-second deadline and each response is limited
  to 1 MiB. The **whole JWKS is rejected** if any entry is unsupported, malformed,
  duplicated, or weak, rather than skipping that entry. This fail-closed choice
  trades availability for strict trust: mixed keysets can prevent startup or
  refresh even if they also contain a usable key.
- Keys refresh **hourly**, with a **24-hour** good-snapshot lifetime. Unknown-key
  refreshes are coalesced and rate-limited to one attempt per **5 minutes** per
  verifier. An attacker-triggered miss can spend that budget and delay a genuine
  new-key refresh by the remaining cooldown, **up to 5 minutes**; the next
  scheduled refresh may recover sooner. A successful refresh replaces the
  snapshot. During an outage, only otherwise-valid tokens signed by cached keys
  remain usable, and only until the snapshot's **original TTL**; failed refreshes
  never extend it.
- `Close` cancels trust I/O and joins the refresh worker. RPC cancellation stops
  that caller's wait, not a shared refresh. Optional `HTTPClient` is a **trusted
  host extension and trust root** for TLS/network configuration. A custom
  `Transport` can rewrite destinations (the offline fixture does); only trusted
  host code may supply it. It must honor cancellation and must not log
  credentials. The client is copied; the timeout, no-redirect policy, and pinned
  verifier-request URLs remain enforced, but do not sandbox that transport.
- Never log bearer tokens, raw claims, or underlying parser/provider errors.
  Verifier errors are generic (with fixed `DebugReason()` diagnostic codes);
  interceptors return generic `UNAUTHENTICATED` without calling handlers for
  invalid credentials. Sessions #180 also maps trust/JWKS outages to that same
  status and has no diagnostics hook. A host needing operational diagnostics
  must wrap the verifier and log only fixed `DebugReason()` codes, never raw
  errors, tokens, or claims. Optional `Config.OnRefreshError(reason, keysExpire)`
  reports each failed background refresh (scheduled or unknown-key) with a fixed
  code and the snapshot expiry, which a failure never extends, so a host can warn
  before the snapshot expires. It is not called for the initial load (`New`
  returns that error) or for a refresh ended by `Close`. It runs on the refresh
  goroutine: return promptly and do not call `Close` from it. Do not add
  token/error dumps to diagnose live access.
- `cmd/host` does both. It logs each rejected caller as `caller authentication
  failed` with only the fixed `reason`, at most once per reason per minute, with
  a `suppressed` count of the failures since the previous line. The `canceled`
  and `deadline` reasons mean the caller's own RPC context ended, not a bad
  credential or Entra outage, so they are logged at debug level. It logs each
  failed refresh with its `reason` and `keys_expire_in`: a warning that says the
  snapshot nears expiry in the last six hours, and an error once it has expired.
  Reasons that are not short lowercase codes are logged as `unclassified`.

## Real-tenant prerequisites (not performed by this package)

Keep **API and client registrations separate** to avoid ID-token/audience
confusion. Following Microsoft's [claims validation guidance](https://learn.microsoft.com/en-us/entra/identity-platform/claims-validation),
[application schema](https://learn.microsoft.com/en-us/graph/api/resources/application?view=graph-rest-1.0),
[API schema](https://learn.microsoft.com/en-us/graph/api/resources/apiapplication?view=graph-rest-1.0),
and [expose-an-API guidance](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-configure-app-expose-web-apis):

1. Register a single-tenant API with `signInAudience=AzureADMyOrg`. Its **`appId`
   GUID**, not its directory object ID or Application ID URI, is `Config.Audience`.
   Set **`api.requestedAccessTokenVersion=2`** explicitly; using a v2 sign-in
   endpoint alone does not select the access-token version.
2. Set `identifierUris` (typically `api://<API-appId>`) and expose an enabled
   `api.oauth2PermissionScopes` entry (`isEnabled=true`) whose `value` is
   `sessions.access` for this example. Your actual short value must match
   `Config.RequiredScope` exactly.
3. Register one or more client apps. Their **`appId` GUIDs** populate
   `Config.AllowedClientIDs` and must match token `azp`. Configure each client's
   `requiredResourceAccess` for the API's delegated scope, plus consent and/or
   API preauthorization as tenant policy permits. Configure the chosen delegated
   user sign-in flow and its appropriate redirect URI for that client.
4. The client requests the **full scope** `api://<API-appId>/sessions.access`
   (using the actual Application ID URI); the verifier compares only the short
   `scp` value **`sessions.access`**. Have test users in that tenant and a known
   user `oid` to check the exact expected identity.
5. Restrict who can get a token. The verifier pins tenant, API, client, and
   scope, not the user population: **every user who can get a delegated token
   for an allowlisted client and `RequiredScope` authenticates**, and
   authenticated callers share session access ([host limits](host.md)). Depending
   on tenant policy that can include B2B guests; the verifier does not check
   guest status. Enable **Assignment required** (`appRoleAssignmentRequired=true`)
   and [assign](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/assign-user-or-group-access-portal)
   only the intended users or groups. With no app roles defined, an assignment
   uses the built-in **Default Access** role (`appRoleId`
   `00000000-0000-0000-0000-000000000000`), so this step needs no app role.
   Group assignment requires Microsoft Entra ID P1 or P2 and does not cascade to
   nested groups. Which service principal's setting (the API's, the client's, or
   both) blocks token issuance is not verified here, so set it on the API and
   every allowlisted client, then confirm in your tenant that an unassigned
   user, and an unassigned guest if you have them, cannot get a token. The
   [`acct` optional claim](https://learn.microsoft.com/en-us/entra/identity-platform/optional-claims-reference)
   (`0` member, `1` guest), configured in the API registration's
   `optionalClaims.accessToken`, shows guest status in a token; the verifier
   does not read it.

The API verifier needs **no client secret or refresh token**. App-only workload
identity/client-credentials tokens cannot replace the delegated user token; do
not add app roles/client-credentials for this path (step 5's assignment uses
Default Access, not an app role). Tenant, issuer, audience, and client IDs are
not secrets. A bearer token **is secret**: do not store or log a
live token, or put one in a handoff. Key-cache behavior follows the bounded
rollover approach in Microsoft's [signing-key rollover guidance](https://learn.microsoft.com/en-us/entra/identity-platform/signing-key-rollover).
No live tenant registration, consent, assignment, or token acquisition is
exercised here.

## Offline verification and the sessions dependency

`entraauth/grpc_test.go` uses locally signed tokens, TLS `httptest` discovery/JWKS,
real sessions authentication interceptors, and an in-process `bufconn` health
service. Unary and streaming calls prove exact issuer/`oid` delivery despite
spoofed metadata, and generic rejection of invalid signatures, malformed,
duplicate, or missing credentials without invoking a handler. The in-memory
gRPC hop is deliberately not a production TLS example. Run the focused check
without a tenant, credentials, or any cloud calls:

```sh
go test -race -count=1 -run TestGRPCAuthentication ./entraauth
```

The `go.mod` requirement selects canonical upstream Sessions commit
`f18a2cb1454d1eea0c9e9063646a5251653bd95e`, pseudo-version
`v0.2.1-0.20261019224537-f18a2cb1454d`, with no fork replacement. It includes the
merged [authentication seam (#180)](https://github.com/agent-primitives/sessions/pull/180)
(`NewInterceptors`, `CallerVerifier`, `Caller`); the Entra verifier contract is
unchanged. Unary authentication is admission-only: a completed handler result is
not overwritten solely because its context ended during execution. Streaming
expiry enforcement remains in the upstream interceptor.

This is still an unreleased development pin, not delivery of
[per-RPC authorization (#190)](https://github.com/agent-primitives/sessions/pull/190)
or approval attribution. When a compatible release includes the required seams,
update the requirement and run `go mod tidy`, then rerun the host and chart
checks. Do not select v0.2.0, which lacks the authentication seam.
