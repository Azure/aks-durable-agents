# Entra caller authentication

[Back to overview](../README.md) · [Host assembly and limits](host.md)

`entraauth` authenticates single-tenant Microsoft Entra **v2 delegated access
tokens** through the sessions `authn.CallerVerifier` interface. It does not grant
session ownership. Optional admission checks constrain app roles, groups and
member accounts; the host separately combines verified approver app roles with
its explicit subject allowlist. It adds no host activation, TLS, or
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
  with no fallback to email, UPN, or `sub`. An `oid` must be a lowercase GUID;
  `Config.ValidIdentity` reports whether an allowlist entry has the exact form
  `Verify` returns. Selecting `sub` is an explicit opt-in that changes ownership
  keys and requires an ownership/policy migration.
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
  Approval-path verification failures use `approval verification failed`, not
  `caller authentication failed`, with a separate per-reason rate limit. A caller
  context ending on that path is logged at debug as `caller context ended during
  approval verification`.

## Optional caller and approver checks

All checks default to off: existing configurations retain their delegated-token
admission and subject-only approval behavior. Configure these fields on
`entraauth.Config`, under `identity` in host auth JSON, or under `auth` in Helm:

| Go field | JSON / chart field | Requirement |
| --- | --- | --- |
| `RequiredRoles` | `requiredRoles` | At least **one** listed app-role value in `roles` on every call |
| `RequiredGroups` | `requiredGroups` | **All** listed lowercase group object IDs in `groups` on every call |
| `MemberOnly` | `memberOnly` | Explicit JSON integer `acct=0` on every call; guests and absent/malformed claims refused |
| `ApproverRoles` | `approverRoles` | At least **one** listed app role grants approval, OR a configured approver subject |

**Host image prerequisite:** enabling `requiredRoles`, `requiredGroups`,
`memberOnly` or `approverRoles` requires a published, verified and pinned host
image containing these checks. A pre-feature image refuses the new auth JSON.
After source merge, follow the [publish, verify and pin process](../ops/images/README.md#publish-then-pin)
before enabling these settings; do not assume the chart's default host digest
contains the checks.

`memberOnly` means **`acct=0` (tenant `userType: Member`)**, not a home-tenant
account guarantee. [B2B users can be Members](https://learn.microsoft.com/en-us/entra/external-id/user-properties#can-microsoft-entra-b2b-users-be-added-as-members-instead-of-guests),
so a B2B member can satisfy this check. The `acct` emission for that specific
B2B-member case is still to be confirmed in a real-tenant run; this setting must
not be used to infer where the user authenticates.

Matching is exact and case-sensitive. Role values must be nonempty with no ASCII
whitespace/control characters; group IDs must be lowercase GUIDs. Duplicate
configured values are rejected. These restrictions cannot be enabled with auth
mode `off`. App roles never replace the required delegated `scp`, tenant,
audience, client or signature checks. Directory roles (`wids`) are not app roles.

**Approval uses OR:** after all configured admission checks pass, either an exact
listed issuer/subject or an approver app role grants approval. An owner has no
implicit approval right. For example:

```yaml
auth:
  # Other required tenant, client, scope and TLS inputs omitted.
  memberOnly: true
  requiredGroups: ["abcdef01-2345-6789-abcd-ef0123456789"]
  approverRoles: ["Approver"]
  approvers:
    - issuer: https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0
      subject: 0a1b2c3d-4e5f-6789-abcd-ef0123456789
```

The listed subject with `roles=["Reviewer"]`, or an unlisted subject with
`roles=["Approver"]`, can approve **only** with `acct=0` and the required group.
Neither source bypasses those checks. An empty subject list is allowed with an
approver role. Helm requires at least one approval source in required mode; the
Go host permits neither source, which denies all approvals.
`requiredRoles`, if set, also applies to approvers; include `Approver` in that
caller list if it should admit approvers without another role.

**No silent subject fallback when role claims are absent.** With approver roles
configured, every approval requires a nonempty, well-formed string-array `roles`
claim, including for listed subjects. A listed subject needs at least one API
app-role assignment (not necessarily an approver role). **Operator upgrade note:**
before adding `approverRoles` to a subject-only deployment, assign the configured
approver app role to those subjects too and acquire fresh tokens. Otherwise,
listed subjects whose tokens have no `roles` claim are intentionally refused.
A listed subject with another valid API app role still qualifies through the
subject route (OR). A missing/empty claim is
refused with `approval requires a nonempty roles claim; configure API app role
assignments`; malformed claims are refused with `approval requires a valid roles
claim`. Ordinary calls are unaffected by `approverRoles`. Startup cannot know
whether future tenant tokens carry roles; this guard runs on each approval,
not a tenant-wide heuristic. If ordinary `requiredRoles` admission rejects first,
the RPC instead returns generic `UNAUTHENTICATED` and the operator log diagnoses
`roles_missing` or `roles_invalid`.

The verifier rejects missing/malformed required claims rather than inferring
membership or calling Graph. When groups are required, any `hasgroups` indicator
or `_claim_names.groups` distributed claim refuses with diagnostic
`groups_overage`, even alongside a supplied group list. Malformed group markers
or non-GUID lists report `groups_invalid`; missing lists report `groups_missing`.
No token-supplied claim-source URL is fetched. Admission refusals remain generic
`UNAUTHENTICATED` to callers; the host's fixed, rate-limited reason codes are the
clear operator diagnostic. Other policy reasons are `role_required`,
`group_required`, and `member_required`.

On startup the host logs `approval sources active` with the configured subject
**count** and configured `app_roles` names, together with `member_only`, configured
`required_roles` names and `required_group_count`. These are operator settings,
never claim values, subject IDs or group IDs. Invalid policy configuration is
refused at host startup with a field-specific rule, without echoing the value;
`Config.ValidatePolicy` also exposes this check without trust I/O. Approval role checks re-verify the same request's
credential and bind its identity to `authn.Caller(ctx)`. They retain no roles or
authority by subject; calling the policy without incoming credentials fails
closed. No upstream Sessions role transport or owner isolation is implied.

For the API registration, define user app roles and assign users/groups to them
so delegated tokens contain `roles`. Enable GUID group claims for group checks;
**do not use `emit_as_roles`**, which replaces app roles with group values.
Configure `acct` in `optionalClaims.accessToken` before enabling `memberOnly`.
Test fresh tokens after assignment/configuration changes; previously issued
tokens retain their permissions until expiry. The chart's auth ConfigMap is
immutable: changing a policy requires the documented stop-and-replace upgrade
procedure, not an in-place ConfigMap update.

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
   scope and, **unless optional checks above are configured**, not the user
   population: every user who can get a delegated token for an allowlisted client
   and `RequiredScope` authenticates, and
   authenticated callers share session access ([host limits](host.md)). Depending
   on tenant policy that can include B2B guests; enable `memberOnly` to require
   explicit member status. Enable **Assignment required** (`appRoleAssignmentRequired=true`)
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
   `optionalClaims.accessToken`, shows guest status in a token; `memberOnly`
   requires this claim to be present and exactly integer `0`.

The API verifier needs **no client secret or refresh token**. App-only workload
identity/client-credentials tokens cannot replace the delegated user token; do
not add client-credentials for this path. Optional app-role checks use user
assignments, not app-only permissions; step 5's Default Access alone emits no
app role. Tenant, issuer, audience, and client IDs are
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

The `go.mod` requirement selects canonical upstream Sessions **v0.3.0**
(commit `bcbd4d9dcb352a10444119c2e6f75b4715dc68e0`), with no fork replacement.
It includes the merged [authentication seam (#180)](https://github.com/agent-primitives/sessions/pull/180)
(`NewInterceptors`, `CallerVerifier`, `Caller`); the Entra verifier contract is
unchanged. Unary authentication is admission-only: a completed handler result is
not overwritten solely because its context ended during execution. Streaming
expiry enforcement remains in the upstream interceptor.

The release also supplies opt-in
[per-RPC authorization (#190)](https://github.com/agent-primitives/sessions/pull/190),
but this host does not enable it. The pin alone does not provide required-mode
resource authorization or verified approval attribution; the [remaining host
work](host.md#what-still-belongs-upstream) is unchanged. Do not select v0.2.0,
which lacks the authentication seam. Follow the [journal upgrade warning](host.md#configuration-and-local-build)
before opening retained state with this release.
