# Keyless model transport

[Back to overview](../README.md) · [Bounded policy reference](../modeltransport/README.md)

Keyless HTTP transport for the sessions OpenAI **Chat Completions** adapter.

## Wiring

```go
import (
    "github.com/agent-primitives/sessions/model/openai"
    "github.com/Azure/aks-durable-agents/modeltransport"
)

// Pin this tuple from configuration; do not probe or switch audiences at runtime.
cfg := modeltransport.Config{
    Endpoint:   "https://your-resource.openai.azure.com/openai/v1/",
    Scope:      "https://ai.azure.com/.default",
    Deployment: "your-deployment",
}
h, err := modeltransport.NewClient(cfg)
if err != nil { return err }
defer h.CloseIdleConnections()
model, err := openai.New(
    openai.WithBaseURL(cfg.Endpoint),
    openai.WithModel(cfg.Deployment),
    openai.WithHTTPClient(h),
)
// Use model.Model / model.StreamModel with your existing sessions assembly.
```

Handle `err` before using `model`. No API key option is needed. The required
workload identity settings are `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, and
`AZURE_FEDERATED_TOKEN_FILE`. Nil `Credential` constructs only
`azidentity.WorkloadIdentityCredential`: no CLI, key, IMDS, or default credential
chain fallback. Tests inject `azcore.TokenCredential`; that seam is trusted
application configuration, not a runtime credential selector.

With a **nil Policy**, `Deployment` keeps the configuration tuple explicit but
is not a body-level allowlist. Sessions `WithModel` sets a default that a nonempty
`ModelRequest.Model` can override, so the host must control that field. A bounded
Policy instead checks the body deployment and explicitly injects the Chat
completion cap described in the [bounded policy reference](../modeltransport/README.md).
Neither mode converts Chat to Responses API.

The host assembly also bridges the journaled `ModelRequest.Params.response_format`
into the live Chat body, because the sessions Chat adapter does not serialize it.
Only that schema parameter is forwarded. Known harness hints `max_tokens` (700
or 16384) and `temperature` (0.2) do not override the host's fixed 4096 completion
cap or reasoning-model default temperature; other Params are refused. Both unary
and streaming host paths use the bridge. The generic library wiring above does
not install that host-specific Params bridge. The host refuses schema-mode
requests without a bounded Policy; a nil Policy remains supported for legacy
plain requests only.

With a bounded Policy, schema-mode responses require no refusal, nonempty content
and a successful `stop` finish. Buffered responses are checked before adapter
decoding. Streamed content frames reach the adapter as they arrive; a missing or
non-`stop` finish fails the call, but callers may already have seen streamed prefixes.
The [policy reference](../modeltransport/README.md) defines complete-input schema
accounting, streamed finish rules, and opt-in policy-version-2 three-attempt budgets.
These are fake-provider-tested contracts, not live model/schema compatibility or
AKS qualification.

## Guarantees and tradeoffs

- Only the configured HTTPS origin (case-insensitive hostname, effective port)
  and plain `/openai/v1/` paths are accepted. Userinfo, Host overrides, encoded,
  backslash, duplicate-slash, and dot-segment paths are refused.
- Request headers are cloned. All case variants of `api-key`, `x-api-key`, and
  `Authorization` are removed before adding the acquired Bearer token.
- Tokens are cached in memory, refreshed at least two minutes before expiry,
  and rejected if empty, malformed, or already inside that refresh window.
  Concurrent requests share the refresh result, including failures. A canceled
  waiter exits independently; cancellation of the refresh leader fails that
  flight for all waiters. A later request may start a new flight. No stale token
  is used after refresh failure, and no background refresh is started.
- `NewClient` has a two-minute total timeout with nil Policy, or 25 seconds with
  a bounded Policy, including token acquisition and body reads. Bounded direct
  `NewTransport` use also enforces 25 seconds; legacy direct callers must bound
  their own request contexts.
- Redirects are refused by both transport status handling and client policy.
  Every non-200 response is closed and replaced by a status-only error, including
  201/202 and redirects. This intentionally follows the sessions adapter's
  exact-200 success contract, rather than a general-purpose HTTP client's rules.
- Credential/network errors and successful-response body-read/close errors are
  sanitized; cancellation/deadline errors remain classifiable. Provider bodies
  are never included in transport errors. Successful response content is still
  returned normally, so callers must not log model content indiscriminately.
- The cloned underlying `*http.Transport` uses fresh **HTTP/1** connections:
  keep-alives and HTTP/2 are disabled to avoid net/http's internal replay paths,
  including POSTs with `GetBody` or an idempotency key. This sacrifices connection
  reuse for a simple no-automatic-model-retry boundary. There are no 429/5xx
  retries. Identity SDK token-endpoint behavior is separate from model POSTs.
- An optional `Transport` supplies trusted TLS/proxy/dial settings, primarily for
  private roots or tests. Its hooks must not introduce their own retries or
  logging of credentials. The supplied transport itself is not modified.

Do not put secrets in endpoints, URL query strings, model IDs, or headers other
than the credential headers above. As usual, `http.Client` and sessions add URL
and model context to their own error wrappers; the transport cannot sanitize
arbitrary application-owned strings outside its boundary. Use the pinned,
query-free `Endpoint` in the wiring above.

## Azure resource and scope

The initial read-only resource check identified a
`Microsoft.CognitiveServices/accounts` resource of **kind `OpenAI`**.
The example above uses a placeholder resource and deployment; pin your actual tuple.
The referenced [OpenAI v1 documentation](https://learn.microsoft.com/en-us/azure/foundry/openai/api-version-lifecycle)
and [Entra authentication documentation](https://learn.microsoft.com/en-us/azure/foundry-classic/openai/how-to/managed-identity)
explicitly use `https://ai.azure.com/.default` for this `/openai/v1/` API and
require **Cognitive Services OpenAI User** (or an appropriate stronger role).
Resource kind alone does not establish the audience for every API/version.
`https://cognitiveservices.azure.com/.default` is not probed or selected as a
fallback. The documented v1 tuple above has not been verified with live inference.
