# Bounded Chat transport

Library callers opt in with Config.Policy. OpenPolicyFile(path) returns
(*Policy, error); keep that policy open until all responses are closed, then call
Policy.Close() error. Config.Endpoint, Scope, Deployment, Credential and Transport
retain their existing meanings. A nil Policy deliberately preserves the legacy,
unbounded library API; CLI assembly must require a policy separately.

Version 1 of the policy file is a strict JSON object, with exactly these names:

    {
      "version": 1,
      "runID": "<unique scenario run identifier>",
      "ledgerPath": "/absolute/private/scenario-directory/model.sqlite",
      "deployment": "<explicit deployment>",
      "pricing": {
        "inputMicroUSDPerMillionTokens": 100000,
        "outputMicroUSDPerMillionTokens": 500000,
        "extraMicroUSDPerCall": 0,
        "source": "<verified HTTPS official pricing URL>",
        "asOf": "2026-09-22"
      }
    }

The example rates/date are the supplied Luna September 22, 2026 official-blog
example, not production defaults or independently verified current pricing.
The source placeholder is intentionally not a valid URL: replace it with the
verified official blog URL and verify the deployment/SKU and rates before use.
There is no pricing fallback. USD is fixed by the microUSD field names: unknown
currency fields, missing rates, nonpositive rates, fractional/overflowing rates,
missing extras assumptions, nonzero extra charges, missing HTTPS source, invalid
dates, duplicate keys, case aliases, nulls and unknown fields are rejected.

Version 2 uses the same fields with `"version": 2` and the additional required
`"maxAttempts": 3`. It explicitly permits a three-turn writer/reviewer/revision
run. No other count is supported; version 1 must omit `maxAttempts` and retains
its two-attempt limit. `Policy.AttemptLimit()` reports the selected ceiling.
Existing version-1 snapshot bytes are unchanged. Changing versions/counts against
an existing ledger is refused, not a way to replenish its budget.

## Reservation and input accounting

Before any model call, the immutable snapshot reserves the full rational amount
(version 1 below; version 2 replaces the multiplier 2 with 3):

    2 * (8192 * inputMicroUSDPerMillionTokens
       + 4096 * outputMicroUSDPerMillionTokens) / 1,000,000 microUSD

The numerator must be <= 2,000,000,000,000, exactly (USD 2); arbitrary-precision
integer arithmetic avoids rounding and overflow. The illustrated rates reserve
5734.4 microUSD (USD 0.0057344) for version 1, or 8601.6 microUSD
(USD 0.0086016) for version 2. Reservation is a conservative bound, not a claim
of actual billing. Reasoning tokens are included in completion tokens, not added
again. The explicit zero extra-charge assumption must match the selected SKU.

Only POST /openai/v1/chat/completions without a query or content encoding is
supported. The closed request schema allows model, messages, stream,
stream_options.include_usage, max_completion_tokens, and optional response_format. Each message must have
a supported role (system/developer/user/assistant) and string content; no tool,
image, audio, name, or arbitrary provider fields are accepted. The model must
already match the pinned deployment. An omitted completion cap is injected as
4096; a different explicit cap is refused. Streaming always requests usage.

The complete conversation is bounded, not only its latest message:
256 envelope tokens + sum(64 + UTF-8 bytes(role) + UTF-8 bytes(content))
+ bytes(encoded response_format), when present.
One token per text byte plus deliberately generous framing is conservative for
the supported text-only Chat form. This is not a general tokenizer guarantee for
arbitrary deployments or provider-specific formats. Requests above 8192 are
refused before credential acquisition or network activity. Raw request size is
also capped at 64 KiB. Response usage is independently checked against
8192 input / 4096 output; reasoning counts, when present, must be within output.

## Structured output

`response_format` accepts only a `json_schema` object with `json_schema.name`
(1–64 ASCII letters/digits/underscore/hyphen), `strict: true`, and a schema whose
root type is `object`. The encoded format is bounded to 16 KiB and also counts
against the stricter complete-input limit. Its closed envelope rejects unknown,
duplicate, null and case-aliased fields. Schema vocabulary/capability is checked
by the configured provider; the host never drops schema mode or falls back to a
different adapter after rejection. The format participates in the outgoing
request fingerprint. Schema objects are re-encoded with sorted keys, preserving
number values without float64 rounding; formatting/property order is not a
byte-for-byte copy of the journaled format. Document scope and schema validation still belong to the caller,
not this transport; structured generation does not prove factual grounding.

Before the sessions Chat adapter can discard outcome metadata, schema-mode
responses require nonempty text, exactly one choice (index 0), a `stop` finish,
and no refusal or tool calls. Null/empty content, missing finish, `length`,
`content_filter`, and refusal-with-stop fail closed, even with valid JSON text.
Streaming accepts role-only and usage-only frames, but must accumulate text and
one successful finish before `[DONE]`; content after the finish is refused.
Partial streaming chunks are not a successful result or an accepted proposal.
Legacy requests without `response_format` keep their existing completion rules.
Known usage is retained on failure when it has already arrived; missing usage is
unknown, never zero. Provider refusal text is not included in errors or ledgers.

## Durable ledger and failure stops

The ledger directory is 0700, the file 0600. Existing unsafe permissions, symlinks
(including path components and SQLite sidecars), empty/corrupt existing ledgers,
or changed snapshots are refused rather than repaired or reset. SQLite uses
DELETE journaling and FULL synchronization. One canonical JSON snapshot is stored
in model_budget; one ledger belongs to exactly one run and immutable pricing/
deployment/path configuration. The fixed tables are:

    model_budget(id INTEGER PRIMARY KEY CHECK(id=1), snapshot TEXT NOT NULL)
    model_attempts(
      id INTEGER PRIMARY KEY, request_hash TEXT NOT NULL UNIQUE,
      started_at TEXT NOT NULL, finished_at TEXT, outcome TEXT NOT NULL,
      input_tokens INTEGER, output_tokens INTEGER, reasoning_tokens INTEGER)

Attempts transition reserved -> dispatching -> succeeded/failed/unknown.
Reservation is committed before credentials; dispatching is committed before any
possible POST. A transaction serializes reservations across processes. The selected
two- or three-attempt ceiling survives restart; any non-succeeded earlier attempt blocks every
subsequent reservation. Canonical outgoing JSON is SHA-256 hashed, never stored;
duplicate hashes are refused even after success. No prompts or bearer credentials
are written to the ledger. Timestamps use UTC RFC3339Nano.

Missing token counts are SQL NULL, never zero. Known partial counts may accompany
an unknown outcome. Success requires complete response JSON or a complete SSE
[DONE] event, known bounded input/output usage, and no non-success finish reason.
SSE is delivered event-by-event, not buffered as a whole response; comments and
CRLF are accepted, unsupported fields/multiline JSON fail closed. Abandoned,
truncated, missing-usage, malformed and canceled responses stop the run.
Responses are capped at 4 MiB. Consumers must close their bodies.

The 25-second context starts before credential acquisition and remains active
through response reads, including direct RoundTrip usage. A context callback
closes abandoned responses and records uncertainty. Cancellation does not undo
durable writes; storage reconciliation may outlive request cancellation.
HTTP status/credential/body errors are sanitized. No model retries are added;
HTTP/2, connection reuse and replayable bodies remain disabled.
