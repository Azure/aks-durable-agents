# Bounded Chat transport

Library callers opt in with Config.Policy. OpenPolicyFile(path) returns
(*Policy, error); keep that policy open until all responses are closed, then call
Policy.Close() error. Config.Endpoint, Scope, Deployment, Credential and Transport
retain their existing meanings. A nil Policy deliberately preserves the legacy,
unbounded library API; CLI assembly must require a policy separately.

Version 1 of the policy file is a strict JSON object. Its required fields are:

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
Both versions optionally accept `"maxInputTokens": 32768`. Omission retains the
8192 input bound; no other explicit value (including 8192) is supported.
`Policy.InputLimit()` reports the selected bound. Version selects the attempt
count, not the input bound. Completion remains fixed at 4096, including reasoning.

Omitted-field snapshots for both versions remain byte-identical. Adding/removing
the opt-in or changing versions/counts against an existing ledger is refused,
not a way to replenish its budget. Use a new run with a separate ledger; do not
reset or migrate historical evidence. Older binaries reject the new field rather
than silently applying a smaller limit. The bound does not alter outgoing request
bytes or hashes, or neutral requests recorded by Sessions.

## Planned-call identity (library-only version 3)

Version 3 is an internal foundation for trusted host code, not an operator/serving
profile. The current host, chart and legacy rehearsal reader support only v1/v2;
the host refuses v3 when constructing its shared client (after opening the ledger).
It does not run packaged tests or establish qualification or Ready.

V3 retains v2's required `"maxAttempts": 3` and all existing pricing, token, USD 2
and timeout limits. It additionally requires `"plannedCallSlots"` containing
exactly three distinct IDs, for example:

    "plannedCallSlots": ["case/1:repeat/1", "case/1:repeat/2", "case/1:judge/1"]

IDs contain 1–128 ASCII letters, digits, `_`, `-`, `.`, `:`, or `/`. Use opaque
host-generated identifiers, never prompts, answers, credentials or personal data.
Array order has no execution meaning, but changing it changes the frozen snapshot.
V1/v2 must omit this field, including an empty array.

Trusted code constructs a separate `Config{Policy: p, CallSlot: id, ...}` client
or transport for each declared slot. V3 requires an exact declared ID; nil/v1/v2
policies require an empty selector. Validation precedes credential construction.
The selector is copied at construction, not read from request headers, context or
model output. It does not derive or authenticate a qualification plan: the trusted
caller must establish that mapping before constructing transports.

Each slot permits at most one reservation, even after success, restart, or a
changed request body. Different slots may send byte-identical normalized bodies;
their separate slot IDs and equal request hashes remain in the ledger. A refused
duplicate writes no attempt and does not poison unused slots. An actual reserved,
dispatching, failed or unknown attempt still blocks the entire run. Concurrent
unused slots may refuse while another attempt is unfinished; refusal never grants
permission to send. There are no automatic retries or new slot IDs on failure.

V3 is a distinct persistent format: `model_attempts` adds `call_slot TEXT NOT NULL
UNIQUE`, while `request_hash TEXT NOT NULL` is no longer unique. The other columns
and transitions remain unchanged. V3 verifies its exact schema and stored slot/hash
identities on open. An existing v1/v2 ledger cannot be adopted as v3, nor vice
versa; changed plans also refuse. No migration, reset, general suite-sized budget,
judge execution or production wiring is supplied by this profile.

## Shared run budget (library-only version 4)

`ValidateRunConfig(RunConfig) error` performs pure preflight;
`OpenRunPolicy(RunConfig) (*Policy, error)` freezes a deep copy and opens one
private run ledger. This programmatic API is not a new operator file profile:
`OpenPolicyFile` rejects its version-4 snapshot. The host and chart do not wire it.

`RunConfig` holds `RunID`, absolute private `LedgerPath`, a canonical SHA-256
`PlanDigest`, optional `MaxInputTokens: 32768`, explicit `Bindings`, and `Slots`.
Every `RunBinding` has an opaque `ID`, explicit HTTPS `Endpoint`, `Scope`,
`Deployment`, and `RunPricing` with the same units/source/date/zero-extra rules
as v1–v3. Every `RunSlot` has an `ID` and `BindingID`. IDs use the v3 character and
length contract. There must be 1–64 unique slots and unique bindings, all bindings
referenced. Encoded run snapshots are bounded to 64 KiB.

One shared `Policy` owns all candidate and judge transports. Construct each with
`Config{Policy: p, CallSlot: slotID, Endpoint: ..., Scope: ..., Deployment: ...}`.
The tuple must match that slot's frozen binding before credential construction;
the request's model must then match the selected deployment. The same run-wide
input bound applies to every request and response. `AttemptLimit()` is the total
slot count, not a per-binding allowance. `Close()` fences every attached transport.
The existing global unfinished/failed/unknown stop and once-per-slot rules apply.
Calls are sequential; a fresh transport or second process handle does not refill
slots. A new arbitrary ledger is not retry or recovery authority.

V4 reuses the v3 slotted table schema but stores a distinct immutable snapshot.
Changed plan, prices, slots, ordering, bindings or run identity refuse reopen;
v1/v2/v3 and v4 cannot adopt each other's ledgers. No reset or migration exists.
`PlanDigest` ties this separate budget to the original qualification plan; the run
snapshot is never written back into that plan's serving `PolicyDigest`.

For heterogeneous bindings the reservation is the sum over **all** slots:

    sum(inputLimit * slotBinding.inputMicroUSDPerMillionTokens
        + 4096 * slotBinding.outputMicroUSDPerMillionTokens)
        / 1,000,000 microUSD

The numerator must still be at most 2,000,000,000,000 (USD 2). Nothing discounts
reservation to actual prompt length or usage. At illustrative USD 2.50/10 per
million input/output tokens, only 32 slots fit at 8192 input, or 16 at 32768.
64 is a maximum envelope, not a promise every price/model fits. Combined overflow
or over-cap inventories refuse before any ledger, credential or model request.

The qualification adapter derives complete repetitions and two slots per judge
assertion. It reserves host-supplied bindings, not package judge provenance,
prompts/scoring, candidate execution, activation or Ready. See
[qualification preflight](../docs/qualification.md#run-budget-preflight).

## Reservation and input accounting

Before any model call, the immutable snapshot reserves the full rational amount
for v1–v3 using the selected attempt count (2 or 3, including v3's fixed 3) and
input bound (8192 or 32768):

    attempts * (inputLimit * inputMicroUSDPerMillionTokens
              + 4096 * outputMicroUSDPerMillionTokens) / 1,000,000 microUSD

The numerator must be <= 2,000,000,000,000, exactly (USD 2); arbitrary-precision
integer arithmetic avoids rounding and overflow. The illustrated rates reserve
5734.4 microUSD (USD 0.0057344) for version 1, or 8601.6 microUSD
(USD 0.0086016) for version 2, with the default 8192 input bound. Version 2 with
32768 input reserves 15974.4 microUSD (USD 0.0159744). Reservation is a conservative bound, not a claim
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
arbitrary deployments or provider-specific formats. Requests above the selected
input bound are refused before ledger reservation, credential acquisition or
network activity. Raw request size is also capped at 64 KiB. Response usage is
independently checked against the same selected input bound and 4096 output;
reasoning counts, when present, must be within output.

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
deployment/path configuration. The v1/v2 fixed tables are:

    model_budget(id INTEGER PRIMARY KEY CHECK(id=1), snapshot TEXT NOT NULL)
    model_attempts(
      id INTEGER PRIMARY KEY, request_hash TEXT NOT NULL UNIQUE,
      started_at TEXT NOT NULL, finished_at TEXT, outcome TEXT NOT NULL,
      input_tokens INTEGER, output_tokens INTEGER, reasoning_tokens INTEGER)

Attempts transition reserved -> dispatching -> succeeded/failed/unknown.
Reservation is committed before credentials; dispatching is committed before any
possible POST. A transaction serializes reservations across processes. The selected
attempt ceiling (two/three for v1–v3, total slots for v4) survives restart; any
non-succeeded earlier attempt blocks every subsequent reservation. Canonical outgoing JSON is SHA-256 hashed, never stored;
duplicate hashes are refused even after success in v1/v2. V3/v4 instead refuse
duplicate slots, retaining a separate hash for each slot as described above.
No prompts or bearer credentials are written to the ledger. Timestamps use UTC RFC3339Nano.

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
