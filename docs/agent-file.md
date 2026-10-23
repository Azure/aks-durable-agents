# Frozen release-writer source projection

[Back to documentation](README.md)

**Offline preparation only.** These commands freeze and inspect an operator-made
projection of one canonical `release-writer.agent.md`. They do not start a
harness, open a session journal, call a model, publish an artifact or deploy to
AKS. No authenticated approval, execution, restart or replay of this profile is
qualified by preparation. The nightly v1/v2 scenarios are unchanged.

The profile is explicitly a **different-model source-file proof**, not an
AgentSuite package or unchanged-model parity. Authored model and selected target
deployment remain separate. Examples are preserved but **not run**; neither a
source hash nor preparation means that examples passed locally or on the target.

## Preparation trust boundary

Prepare the projection locally through canonical `agentfile.Parse` from kmx at
[`bc1fc4a7c0ebeac37ef340c7928ed80e844f7643`](https://github.com/kaimahi-agents/kaimahi/tree/bc1fc4a7c0ebeac37ef340c7928ed80e844f7643).
That parser is internal to kmx. An operator may use a local-only helper inside an
isolated checkout of that exact revision; this repository does not provide a kmx
export command, extract its parser or interpret Markdown as an alternative.
Use `Parse`, not the display-only `Inspect` path. Refuse parser errors and
unsupported declarations rather than removing them from the source.

The parser's `Revision` hashes the original file bytes. Its `Instructions`
normalizes CRLF to LF and includes every line before `## Examples`, ending in
one LF, without trimming. Examples never become instructions. Preserve the
ordered parsed example IDs, inputs and complete assertions, including judge
fields, without executing any assertions or judging calls.

The operator is trusted to use that parser and preserve its output. ADA checks
bounds, exact JSON fields, hashes and the source-prefix relationship; **it does
not attest the helper or independently prove canonical acceptance**. Parser
provenance, authored model and parsed examples are operator declarations, not
independent source-to-field verification. A hash does not establish parser
execution, passing tests, model availability, image identity or caller authority.
Only fictional, non-secret source data belongs in this proof. A later target
model selection must not silently rewrite the source's authored model.

Freeze the final edited source after the local authoring/test loop, not the
initial intentionally failing sample. Keep the original local results separately;
they are not target qualification. Any subsequent source edit requires a new
profile/run and invalidates prior target evidence for those bytes.

## Projection contract

A private UTF-8 JSON object, at most **1 MiB**, with exactly these fields:

| Field | Value |
| --- | --- |
| `version` | Integer `1`. |
| `parser_commit` | Exact full kmx commit above; unknown pins refuse. |
| `source` | Base64 original source bytes, nonempty, valid UTF-8, at most 256 KiB decoded. |
| `source_sha256` | Parser Revision, `sha256:` followed by 64 lowercase hex characters. |
| `agent_id` | Exact `release-writer`. |
| `authored_model` | Parser's exact concrete model ID; not `auto`, a URL or wildcard. |
| `instructions` | Exact parser Instructions, nonblank, no Examples section. |
| `instructions_sha256` | SHA-256 of those exact UTF-8 instruction bytes, same digest spelling. |
| `examples` | Ordered JSON array of parsed examples; each carries `id`, `input`, `assertions`. |
| `examples_sha256` | SHA-256 of the exact serialized `examples` JSON value bytes. |

Serialize examples once and embed those same bytes; pretty-printing or
re-encoding them requires recomputing their hash. No YAML parsing or assertion
validation occurs here. ADA retains examples as opaque JSON array bytes
(1–128 entries); unknown nested example fields are not interpreted. This does
not make extensions runnable. Duplicate JSON keys at any depth, unknown or
case-variant top-level fields, trailing JSON, invalid UTF-8 and excessive nesting
refuse. Source and instruction hashes must match; instructions must be a prefix
of the CRLF-normalized source with the exact `## Examples` heading next.

The synthetic conformance fixture in
[`internal/sessionfixture/testdata/agent-file-projection.json`](../internal/sessionfixture/testdata/agent-file-projection.json)
was produced through that pinned parser. Its cases include a judge assertion to
check preservation, not evaluation. It is not a final agent or passing evidence.

## Commands and retained data

Build the existing fixture executable:

```sh
go build -o session-fixture ./cmd/session-fixture
```

Select an **existing, empty, owned mode 0700 directory** for the new profile and
an absolute, owned mode 0600 projection file in an owned private directory.
All path components must be nonsymlink. Preparation never creates directories,
repairs permissions, overwrites files or adopts historical state. For example,
with operator-prepared absolute paths:

```sh
./session-fixture agent-file-prepare \
  --data /private/proof/new-profile \
  --projection /private/proof/input/projection.json \
  --target-model target-deployment

./session-fixture agent-file-inspect --data /private/proof/new-profile
```

`--target-model` is explicit and must differ from the authored model. Neither
command verifies that the selected deployment exists or accepts workload
identity. No credentials are read or needed.

Preparation writes only two mode 0600 files:

- `scenario.json`: a new `agent-file-v1` marker, so old v1/v2 roles refuse this
  data rather than adopt it.
- `agent-file.json`: a version-1 envelope containing the **base64 exact projection
  JSON bytes**, `target_model`, `proof_kind: "different-model-source-file"` and
  `target_examples: "not-run"`. The envelope has a 2 MiB read limit.

Base64 embedding preserves projection whitespace, including the bytes covered
by `examples_sha256`. The entire exact envelope file, including its terminating
newline and target/status fields, is hashed to form
`release-writer-file-v1-<64-lowercase-hex>`. This is a frozen profile identity,
not a Kubernetes name or a registered runtime route. Whitespace changes alter
that identity. Inspection recalculates it; inspection alone does not compare
against a previous run or prove the files were never changed. A runtime consumer
must bind and compare the original profile identity before restart/replay.

Both commands return only hashes, parser pin, authored/target models and the
explicit proof/examples labels. Source, instructions, examples and local paths
are not printed. Keep these cleartext source/projection files private; the
operator owns retention. Do not put credentials or personal data in them.

Every pre-existing file, even an identical profile, makes preparation fail.
Files and directory entries are synced. A failure can leave partial state;
stop and reconcile that original directory. There is no automatic deletion,
retry, repair or success evidence for a partially completed preparation.
Private owned paths are not an OS sandbox against a hostile concurrent writer
with the same UID. Arrange exclusive operator access during preparation/use.

## Offline verification

```sh
go test -race ./internal/sessionfixture -run AgentFile -count=1
```

Tests exercise a pinned-parser conformance fixture, CRLF/source identity,
opaque example preservation, malformed JSON, hashes/models, private filesystem
refusals, no state adoption and unchanged v1/v2 separation. They make no model,
Azure, sign-in or target-example calls. See [development checks](development.md)
for the full repository gates.
