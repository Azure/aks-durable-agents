# Labelled source-file demo bridge

This opt-in fixture runs authored instructions through existing Sessions execution
`Config`. It is **not AgentSuite deployment, package admission or a Ready agent**.
It adds no deploy, profile-ingestion or registration RPC. AgentSuite-by-digest
work remains separate ([#67](https://github.com/Azure/aks-durable-agents/issues/67)).

Agent-file parsing/export belongs in kmx. The producer uses
[`kmx run-profile export FILE`](https://github.com/kaimahi-agents/kaimahi/pull/685)
and maps its output to ordinary execution Config. Neither the host nor fixture
reads Markdown or understands the kmx export envelope. Keep the export, authored
model and ordered examples as separate producer evidence. Exported examples stay
**`not_run`**; this scenario does not execute assertions or establish target parity.
If the target model differs from the authored model, label the result explicitly
as a different-model source-file demo. An unspecified authored model is not parity.

## Runtime and approval boundary

The static fixture route is `demo-release-notes`. Its harness requires an explicit
target `--model`; its descriptor advertises that model and binds it into the replay
version. The host requires that model to equal its configured `-model` deployment,
checks session selection and plain/stream requests, and refuses mismatches before
transport. Legacy routes retain their existing deployment override behavior.
This records configured model selection, not provider weight/build attestation.

The removable host adapter always requires approval for `publish_release_notes`
on this exact static route, independent of descriptor mediation or instructions.
It uses the existing version-1 `tools.json` executor/durable-dedup contract; there
is no new tool-config field or profile admission API. The host intercepts proposals
before the controller sees them. A weaker/unspecified/reported proposal is refused,
not upgraded: the pinned remote transport requires the original proposal to carry
approval mediation for its durable park handshake. A correctly marked proposal
parks normally. This demo route accepts no harness-reported results, including
standalone results before any tool proposal.

There is no local effect before approval. An authorized `Approve` records a
decision; it **does not Resume**. The owner must explicitly Resume using the
verified current head and expected pending tuple. The existing required-auth TLS,
owner and approver policy still applies. A single owner who independently meets
approver policy is supported. Do not loosen authentication or listeners to test it.

Publication is one bounded verbatim draft in a SQLite `publications` body BLOB,
plus its `receipts` row in the same transaction. The `.json` artifact name is an
identifier, **not a separate filesystem file**. The destination is fixed to
`release-notes-demo`; nothing is posted externally. Receipts carry `local_demo`,
artifact, draft, destination and exact Config digest, not a simulated-auth label or
independently verified human identity. Same session/key/payload returns the same
receipt; changed payload is refused. A lost reply is unknown, not permission to
start another operation. Reconcile the existing receipt under the original key.
Private socket/filesystem access remains a trusted pod/operator boundary, not OS
containment against another process with the same access.

## Prepare without inference

Build with the repository's pinned Go toolchain. Use two new, owned, nonsymlink
mode-0700 directories; initialization refuses nonempty or retained state. The
runtime directory must not contain producer files before `bridge-init`.

```sh
set -eu
umask 077
go build -o .build/session-fixture ./cmd/session-fixture
INPUT=/absolute/private/demo-input
DATA=/absolute/private/demo-runtime
mkdir -m 700 "$INPUT" "$DATA"
.build/session-fixture bridge-init --data "$DATA"

# Review and freeze the source first. These are producer-side commands only.
kmx run-profile export ./release-writer.agent.md > "$INPUT/producer.json"
REFERENCE="sha256:$(sha256sum "$INPUT/producer.json" | awk '{print $1}')"
jq -c --arg ref "$REFERENCE" \
  '{system_prompt: .instructions.text, reference: $ref}' \
  "$INPUT/producer.json" > "$INPUT/config.json"
CONFIG_SHA256="sha256:$(sha256sum "$INPUT/config.json" | awk '{print $1}')"
```

Record the exact export and Config bytes/hashes, authored model and explicitly
chosen target model **before executing**. The reference is an opaque producer
correlation digest, not parser/build attestation, package identity or authorization.
Do not derive an "original" binding from whichever profile exists after restart.
All source, input and model output is retained in the private journal and is
visible to authorized readers/approvers. Use nonsensitive fictional material.

In separate processes, start the local fixture roles:

```sh
.build/session-fixture bridge-harness --model "$TARGET_MODEL"
.build/session-fixture bridge-executor --data "$DATA"
```

The harness defaults to literal loopback. Explicit `--addr 0.0.0.0:9000` is only
for a privately isolated pod, not public access. The executor owns
`DATA/publish.sock`; it refuses a preexisting socket rather than removing an
unknown owner. Its DB is `DATA/publications.db`. Each role emits metadata-only
readiness JSON. Existing v1/v2 roles refuse this separately marked data lineage.
Do not adopt, migrate or repair their journals/receipts into this scenario.

Use the existing [host configuration](host.md) with this static harness address,
`-tool-executors=DATA/tools.json`, a journal in `DATA`, and explicit matching target
model. Start the harness before the host: model-policy registration requires a
successful bounded Describe, so an unreachable harness refuses host startup/restart.
Required-auth use still needs verified TLS, identity and approver policy;
live use additionally needs the reviewed bounded model policy, private networking
and operational authorization. No chart, image digest or live deployment is
qualified by this fixture.

An SDK producer uses the existing APIs: CreateSession with
`Harness: "demo-release-notes"` and the explicit target Model; Exec with the exact
Config bytes and one plain text user input. Retain the returned session UID and
pending execution/call/request tuple. It is a single-turn scenario. Inspect the
draft before qualified approval, verify the durable decision, then explicitly
Resume as owner. The legacy plaintext demo client is **not** a signed-in TLS
client for this route; a real interactive client/approval qualification is separate.

## Inspect and strict replay

`bridge-inspect --data "$DATA"` reports counts and artifact hashes, not draft text.
After completion, stop/fence the writers and retain a **checkpointed** snapshot.
Strict verification refuses nonempty WAL/rollback journals. Preserve them and
recover/checkpoint a complete copy on writable recovery scratch; do not delete
sidecars or checkpoint retained evidence inside the verifier. SQLite immutable
reads avoid creating empty WAL/SHM on cold databases, but would ignore nonempty
WAL, which is why this precondition fails closed.

```sh
.build/session-fixture bridge-verify \
  --data "$DATA" --journal "$DATA/journal.db" \
  --session "$ORIGINAL_UID" --model "$ORIGINAL_TARGET_MODEL" \
  --config-sha256 "$ORIGINAL_CONFIG_SHA256" --reference "$ORIGINAL_REFERENCE"
```

These values must come from the retained original binding. Verification binds
recorded Config/reference, descriptor version and model, checks one positive
approval graph and the matching durable local artifact, then replays every
completed invocation in isolated memory with failing model/tool callbacks and the
same host approval wrapper. Success requires zero provider/executor calls and
unchanged journal bytes/head and publication bytes/inventory. Output is labelled
`bridge_only: true`, with `target_examples: "not_run"`. This is not signed-in human
attribution, an external post, package-by-digest execution or a live WI/AKS result.

Offline tests cover real host/fixture RPC assembly, synthetic signed-in TLS owner
policy, restart, explicit Approve/Resume, wrong bindings, lost-reply deduplication
and strict replay. They do not qualify live credentials, target examples, an image
or cluster isolation. Frozen nightly v1/v2 scenarios and their simulated-auth
claims are unchanged.
