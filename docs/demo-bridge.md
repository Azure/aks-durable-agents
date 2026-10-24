# Deletable source-file demo bridge

Not AgentSuite deployment, package attestation or a Ready agent (#67).
Export with `kmx run-profile export FILE`; parsing stays in kmx. Producer projection
into existing Exec.Config is only:
```sh
jq -c --arg ref "$ORIGINAL_EXPORT_SHA256" \
  '{system_prompt: .instructions.text, reference: $ref}' producer.json > config.json
```
Retain exact export/Config bytes and hashes, authored model and explicit target model
before execution. Reference is opaque correlation, not trust. Label model differences;
examples remain `not_run`, with no target parity claim. Use fictional material.

## Run once
Build `go build -o .build/session-fixture ./cmd/session-fixture`. In an owned empty
absolute nonsymlink mode-0700 `$DATA`, initialize and start separate roles:
```sh
.build/session-fixture bridge-init --data "$DATA"
.build/session-fixture bridge-harness --model "$TARGET_MODEL"
.build/session-fixture executor --scenario source-demo-v1 --database "$DATA/publications.db"
```
Configure the existing host: static route `demo-release-notes`, harness address,
matching `-model`, `$DATA/tools.json`, `$DATA/journal.db`. Start the harness first:
startup Describe checks model compatibility; execution checks identity, including
Substrate. Loopback is default; explicit harness `--addr 0.0.0.0:9000` is private-pod-only.
Retain required TLS/auth, bounded model policy and operational authorization.
SDK Create selects this route/target Model; Exec takes exact Config and one text input.
The host rejects weak mediation before the controller and all harness-reported results.
Inspect the draft. Qualified Approve records only a decision; explicit owner Resume
publishes. One owner independently satisfying approver policy is supported.
Legacy plaintext clients are not signed-in qualification. Never relax auth/listeners.

Publication is one SQLite body BLOB plus receipt in one transaction, not an external
post or separate `.json` file. Session/key/payload dedup survives lost replies;
changed payload is refused. Reconcile uncertainty, never blindly retry. Keep v1/v2
lineages separate. Journals contain private instructions/input/output; same-access
pod/filesystem processes remain trusted.

## Zero-call replay
Stop/fence writers; use existing consistent backup/restore for BOTH journal and
publication DBs, preserving committed WAL/needed sidecars. Never copy only main
files or discard WAL. Restore a complete copy to mode-0700 writable scratch:
```sh
.build/session-fixture bridge-verify --journal "$SCRATCH/journal.db" \
  --session "$ORIGINAL_UID" --model "$ORIGINAL_TARGET_MODEL" --config-sha256 "$ORIGINAL_CONFIG_SHA256"
```
Thin checks bind original Config/model/version, positive approval and the exact durable
publication/receipt. Existing isolated-memory replay rejects unfinished runs and uses
failing model/tool callbacks, requiring zero calls and full coverage. SQLite may create
bookkeeping in scratch: this is not a live-store forensic audit. Output is `bridge_only:true`,
examples `not_run`, not human attribution/package/live WI/AKS/image qualification.
Frozen nightly behavior and claims stay unchanged.
