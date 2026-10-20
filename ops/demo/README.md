# Disposable kind demo

From the repository root:

```sh
make demo
```

## Prerequisites and boundaries

- Linux/amd64 Docker backend and a POSIX terminal (Linux tested).
- kind v0.33.0+, kubectl compatible with Kubernetes v1.37, Helm, Python 3 and Make.
  Tested locally: kind v0.33.0, kubectl v1.37.0, Helm v4.1.3, Python v3.14.3.
- Internet access for public Go modules, images and the Cilium chart. Bootstrap
  is not air-gapped. Docker builds the two demo binaries; no host Go or private
  client checkout is needed. The scenario itself uses a deterministic local TLS
  fake model, never Azure/OpenAI credentials or a real provider.

The runner creates a random owned kind cluster and a private kubeconfig. Every
Kubernetes/Helm operation names that context explicitly; your current context is
not used or changed. It uses fresh UID/GID 65532, mode-0700 data, not retained
journals. It never adopts or resets earlier runs. Do not run it on a real cluster
or share its unauthenticated service with untrusted users.

The separate image is **local demo only**, labelled accordingly. Its base is the
chart's verified published host digest; the unchanged production executable is
retained as `/production-host`. The demo entrypoint has a fixed fake model,
scoped fake credential and loopback-only API. The published fixture is reused
unchanged for harness/executor/inert-fake roles. No demo image is published, and
production images, chart defaults and templates are unchanged. The chart's
synthetic test client ID is only a schema placeholder: kind has no Azure
workload-identity webhook, and identity is not exercised.

## What the printed steps prove

1. Build the separate fake-model image from public, pinned inputs.
2. Create kind, install digest-pinned Cilium, stage default-deny NetworkPolicy,
   a fresh PVC, and the existing chart. Start the fixture before the host.
3. Create one session and show the fictional release-note proposal at its
   pending-approval point. The independent HTTP meter must be one; effects zero.
4. Replace the host pod. Require the same session UID, journal sequence/hash,
   pending approval tuple and draft, with no repeated inference or effects.
5. Ask for `approve`, record only that decision, and check effects remain zero.
   Ask separately for `continue`; only then resume the frozen approved execution.
6. Require one publication, durable receipt and artifact, then scale **both**
   deployments to zero and wait for their writer pods to disappear.
7. **DEMO-ONLY sealing**, printed as its own step, described below.
8. Run the published fixture's first strict replay in a separate default-deny
   pod with a read-only data mount and read-only root filesystem. Require the
   completed head/hash, full execution coverage, zero provider/executor callbacks
   and unchanged model/effect inventories.
9. Delete only the owned kind cluster, including its PVC and fictional data.

`realModelCalls: 1` is the fixture's name for its transport-path ledger: here that
one request went to the **local fake**, not a real provider. `fakeModelCalls: 0`
is the separate inert-fake role's meter. The independent demo HTTP meter is one.
Approval is explicit CLI consent, not an authenticated named-person approval.
No real Kubernetes change is performed: publication is a simulated local effect.
The demo also runs two TCP positive controls and two denial probes before any
session starts. Controller-owned Jobs use literal pod IPs and no data mount.
Each Job first reaches an allowed listener, then requires the published probe's
TCP-timeout-only denial proof. A refused port, DNS error or cancellation cannot
pass. The results check required allow paths and no over-allow in the effective
policy set (including default-deny); they do not attribute a drop to one named
policy. Probe Jobs and temporary policy/listener resources are removed before
host replacement. This is not AKS or hostile-tenant isolation qualification.

## Demo-only sealing is preparation, not replay

**Real hosts do not run this seal command or switch their live stores from WAL
to DELETE as part of this demo procedure.** Normal SQLite WAL checkpoints are
not this special sealing step. Never apply the demo command to a real PVC.

A WAL-mode database can remain in WAL mode after a clean close removes its
sidecars. A read-only mount without usable `-wal`/`-shm` files can then fail to
open, despite `mode=ro`; the published fixture was observed returning
`SQLITE_CANTOPEN` (14). See [SQLite's read-only WAL conditions](https://sqlite.org/wal.html#readonly).
This is also a possible condition for a real offline inspection pod; it is not
proof that an ordinarily writable running host fails or that data is corrupt.

After all demo writers stop, the sealing helper opens only the existing owned
current-run journal/publication stores, with no database creation, application
reset or repair. On one connection per store it sets `synchronous=FULL` and
`busy_timeout=0`, and requires `journal_mode=DELETE` to succeed. SQLite checkpoints
committed WAL frames into the main files. Missing/unsafe/busy stores, a changed
completed head/hash, a non-DELETE result, remaining sidecars, or changed
model/effect inventories all fail closed. It does not retry or discard an error.

Sealing compares the saved completed journal head/hash and independent HTTP
meter, plus the fixture's model ledger digest and publication/receipt/artifact
inventory, before and after preparation. It writes an immutable sealed snapshot.
This is the **final write**: no writer restarts or read-write reopen happens
before read-only verification and teardown. Replay runs once, with no warm-up or
retry. Its byte-stability check applies to the sealed stores, not a claim that
arbitrary retained WAL stores can be replayed directly read-only.

For real data, follow the [backup/recovery procedure](../backup/README.md): it
preserves the source, copies all relevant sidecars into writable scratch and
validates/checkpoints only the copy. Do not delete WAL files, mark mutable stores
immutable, or ignore a first replay error to get a passing result.

## Time, interruption and evidence

The overall work budget is 600 seconds, including builds/downloads and both
prompts, with a cleanup reserve. EOF, any answer other than the exact requested
word, timeout, subprocess failure, Ctrl-C or SIGTERM aborts and attempts owned
cluster cleanup. No prompt auto-approves. For an explicitly automated local run:

```sh
printf 'approve\ncontinue\n' | make demo
```

A local successful run took 213.7 seconds including cleanup, with Docker build
layers and the kind node image already cached. This is not a cold-start timing
guarantee; network speed and user input count against the budget. Tool installation
is a prerequisite, not part of this measurement. No AKS timing was measured.

Private command logs, `proof.json`, `network-proof.json` and per-phase
`timings.json` remain under `.build/demo/<run>/`. Phase measurement includes
cleanup and does not extend the 600-second budget. Cluster
storage is deleted; local Docker images/build caches and evidence remain for
inspection. If automatic cleanup fails, the error prints the exact owned-cluster
cleanup command with its private kubeconfig and Docker provider. Do not delete an
unrelated cluster or relax the timeout to hide a failure.

## Checks

```sh
go test -race ./internal/democli ./internal/demohost
python3 -B -m unittest discover -s ops/demo -p 'test_*.py'
DEMO_DOCKER_REPLAY=1 go test -race -count=1 \
  -run '^TestPublishedReplayOnReadOnlyMount$' ./internal/democli
```

The Docker probe uses a real completed session, the real seal command and the
published fixture on a genuinely read-only, network-none bind mount. It checks
logical head/inventories and absent sidecars before the first replay. It is
opt-in; ordinary Go/Python CI does not imply that this container probe or the
full kind demo ran. Python chart-contract tests reuse the chart suite's existing
Helm/PyYAML test dependencies; the runner itself uses only the Python stdlib.

## Nightly/manual hosted kind e2e

`Nightly kind e2e` runs at 03:17 UTC and supports manual dispatch on canonical
`main`. It runs this same `make demo` with the explicit simulated `approve` and
`continue` answers, including the TCP controls/denials. It uses Ubuntu 24.04,
checked kind v0.33.0/kubectl v1.37.0, Helm v3.20.0 and Python v3.14.3. Public
image/module downloads can dominate cold setup; the first hosted timing is a
separate result, not inferred from a local warm-cache run.

The workflow declares no default token permissions. Its demo job explicitly
requests only `contents: read`. Only the separate reporting job requests
`issues: write` (plus `contents: read` for checkout), using `GITHUB_TOKEN` only.
Reporting is restricted to the canonical repo and main; it executes no PR code
or downloaded artifacts and uses no PAT, App or long-lived secret fallback.

The summary records phase durations, proof status, zero replay callbacks and
policy control/denial counts. Seven-day artifacts contain the generated summary,
proofs, console tail and newest numbered command logs only. Proofs have priority
under the 16 MiB/256-file cap; oversized logs are tail-truncated and old/excess
logs omitted with notes. Kubeconfigs, journals, environment dumps and whole data
directories are never collected. Invalid success proof fails visibly while
retaining diagnostic logs.

On failure, reporting finds or creates one `Kind e2e regression` tracker. Only
issues authored by `github-actions[bot]` with type `Bot` and the fixed title and
marker are eligible; stranger-authored lookalikes are ignored. Repeated failures
update/reopen the same issue, preserving text outside its managed block, without
per-night comments. Ambiguous or incomplete lookups fail without creating an
issue. Successful nights do not automatically close it; normal closure is manual.

### Reporting-only permission check — after merge

**Permission check runs after merge.** It is not a prerequisite for the demo,
and no pre-merge permission or hosted-run success is claimed. After the workflow
lands, the initial operator check is one manual dispatch:

```sh
gh workflow run kind-e2e.yml --repo Azure/aks-durable-agents \
  --ref main -f report_test=true
```

`report_test: true` skips the demo entirely and runs only reporting. It finds or
creates the same bot-owned tracker, adds a short `Test run: reporting permission
check. No demo was run.` comment with the run URL, then closes the issue. **This
also closes an existing open tracker**, so use the test deliberately. A denied
issue permission or API error fails the reporting job visibly; there is no token
workaround or masked failure. Repeated dispatches would repeat the comment, so
the initial post-merge check is dispatched once, not automatically retried.

This is issue #17's kind/fake-model stage only. Real AKS/model/workload-identity
qualification and Substrate variants still require their separate manual and
hosted validation.
