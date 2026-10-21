# Development and contributing

[Back to overview](../README.md)

Send changes as pull requests. Keep validation claims tied to the checks actually
run; offline fixtures do not qualify a live deployment.

## Start offline

Component checks run without Azure credentials or model keys. Use Python
**3.14.3** and the Go toolchain from [`go.mod`](../go.mod) (currently **1.27.3**):

```sh
go mod download
go test ./...
python3 -B -m unittest discover -s ops/backup -p 'test_*.py'
```

These exercise components with fake credentials and local test servers, not a
cluster workflow. For the self-contained fake-model kind workflow, use
[`make demo`](../ops/demo/README.md); it builds its own client inside Docker.

For Helm lint, rendering and refusal tests, use Helm **3.20.0** and the
[pinned Python requirements](../charts/aks-durable-agents/tests/requirements.txt),
then follow the [offline chart checks](../charts/aks-durable-agents/README.md#offline-verification).

## Deployment and rehearsal limits

The [local kind rehearsal](../ops/backup/README.md#local-kind-rehearsal) exercises
backup/replay with a fake model. It requires Docker, kind, kubectl, Helm and
matching fixture/client binaries. The reference fixture source and
[image build recipe](../ops/images/README.md) are included; the native RPC client
and tagged integration test's external JavaScript reviewer are not distributed
here. Those legacy rehearsal inputs are not required by the separate
[self-contained kind demo](../ops/demo/README.md), which supplies its own SDK
client and explicitly demo-only sealing step. See [external test inputs](#external-fixture-qualification)
for the legacy rehearsal.
The rehearsal uses kind Kubernetes 1.32.2 with chart YAML rendered for 1.37, not a
Helm install or AKS qualification.

For an existing cluster, follow the [chart's prerequisites and policy-first install](../charts/aks-durable-agents/README.md).
It targets **AKS 1.37**, Linux amd64, OpenID Connect (OIDC) and workload identity,
Cilium enforcement and Azure Disk CSI. Reviewed probe-capable image digests,
prepared private storage, and identity/TLS/model-policy inputs are required;
bare defaults cannot run. The root Dockerfile alone lacks the **legacy fixture
profile's** probe binary; the native profile uses `/host health-probe` and
requires its own reviewed producer image and prepared archives.
Workloads start dormant until the operator verifies policy enforcement.
Read the [backup and restore recipe](../ops/backup/README.md) before opening retained data.

## Full development checks

CI runs on pull requests and pushes to `main`. To run the same checks locally,
use the Go toolchain pinned in `go.mod` (currently Go 1.27.3; language floor 1.27):

```sh
set -e
test "$(go env GOVERSION)" = "$(awk '$1 == "toolchain" {print $2}' go.mod)"
go mod download
go mod verify
go build ./...
go vet ./...
go test -race ./...
go install honnef.co/go/tools/cmd/staticcheck@v0.8.2
staticcheck ./...
go install golang.org/x/vuln/cmd/govulncheck@v1.9.0
govulncheck ./...
```

Image validation additionally runs `bash ops/images/vulncheck.sh` after
`make images` and `bash ops/images/smoke.sh`, using the same installed scanner.
It strictly scans the actual packaged Go executables in all three images.
Publication scans built binaries before push and packaged binaries before signing.
Only kubectl/kubelogin runner scans are report-only, with full findings in the
run summary and separate artifacts; see the [runner scan policy](../ops/aks/TOOL-SCANS.md).
These Go checks do not audit OS layers or Python dependencies.

For the chart checks, use Helm **3.20.0**, Python **3.14.3** and the pinned
Python requirements:

```sh
python3 -m pip install -r charts/aks-durable-agents/tests/requirements.txt
python3 -B charts/aks-durable-agents/tests/test_chart.py
```

The chart suite includes strict `helm lint`, template/golden comparisons and
refusal tests with synthetic fixtures; bare defaults intentionally refuse missing
operator inputs. See the [chart README](../charts/aks-durable-agents/README.md#offline-verification).

Tests use fake credentials and local TLS servers, including the **real sessions
OpenAI adapter** at the [canonical upstream pin](entraauth.md#offline-verification-and-the-sessions-dependency). They require neither Azure access nor model keys. The [manual AKS workflow](../ops/aks/README.md) defaults to read-only dispatch validation and
retains independent owned-resource expiry cleanup. Its optional real-model scenario
is separately operator-gated, with simulated approval, parked-host restart, effective
policy controls, fenced backup/strict replay and whole-cluster teardown. There is
no scenario schedule: live execution and any AKS qualification claim remain blocked
until the separate Continue/replay qualification and manual-run approvals pass.
Offline tests use fake cloud commands and optional local Docker exercises, never
Azure provisioning or inference. A separately approved CLI-identity smoke check must use an
explicit `AzureCLICredential`, no retries, and at most three calls; missing RBAC
must be reported, not assigned.

Run the backup and native producer unit tests separately:

```sh
python3 -B -m unittest discover -s ops/backup -p 'test_*.py'
python3 -B -m unittest discover -s ops/canvas -p 'test_*.py'
python3 -B -m unittest discover -s ops/aks -p 'test_*.py'
```

## External fixture qualification

The `scenario_v2` suite is build-tagged and is **not** included in ordinary CI or
`go test ./...`. It requires matching reviewed fixture and native RPC binaries,
plus an external `sessions.mjs` reviewer in the layout expected by the test.
The fixture source/build recipe is now included, but the native RPC helper and
reviewer module are not distributed here. A fresh public clone still cannot
reproduce this tagged qualification from this repository alone. Ordinary
`go test ./...` now also runs the reference fixture's tests.

When those independently reviewed inputs are available locally:

```sh
ADA_FIXTURE_BINARY=/absolute/path/session-fixture \
ADA_NATIVE_BINARY=/absolute/path/reviewer/.runtime/bin/sessions-rpc \
go test -race -tags scenario_v2 -run TestScenarioV2ActualFixture -count=1 -timeout=90s ./internal/host
```

The reviewer module must be two directories above the native helper's directory.
Build the reference fixture from this repository with `make image-binaries`
and use its absolute `.build/images/session-fixture` path. Its public fixture
identity is a fresh lineage: initialize a new private subtree; do not adopt
journals or receipts from older externally built fixtures. The remaining external
client and reviewer requirements are unchanged.

The suite requires both absolute binary paths and fails rather than silently
skipping missing inputs. It exercises success, HTTP 429 and model timeout with a
fake TLS model, not live Azure inference or a signed-in approver. Use the
`ADA_*` names in launchers; no legacy environment aliases are supplied.

[Dependabot](../.github/dependabot.yml) proposes weekly dependency updates.
[CodeQL](../.github/workflows/codeql.yml) runs in the Azure repository with
licensed code scanning and in public copies. Other private copies skip rather
than claim unavailable licensed analysis ran. Check the actual analysis results;
neither configuration nor an empty/skipped check completes security review.
