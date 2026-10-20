# Development and contributing

[Back to overview](../README.md)

Send changes as pull requests. Keep validation claims tied to the checks actually
run; offline fixtures do not qualify a live deployment.

CI runs on pull requests and pushes to `main`. To run the same checks locally,
use the Go toolchain pinned in `go.mod` (currently Go 1.27.2; language floor 1.27):

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
OpenAI adapter** (the [module-wide pinned replacement](entraauth.md#offline-verification-and-the-sessions-dependency) also applies to these
tests). They require neither Azure access nor model keys. There is no
automatic live test. A separately approved CLI-identity smoke check must use an
explicit `AzureCLICredential`, no retries, and at most three calls; missing RBAC
must be reported, not assigned.

Run the backup and native producer unit tests separately:

```sh
python3 -B -m unittest discover -s ops/backup -p 'test_*.py'
python3 -B -m unittest discover -s ops/canvas -p 'test_*.py'
```

## External fixture qualification

The `scenario_v2` suite is build-tagged and is **not** included in ordinary CI or
`go test ./...`. It requires matching reviewed fixture and native RPC binaries,
plus an external `sessions.mjs` reviewer in the layout expected by the test. Their
source/build recipe and reviewer module are not distributed here. A fresh public
clone cannot reproduce this qualification from this repository alone; the
self-contained entry point is the ordinary Go, backup and chart checks above.

When those independently reviewed inputs are available locally:

```sh
ADA_FIXTURE_BINARY=/absolute/path/session-fixture \
ADA_NATIVE_BINARY=/absolute/path/reviewer/.runtime/bin/sessions-rpc \
go test -race -tags scenario_v2 -run TestScenarioV2ActualFixture -count=1 -timeout=90s ./internal/host
```

The reviewer module must be two directories above the native helper's directory.
The suite requires both absolute binary paths and fails rather than silently
skipping missing inputs. It exercises success, HTTP 429 and model timeout with a
fake TLS model, not live Azure inference or a signed-in approver. Use the
`ADA_*` names in launchers; no legacy environment aliases are supplied.

[Dependabot](../.github/dependabot.yml) proposes weekly dependency updates.
[CodeQL](../.github/workflows/codeql.yml) runs in the Azure repository with
licensed code scanning and in public copies. Other private copies skip rather
than claim unavailable licensed analysis ran. Check the actual analysis results;
neither configuration nor an empty/skipped check completes security review.
