# Reference images

The repository builds two Linux amd64 images for the chart's reference fixture
profile. They are not a production-ready agent or a self-contained demo.

| Image | Contents |
| --- | --- |
| `ghcr.io/azure/aks-durable-agents/host` | Unchanged production `/host`, CA roots, and `/session-fixture` for the chart's readiness probe |
| `ghcr.io/azure/aks-durable-agents/session-fixture` | Reference release-notes harness, durable local publication executor, inert loopback fake, and bounded evidence/reconstruction-replay commands |

Harness, executor and fake containers share the fixture image. No third executor
image is needed. The production host still requires workload identity for model
access. Neither existing `ops/backup/drillhost` nor `ops/canvas/drillhost` is built
or published by this workflow. A future separately labelled fake-model **demo
host** is not a production chart default.

## Build locally

Use Go **1.27.2** from `go.mod`, Make, Docker with BuildKit, and Linux amd64.
Python **3.14.3** runs the smoke and pin tests. These commands use only public
module dependencies and the pinned distroless base; no adjacent checkout, native
RPC helper, JavaScript reviewer, Azure credential or model key is a build input.

```sh
go mod download
go mod verify
go test -race ./...
make images
bash ops/images/smoke.sh
python3 -m pip install -r charts/aks-durable-agents/tests/requirements.txt
python3 -B -m unittest discover -s ops/images -p 'test_*.py'
```

`make image-binaries` writes `.build/images/host` and
`.build/images/session-fixture`. The build fixes the Go toolchain, module graph,
OS/architecture, CGO setting, source paths, VCS embedding and linker build ID.
`images/Dockerfile` copies only those static binaries onto an immutable base,
with UID/GID **65532** and no runtime downloads. The root `Dockerfile` remains
the host-only packaging option for profiles that do not need the fixture probe.

For a second binary reproducibility check:

```sh
make image-binaries IMAGE_CONTEXT=.build/repeat
cmp .build/images/host .build/repeat/host
cmp .build/images/session-fixture .build/repeat/session-fixture
```

This checks reproducible binary contents. Registry indexes also contain build
provenance, SBOM generation timestamps and signing evidence; these are not
claimed to be byte-identical across runs. The publish workflow additionally
uses the source commit's timestamp and BuildKit's timestamp rewrite for layers.
Buildx, BuildKit and the SBOM scanner are version/digest-pinned in the workflow.

## Fixture interface and retained data

Source lives in `internal/sessionfixture` and `cmd/session-fixture`. Run
`.build/images/session-fixture` without arguments for the role list. The chart
uses `harness --scenario v2`, `executor --scenario v2`, `fake`, and
`network-probe`; initialization, evidence and strict replay are explicit
operator commands, not startup effects.

Initialize a **new private subtree** with `init --scenario v2 --data ABSOLUTE_PATH`.
A model ledger is not created by initialization. Until the host has created its
ledger, v2 `evidence` refuses rather than manufacturing a zero-call report.
`verify-replay` reconstructs completed controller work with provider/executor
callbacks forbidden; it is not just a journal listing.

The executor creates `publications.db` only when absent. Existing empty databases
or missing required tables/columns refuse recovery instead of rebuilding lost
deduplication history. A failed first initialization can also leave such a file.
Stop all writers and preserve the database, sidecars and journal for
reconciliation; do not delete or truncate retained state to make startup pass.
For a confirmed never-started new run, prepare a separate fresh subtree.

The public fixture uses its own frozen instruction/descriptor/executor namespace.
It must not adopt journals, receipts or instructions from older externally built
fixtures. There is no retained-data migration or automatic reset. Keep those old
artifacts and compatible binaries together; prepare a separate subtree for this
fixture. The chart still needs separately prepared storage, model policy,
identity and TLS inputs before workloads can run.

## Publish, then pin

`Images` validates PR image builds without package-write or OIDC permissions.
On canonical `main` pushes and `v*` tags it builds both images, attaches BuildKit
SPDX SBOM/provenance attestations, and signs the pushed **digests** using cosign
and GitHub OIDC. It uses only the job's ephemeral `GITHUB_TOKEN` and OIDC token,
not a PAT or long-lived signing key. Tags are locators, not immutable identities;
consumers must use digests. Main publication and tag publication have distinct
certificate identities matching their Git refs.

The `published-images` artifact (30-day retention) records `images.json`, extracted
SBOMs and signature verification results. The signed image index covers its
attached attestation manifests. SBOM generation is inventory, not a completed
security review. Missing build/signature/SBOM evidence fails publication.

The first publication is a bootstrap: **default digests stay blank until actual
signed images exist and both packages are public**. No synthetic test digest is
a release pin. `Verified image pins` runs after a successful main `Images` run.
It checks the run's repository/workflow/event/SHA, source ancestry and
image-relevant drift, then anonymously pulls both digests and verifies
signatures and attached SBOMs. It writes the verified digests to its job summary
and the `verified-image-pins` artifact, alongside signature and SBOM evidence.
**It does not write repository files, push branches, or create/update PRs.**

If packages are still private, verification prints a notice and stops without
exporting a verified artifact. After changing package visibility, run
**Verified image pins** manually on **main**, supplying the successful **Images
run ID** as `publish_run_id`. A failed run, tag publication, foreign
workflow/repository, or image-relevant source change cannot supply pins.
Docs-only and pin-only main changes do not invalidate the source. Markdown and
chart values are excluded from image publication so a pin merge does not
needlessly republish images.

### Open the pin PR as a person or lane

Use a successful canonical **Verified image pins** run, not an unverified
manifest or the earlier publication artifact. On a fresh branch from current
main in your own checkout:

```sh
# Replace this with the successful verification run ID, not the Images run ID.
run_id=REPLACE_WITH_VERIFICATION_RUN_ID
evidence=$(mktemp -d)
gh run download "$run_id" --repo Azure/aks-durable-agents \
  --name verified-image-pins --dir "$evidence"
python3 -m json.tool "$evidence/images.json"
python3 ops/images/update_pins.py update --manifest "$evidence/images.json" \
  --values charts/aks-durable-agents/values.yaml
git diff -- charts/aks-durable-agents/values.yaml
python3 -B charts/aks-durable-agents/tests/test_chart.py
git add charts/aks-durable-agents/values.yaml
git commit -m 'chore: pin verified reference images'
git push -u origin HEAD
gh pr create --repo Azure/aks-durable-agents --base main \
  --title 'Pin verified reference images' \
  --body "Pin the verified host and reference fixture digests from verification run $run_id. Required operator inputs and production host credentials are unchanged."
```

Review the manifest's `sourceCommit` against current main before opening and
merging; if image-relevant source changed, use a new publication and verification
run. Inspect the source run, artifact evidence and exact five-field values diff.
The updater validates manifest shape, repositories and digests; it does not itself
verify signatures. It also sets `includesHealthProbe: true` for the verified host
packaging. Operator inputs and dormant workload defaults are unchanged. Human
credentials used by `gh` stay outside Actions; no PAT or PR-creation token is
added to the workflows.

### Administrator checklist

Before publication, confirm:

- The Azure organization permits package creation and the exact SHA-pinned
  actions in `images.yml` and `image-pins.yml`, including Docker and Sigstore.
- The publish job explicitly requests exactly `contents: read`,
  `packages: write`, and `id-token: write`. Associated packages grant this
  repository Actions access. The default workflow token may remain read-only.
- The verification job requests only `contents: read` and `actions: read`.
  Actions PR creation may remain disabled by org/enterprise policy. No workflow
  requests repository-content write or PR write, and no policy bypass is needed.

After the first publication, a package administrator must make **both** `host`
and `session-fixture` packages public. A public repository does not automatically
make GHCR packages public. Then dispatch pinning as above. Do not enable the demo
or claim anonymous installation until anonymous digest pulls and signatures have
actually been verified.

To inspect a known main publication with cosign **3.1.3** and Buildx **0.38.0**:

```sh
# Substitute an actual digest from that run's images.json, not a tag.
image=ghcr.io/azure/aks-durable-agents/host@sha256:REPLACE_WITH_PUBLISHED_DIGEST
cosign verify \
  --certificate-identity https://github.com/Azure/aks-durable-agents/.github/workflows/images.yml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com "$image"
docker buildx imagetools inspect "$image" --format '{{json .SBOM.SPDX}}'
```

For a tag publication, verify the exact `@refs/tags/<tag>` certificate identity
instead; do not relax it to accept arbitrary workflow identities.

References: [GHCR access and visibility](https://docs.github.com/en/packages/learn-github-packages/configuring-a-packages-access-control-and-visibility),
[GitHub token permissions](https://docs.github.com/en/actions/tutorials/authenticate-with-github_token),
[BuildKit SBOM attestations](https://docs.docker.com/build/metadata/attestations/sbom/).
