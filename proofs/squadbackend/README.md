# SquadBackend proof

**This is a proof, not a product.** It is a non-shipping module for synthetic
team-state and Sessions runtime fixtures, not a production SquadBackend service.
The [fixture README](internal/squadproof/README.md) describes its safety limits.

Run these commands from this directory, in a complete repository checkout:

```sh
go mod download
go mod verify
go mod tidy -diff
go build ./...
go vet ./...
go test -race ./...
go test -race -tags squadproof ./...
go vet -tags squadproof ./...
go build -tags squadproof -o .build/squad-proof ./cmd/squad-proof
```

The local parent-module replacement reuses the shipping Unix tool adapter and
model transport without copying or exporting them. The root module does not
depend on this module; root `go build/test ./...` does not traverse it. Serving
fixtures and the command still require the explicit `squadproof` tag. No
production image or publication target includes the proof command.

CI runs this module separately, including staticcheck, govulncheck, module
boundary checks and the original fixture tests. CodeQL explicitly builds both
modules. Boundary tests require matching Go language/toolchain pins, common
declared dependency pins and versions of dependencies the proof actually uses.
Unused transitive modules in the parent's lazy graph need not be identical.

Dependabot version updates group each Go dependency across both module
directories, retaining the existing Substrate qualification hold. Maintainers
must also pair shared security-update changes and Go/toolchain bumps in both
manifests when needed; cross-directory version grouping does not cover those
changes. The alignment checks refuse drift. Keep both modules tidy and run
[both modules' checks](../../docs/development.md#full-development-checks) before
merging a shared dependency update.
