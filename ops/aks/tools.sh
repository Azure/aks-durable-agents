#!/usr/bin/env bash
# Install checksum-pinned runner clients using the repository toolchain.
set -euo pipefail
umask 077
tools="$RUNNER_TEMP/aks-nightly-tools"
mkdir -m 700 "$tools"
curl --fail --silent --show-error --location --connect-timeout 10 --max-time 120 \
  https://dl.k8s.io/release/v1.37.1/bin/linux/amd64/kubectl -o "$tools/kubectl"
printf '%s  %s\n' 65691ff77eb6fa44c908b77a1082c9f092c3b9733b5cefabec0d1104890e21a8 "$tools/kubectl" | sha256sum --check -
curl --fail --silent --show-error --location --connect-timeout 10 --max-time 120 \
  https://github.com/Azure/kubelogin/releases/download/v0.2.21/kubelogin-linux-amd64.zip -o "$tools/kubelogin.zip"
printf '%s  %s\n' 934a2a9618e018cb9fbeb14f3e4c28416fdae815df7706df91500e41d234eb66 "$tools/kubelogin.zip" | sha256sum --check -
unzip -p "$tools/kubelogin.zip" bin/linux_amd64/kubelogin > "$tools/kubelogin"
chmod 700 "$tools/kubectl" "$tools/kubelogin"
python3 -m pip install --disable-pip-version-check -r charts/aks-durable-agents/tests/requirements.txt
# Compile our client and scanner with the repository's toolchain pin.
toolchain=$(awk '$1 == "toolchain" {print $2}' go.mod)
test -n "$toolchain"
GOTOOLCHAIN="$toolchain" go build -o "$tools/demo-client" ./cmd/demo-client
GOTOOLCHAIN="$toolchain" GOBIN="$tools" go install golang.org/x/vuln/cmd/govulncheck@v1.9.0
printf '%s\n' "$tools" >> "$GITHUB_PATH"
