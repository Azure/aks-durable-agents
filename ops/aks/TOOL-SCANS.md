# CI runner tool scan policy

kubectl and kubelogin are checksum-pinned **runner-only tools**. Their binary
vulnerability scans are **report-only**, not an advisory allowlist or a clean
security gate. Every reported advisory is retained, including GO-2026-6809.
Findings do not prevent CI or an otherwise authorized scenario from proceeding.
This policy does not authorize a live scenario or enable a schedule.

| Tool | Release | Linux amd64 executable SHA256 | Embedded Go |
| --- | --- | --- | --- |
| kubectl | v1.37.1 | `65691ff77eb6fa44c908b77a1082c9f092c3b9733b5cefabec0d1104890e21a8` | 1.26.8 |
| kubelogin | v0.2.21 | `5160d49d0fb0d5f6fd7923058000f5fde34627a640cb4b313026992586c20ff2` | 1.26.6 |

The kubelogin ZIP has SHA256
`934a2a9618e018cb9fbeb14f3e4c28416fdae815df7706df91500e41d234eb66`.
Download checksums and the extracted executable hashes remain blocking. Unknown
executables, changed bytes or symlinks cannot use report-only mode as an integrity
bypass. These tools are not copied into host, fixture or backup-helper images.

`tool_audit.py` runs pinned govulncheck v1.9.0 in binary/symbol JSON mode. It
reports findings independently of scanner exit zero, which is not proof of a
clean JSON scan. Advisory IDs are deduplicated without stdlib, package or advisory
filtering. Module/package/symbol findings are scanner evidence, not a proof that
a selected command can exploit a vulnerability.

## Evidence and failure behavior

The credential-free CI job writes a fixed-field `report.json` and `summary.md`,
appends the Markdown to the run summary, and emits
warnings for non-clean results. Separate seven-day artifacts contain only these
two files, not raw scanner streams, errors, credential caches, paths or cloud data.
Callers use the same sanitized output boundary; no raw scan stream is uploaded.

Statuses are `clean`, `findings`, `scan-error` or `integrity-error`. Unavailable,
malformed, incomplete or scanner-cap-timed-out scans produce visible `scan-error`
reports and do not gate on advisories. They never count as zero vulnerabilities.
Integrity errors still fail. Cancellation and expiration of the enclosing
caller's elapsed budget still stop execution; report-only mode cannot extend it.
Missing report artifacts warn rather than conceal an earlier installation error.

## Own code and images remain strict

The source `govulncheck ./...` is unfiltered and blocking; it covers the compiled
scenario client as source. Image validation scans all actual packaged Go
executables from host, fixture and backup-helper images with unfiltered
`govulncheck -mode=binary`. Image publication also scans source and the built Go
binaries before pushing, then the actual pulled image executables before signing.
No runner reporting policy applies to these checks. An extraction or scan failure
blocks validation/signing. These are Go checks, not an OS-layer or Python audit.

Post-push packaged scans cannot undo already-pushed unsigned tags if a later
check fails. Pre-push scans cover the built Go bytes; only the successful signed
publication and its matching receipts are eligible for operator review.

## Follow-up

Track **all** findings for both pinned executables, not only GO-2026-6809. Refresh
compatible upstream builds when Go 1.26.10 / 1.27.3 or newer fixed patch builds
ship; verify publisher checksums, executable build metadata and both full scans.
A newer Go build alone does not resolve third-party/module findings such as
kubectl's GO-2025-3521 and GO-2025-3547. Review those separately and keep unresolved
findings visible. No tracking issue number is asserted before one is posted.
