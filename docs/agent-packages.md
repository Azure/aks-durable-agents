# AgentSuite package verification

The experimental `internal/agentpackage` library pulls and verifies packages.
The opt-in [host controller](agent-runtime.md#opt-in-host-controller) uses it;
verification alone does not establish registration, Ready or qualification.
Integrity is not publisher authentication or runnable-member qualification.

## Registry access and proxies

References must use an allowed exact repository and a lowercase SHA-256 manifest
digest, not a tag. ORAS v2.6.2 handles anonymous bearer challenges and HTTPS blob
redirects. Every redirect hop drops Authorization, including same-origin hops;
a redirected endpoint cannot reuse the registry token. The usual ten-hop redirect
bound and 30-second pull deadline apply. Plain HTTP is restricted to the explicit
development authority, without configured credentials.

Private registries require explicit `Policy.Credentials[repository]` credentials.
The library copies them into a separate client/cache per allowed repository. It
never loads Docker stores/helpers, Azure credentials or the host identity chain.
Username/password and registry access tokens are supported, not OAuth refresh/login.
As in normal ORAS registry authentication, the configured registry selects its
bearer token realm; configure only trusted registries and scoped pull credentials.

`New(policy, nil)` deliberately ignores `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY`.
Setting those variables alone does not change library pulls. The enabled host
controller explicitly clones the default proxy-aware transport; embedding code
can likewise use the existing transport argument:

```go
transport := http.DefaultTransport.(*http.Transport).Clone()
transport.Proxy = http.ProxyFromEnvironment // HTTP(S)_PROXY and NO_PROXY
puller, err := agentpackage.New(policy, transport)
```

The caller owns proxy and TLS configuration. Supplying a transport does not
change repository credential scope, redirect stripping or content checks. Do not
put proxy credentials, registry tokens or response bodies in logs.

## Deliberately narrower host profile

This profile is an additional requirement, not the complete AgentSuite v0.7.0
format. A package passing Suite or produced by kmx can still be refused here.
Refusals expose a fixed `Error.Rule`; paths, package content and Suite messages
are not included. No existing size limit is increased by this profile.

| Rule | Requirement |
| --- | --- |
| `manifest-media-type` | Manifest explicitly declares `application/vnd.oci.image.manifest.v1+json`; Suite's omitted-mediaType form is not supported. |
| `descriptor-inline-data`, `descriptor-urls` | Neither descriptor field may be present, even as null. Matching inline `data` is still refused; config/layer bytes are fetched and checked separately. |
| `manifest-profile`, `descriptor-profile`, `blob-profile` | Schema 2, Suite artifact type, no subject or unknown fields, exactly one content layer; lowercase SHA-256 descriptors, exact two-byte `{}` empty config and Suite gzip-content media type. |
| `tar-format` | USTAR only: no GNU/PAX headers or records. A basename over 100 bytes needing PAX is refused; USTAR prefix/name paths remain supported. |
| `entry-type` | Only regular files and directories; **no symlinks, including in-root links**, hardlinks, devices or FIFOs. |
| `entry-path`, `duplicate-path` | Canonical UTF-8 relative paths, no backslashes, traversal, empty/dot components or duplicate entries. |
| `entry-mode` | No set-ID/sticky bits or group/world-write permission. |
| `byte-limits`, `manifest-limit`, `file-size`, `entry-count` | Manifest ≤1 MiB, compressed layer ≤8 MiB, file ≤1 MiB, at most 128 archive entries. |

The decompressed stream is capped at 16 MiB including headers/padding, not only
file data. Gzip CRC/footer, a single gzip stream, complete file bodies and no
trailing bytes are required (`gzip`, `tar`, `file-body`, `archive-tail`). Extraction
is confined by `os.Root`. Suite validates the same private tree backing `ReadFile`
and the retained report; its OCI-layout check separately validates the envelope.
The report describes validated content, not host eligibility or qualification.

## Verification results and failures

`Verify(ctx, expectedDigest, manifest, config, layer)` requires the intended
manifest digest and checks it before parsing/extraction (`expected-digest`).
Retention reloads must pass their stored identity, not hash the loaded manifest
and substitute that as the expectation. `Package.Report()` returns a copied
`*core.Report`, including independent nested platform slices. `ReadFile` and
`OCIBytes` also return copies.

Use `errors.Is` for `ErrUnavailable`, `ErrIntegrity` and `ErrUnsupported`, and
`errors.As` for `*Error` with `Role`, `StatusCode` and `Rule`. Registry reads name
manifest/config/layer; offline checks additionally name package/content/archive.
Status is the last observed response, zero if none, not a retry recommendation.
401/403 require access/credential correction; 404 means missing/inaccessible;
429/5xx and transport failures are unavailable. Successful responses failing
header/body descriptor checks are integrity failures. Profile refusals are
unsupported. Cancellation/deadline errors remain detectable with `errors.Is`.
Raw registry, URL, transport and Suite errors are not retained in the error chain.
