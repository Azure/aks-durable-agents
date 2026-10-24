// Package agentpackage pulls self-contained AgentSuite artifacts without executing them.
// Verification establishes byte/graph integrity, not publisher trust or runner eligibility.
package agentpackage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/agent-primitives/suite/oci"
	godigest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
)

const (
	maxManifest = 1 << 20
	maxLayer    = 8 << 20
	maxExpanded = 16 << 20
	maxFile     = 1 << 20
	maxEntries  = 128
)

// Policy is operator configuration, never package-supplied. Credentials are
// explicit pull-scoped registry credentials keyed by exact allowed repository;
// absent entries use anonymous bearer authentication, never ambient identity.
// HTTPRegistry permits plaintext only to that development authority, without
// configured credentials. OAuth refresh/login flows are not supported.
type Policy struct {
	Repositories []string
	HTTPRegistry string
	Credentials  map[string]auth.Credential `json:"-"`
}

type Puller struct{ repositories map[string]*remote.Repository }

// New accepts a trusted transport for host TLS policy or tests. Nil disables
// ambient proxies. ORAS handles bearer challenges; this client strips
// Authorization on every redirect hop, including redirects within one origin.
func New(policy Policy, transport http.RoundTripper) (*Puller, error) {
	if len(policy.Repositories) == 0 {
		return nil, fault(ErrUnsupported, "policy", "repositories-required")
	}
	if transport == nil {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.Proxy = nil
		t.DisableCompression = true
		transport = t
	}
	client := &http.Client{Transport: statusTransport{transport}, Timeout: 30 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		// net/http can copy the initial headers again on a later redirect hop.
		req.Header.Del("Authorization")
		// auth.Client installs CheckRedirect, so preserve Go's usual ten-hop bound.
		if len(via) >= 10 || (req.URL.Scheme != "https" && (req.URL.Scheme != "http" || policy.HTTPRegistry == "" || req.URL.Host != policy.HTTPRegistry)) {
			return fault(ErrUnsupported, "redirect", "redirect-policy")
		}
		return nil
	}}
	p := &Puller{repositories: make(map[string]*remote.Repository)}
	foundHTTP := policy.HTTPRegistry == ""
	for _, name := range policy.Repositories {
		r, err := remote.NewRepository(name)
		if err != nil || r.Reference.Reference != "" || r.Reference.Registry+"/"+r.Reference.Repository != name {
			return nil, fault(ErrUnsupported, "policy", "repository-reference")
		}
		r.PlainHTTP = r.Reference.Registry == policy.HTTPRegistry
		foundHTTP = foundHTTP || r.PlainHTTP
		r.ManifestMediaTypes = []string{ocispec.MediaTypeImageManifest}
		r.MaxMetadataBytes = maxManifest
		r.Client = &auth.Client{Client: client, Credential: auth.StaticCredential(r.Reference.Registry, policy.Credentials[name]), Cache: auth.NewCache()}
		p.repositories[name] = r
	}
	if !foundHTTP {
		return nil, fault(ErrUnsupported, "policy", "http-authority")
	}
	for name, cred := range policy.Credentials {
		r := p.repositories[name]
		if r == nil || cred.RefreshToken != "" || (r.PlainHTTP && cred != auth.EmptyCredential) {
			return nil, fault(ErrUnsupported, "policy", "credential-scope")
		}
	}
	return p, nil
}

// Pull resolves only an allowlisted repository@sha256 digest. ORAS performs
// registry I/O; all descriptor bytes are verified before extraction or Suite.
func (p *Puller) Pull(ctx context.Context, ref string) (pkg *Package, err error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	state := &readState{role: "manifest"}
	ctx = context.WithValue(ctx, readKey{}, state)
	defer func() {
		if ctx.Err() != nil {
			pkg, err = nil, state.failure(ctx, ErrUnavailable, "context", ctx.Err())
		}
	}()
	repo, dig, ok := strings.Cut(ref, "@")
	if !ok || !validDigest(dig) {
		return nil, fault(ErrUnsupported, "manifest", "digest-reference")
	}
	r := p.repositories[repo]
	if r == nil {
		return nil, fault(ErrUnsupported, "manifest", "repository-allowlist")
	}
	desc, body, err := r.FetchReference(ctx, dig)
	if err != nil {
		return nil, state.failure(ctx, nil, "registry-read", err)
	}
	if desc.Digest.String() != dig || desc.Size < 0 {
		body.Close()
		return nil, state.failure(ctx, ErrIntegrity, "manifest-descriptor", nil)
	}
	if desc.Size > maxManifest {
		body.Close()
		return nil, state.failure(ctx, ErrUnsupported, "manifest-limit", nil)
	}
	manifest, err := readDescriptor(ctx, state, body, desc)
	if err != nil {
		return nil, err
	}
	m, err := parseManifest(manifest)
	if err != nil {
		return nil, state.failure(ctx, nil, "manifest-profile", err)
	}
	blobs := make([][]byte, 0, 2)
	for i, d := range []blobDescriptor{m.Config, m.Layers[0]} {
		state = &readState{role: []string{"config", "layer"}[i]}
		ctx = context.WithValue(ctx, readKey{}, state)
		target := ocispec.Descriptor{MediaType: d.MediaType, Digest: godigest.Digest(d.Digest), Size: d.Size}
		rc, err := r.Fetch(ctx, target)
		if err != nil {
			return nil, state.failure(ctx, nil, "registry-read", err)
		}
		b, err := readDescriptor(ctx, state, rc, target)
		if err != nil {
			return nil, err
		}
		blobs = append(blobs, b)
	}
	return Verify(ctx, dig, manifest, blobs[0], blobs[1])
}
func readDescriptor(ctx context.Context, state *readState, body io.ReadCloser, desc ocispec.Descriptor) ([]byte, error) {
	defer body.Close()
	b, err := content.ReadAll(body, desc)
	if err != nil {
		return nil, state.failure(ctx, ErrIntegrity, "descriptor-body", err)
	}
	return b, nil
}

type blobDescriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	URLs        json.RawMessage   `json:"urls,omitempty"`
	Data        json.RawMessage   `json:"data,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}
type manifest struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType"`
	ArtifactType  string            `json:"artifactType"`
	Config        blobDescriptor    `json:"config"`
	Layers        []blobDescriptor  `json:"layers"`
	Subject       json.RawMessage   `json:"subject,omitempty"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}

func parseManifest(b []byte) (manifest, error) {
	var m manifest
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	err := d.Decode(&m)
	if err != nil || d.Decode(new(any)) != io.EOF || m.SchemaVersion != 2 || m.ArtifactType != oci.MediaTypeArtifact || m.Subject != nil || len(m.Layers) != 1 {
		return m, fault(ErrUnsupported, "manifest", "manifest-profile")
	}
	if m.MediaType != "application/vnd.oci.image.manifest.v1+json" {
		return m, fault(ErrUnsupported, "manifest", "manifest-media-type")
	}
	for _, v := range []blobDescriptor{m.Config, m.Layers[0]} {
		if v.URLs != nil {
			return m, fault(ErrUnsupported, "manifest", "descriptor-urls")
		}
		if v.Data != nil {
			return m, fault(ErrUnsupported, "manifest", "descriptor-inline-data")
		}
		if !validDigest(v.Digest) || v.Size < 0 {
			return m, fault(ErrUnsupported, "manifest", "descriptor-profile")
		}
	}
	if m.Config.MediaType != oci.MediaTypeEmptyConfig || m.Config.Size != 2 || m.Layers[0].MediaType != oci.MediaTypeContent || m.Layers[0].Size > maxLayer {
		return m, fault(ErrUnsupported, "manifest", "blob-profile")
	}
	return m, nil
}
func validDigest(s string) bool {
	return strings.HasPrefix(s, "sha256:") && godigest.Digest(s).Validate() == nil
}
func hash(b []byte) string { h := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(h[:]) }
