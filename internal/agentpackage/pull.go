// Package agentpackage pulls self-contained AgentSuite artifacts without executing them.
// Verification establishes byte/graph integrity, not publisher trust or runner eligibility.
package agentpackage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/agent-primitives/suite/oci"
	"github.com/distribution/reference"
)

const (
	maxManifest = 1 << 20
	maxLayer    = 8 << 20
	maxExpanded = 16 << 20
	maxFile     = 1 << 20
	maxEntries  = 128
)

// Policy is operator configuration, never a package-supplied registry exception.
// Repositories are exact host[:port]/path names. HTTPRegistry, if set, permits
// plaintext only to that exact development registry authority; all others use TLS.
type Policy struct {
	Repositories []string
	HTTPRegistry string
}

// Puller performs anonymous, bounded reads. It never follows redirects or
// registry authentication challenges, uses ambient credentials, or retries writes.
type Puller struct {
	policy Policy
	client *http.Client
}

// New accepts a trusted transport for host TLS policy or local tests. Nil uses
// the standard transport without ambient proxies or HTTP decompression.
func New(policy Policy, transport http.RoundTripper) (*Puller, error) {
	if len(policy.Repositories) == 0 {
		return nil, errors.New("registry repositories required")
	}
	foundHTTP := policy.HTTPRegistry == ""
	for _, repo := range policy.Repositories {
		named, err := reference.ParseNamed(repo)
		u, urlErr := url.Parse("https://" + repo)
		if err != nil || named.Name() != repo || urlErr != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || u.Host != strings.ToLower(u.Host) || !strings.Contains(repo, "/") {
			return nil, errors.New("invalid registry repository")
		}
		if _, ok := named.(reference.Tagged); ok {
			return nil, errors.New("repository must not contain a tag")
		}
		if _, ok := named.(reference.Digested); ok {
			return nil, errors.New("repository must not contain a digest")
		}
		if u.Host == policy.HTTPRegistry {
			foundHTTP = true
		}
	}
	if !foundHTTP {
		return nil, errors.New("HTTP registry must match an allowed repository authority")
	}
	policy.Repositories = append([]string(nil), policy.Repositories...)
	if transport == nil {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.Proxy = nil
		t.DisableCompression = true
		transport = t
	}
	return &Puller{policy: policy, client: &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

// Pull accepts only an allowlisted explicit repository@sha256 digest. The
// returned package owns its bytes; temporary validation trees never escape.
func (p *Puller) Pull(ctx context.Context, ref string) (*Package, error) {
	repo, dig, ok := strings.Cut(ref, "@")
	if !ok || !validDigest(dig) {
		return nil, errors.New("package requires a lowercase sha256 digest reference")
	}
	allowed := false
	for _, r := range p.policy.Repositories {
		if repo == r {
			allowed = true
		}
	}
	if !allowed {
		return nil, errors.New("package repository not allowed")
	}
	authority, name, _ := strings.Cut(repo, "/")
	scheme := "https"
	if authority == p.policy.HTTPRegistry {
		scheme = "http"
	}
	base := scheme + "://" + authority + "/v2/" + name
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	manifest, err := p.fetch(ctx, base+"/manifests/"+dig, maxManifest)
	if err != nil {
		return nil, err
	}
	if hash(manifest) != dig {
		return nil, errors.New("manifest digest mismatch")
	}
	m, err := parseManifest(manifest)
	if err != nil {
		return nil, err
	}
	config, err := p.fetch(ctx, base+"/blobs/"+m.Config.Digest, 2)
	if err != nil {
		return nil, err
	}
	layer, err := p.fetch(ctx, base+"/blobs/"+m.Layers[0].Digest, m.Layers[0].Size)
	if err != nil {
		return nil, err
	}
	return Verify(ctx, manifest, config, layer)
}
func (p *Puller) fetch(ctx context.Context, address string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, errors.New("registry request invalid")
	}
	req.Header.Set("Accept", "application/vnd.oci.image.manifest.v1+json, application/octet-stream")
	resp, err := p.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("registry read failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("registry refused read")
	}
	if resp.ContentLength > limit {
		return nil, errors.New("registry response exceeds limit")
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil || int64(len(b)) > limit {
		return nil, errors.New("registry response incomplete or oversized")
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
	if err != nil || d.Decode(new(any)) != io.EOF || m.SchemaVersion != 2 || m.MediaType != "application/vnd.oci.image.manifest.v1+json" || m.ArtifactType != oci.MediaTypeArtifact || m.Subject != nil || len(m.Layers) != 1 {
		return m, errors.New("unsupported package manifest")
	}
	for _, v := range []blobDescriptor{m.Config, m.Layers[0]} {
		if !validDigest(v.Digest) || v.Size < 0 || v.URLs != nil || v.Data != nil {
			return m, errors.New("invalid package descriptor")
		}
	}
	if m.Config.MediaType != oci.MediaTypeEmptyConfig || m.Config.Size != 2 || m.Layers[0].MediaType != oci.MediaTypeContent || m.Layers[0].Size > maxLayer {
		return m, errors.New("unsupported package blobs")
	}
	return m, nil
}
func validDigest(s string) bool {
	if len(s) != 71 || !strings.HasPrefix(s, "sha256:") {
		return false
	}
	for _, c := range s[7:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func hash(b []byte) string { h := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(h[:]) }
