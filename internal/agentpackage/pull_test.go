package agentpackage

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// These fixtures are built by hand, not by kmx or the production verifier.
func digest(b []byte) string { h := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(h[:]) }
func jsonBytes(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
func descriptor(media string, b []byte) map[string]any {
	return map[string]any{"mediaType": media, "size": len(b), "digest": digest(b)}
}

const artifactType = "application/vnd.agentsuite.suite.v1"
const contentType = "application/vnd.agentsuite.content.v1.tar+gzip"
const configType = "application/vnd.oci.empty.v1+json"
const manifestType = "application/vnd.oci.image.manifest.v1+json"

type fixture struct {
	manifest, config, layer []byte
	files                   map[string][]byte
}

func makeFixture(t *testing.T) fixture {
	t.Helper()
	files := map[string][]byte{"instructions/writer.md": []byte("Write fictional release notes.\n")}
	agent := map[string]any{"schemaVersion": "1.0.0-draft", "mediaType": "application/vnd.agentsuite.agent.v1+json", "id": "writer", "instructions": map[string]any{"path": "instructions/writer.md", "descriptor": descriptor("text/markdown; charset=utf-8", files["instructions/writer.md"])}, "model": map[string]any{"protocol": "openai-compatible", "model": "example-model"}}
	files["agents/writer.json"] = jsonBytes(agent)
	files["tool-providers/catalog.json"] = jsonBytes(map[string]any{"schemaVersion": "1.0.0-draft", "mediaType": "application/vnd.agentsuite.tool.provider.catalog.v1+json", "toolProviders": []any{}})
	platform := map[string]any{"os": "linux", "architecture": "amd64"}
	image := map[string]any{"platform": platform, "imageRef": "registry.example/harness@sha256:" + strings.Repeat("a", 64), "image": map[string]any{"mediaType": manifestType, "digest": "sha256:" + strings.Repeat("a", 64), "size": 1}}
	files["build-profiles/default.json"] = jsonBytes(map[string]any{"schemaVersion": "1.0.0-draft", "mediaType": "application/vnd.agentsuite.build.profile.v1+json", "id": "default", "sourceEpoch": 1, "runtimeBase": []any{image}, "harness": []any{image}})
	files["compositions/writer.json"] = jsonBytes(map[string]any{"schemaVersion": "1.0.0-draft", "mediaType": "application/vnd.agentsuite.composition.v1+json", "agent": "writer", "platform": platform, "buildProfile": "default", "toolProviders": []any{}})
	ref := func(id, path, media string) map[string]any {
		return map[string]any{"id": id, "path": path, "descriptor": descriptor(media, files[path])}
	}
	files["agentsuite.json"] = jsonBytes(map[string]any{"schemaVersion": "1.0.0-draft", "mediaType": "application/vnd.agentsuite.manifest.v1+json", "name": "handmade", "agents": []any{ref("writer", "agents/writer.json", "application/vnd.agentsuite.agent.v1+json")}, "toolProviderCatalog": ref("catalog", "tool-providers/catalog.json", "application/vnd.agentsuite.tool.provider.catalog.v1+json"), "buildProfiles": []any{ref("default", "build-profiles/default.json", "application/vnd.agentsuite.build.profile.v1+json")}, "compositions": []any{map[string]any{"agent": "writer", "platform": platform, "path": "compositions/writer.json", "descriptor": descriptor("application/vnd.agentsuite.composition.v1+json", files["compositions/writer.json"])}}})
	f := fixture{config: []byte("{}"), files: files}
	f.layer = archive(t, files, nil)
	f.remanifest()
	return f
}
func archive(t *testing.T, files map[string][]byte, extra *tar.Header) []byte {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	for name, data := range files {
		h := &tar.Header{Name: name, Mode: 0644, Size: int64(len(data)), ModTime: time.Unix(0, 0), Format: tar.FormatUSTAR}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if extra != nil {
		if err := tw.WriteHeader(extra); err != nil {
			t.Fatal(err)
		}
		if extra.Size > 0 {
			if _, err := io.CopyN(tw, strings.NewReader(strings.Repeat("x", int(extra.Size))), extra.Size); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
func (f *fixture) remanifest() {
	f.manifest = jsonBytes(map[string]any{"schemaVersion": 2, "mediaType": manifestType, "artifactType": artifactType, "config": descriptor(configType, f.config), "layers": []any{descriptor(contentType, f.layer)}})
}
func serveFixture(t *testing.T, f fixture, change func(http.ResponseWriter, *http.Request) bool) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	calls := new(atomic.Int64)
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if strings.Contains(r.URL.Path, "/manifests/") {
			w.Header().Set("Content-Type", manifestType)
		}
		if change != nil && change(w, r) {
			return
		}
		switch r.URL.Path {
		case "/v2/test/suite/manifests/" + digest(f.manifest):
			w.Write(f.manifest)
		case "/v2/test/suite/blobs/" + digest(f.config):
			w.Write(f.config)
		case "/v2/test/suite/blobs/" + digest(f.layer):
			w.Write(f.layer)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.Close)
	return s, calls
}
func pullFixture(t *testing.T, f fixture, change func(http.ResponseWriter, *http.Request) bool) (*Package, error) {
	t.Helper()
	s, _ := serveFixture(t, f, change)
	repo := strings.TrimPrefix(s.URL, "https://") + "/test/suite"
	p, err := New(Policy{Repositories: []string{repo}}, s.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	return p.Pull(t.Context(), repo+"@"+digest(f.manifest))
}
func TestPullVerifiedBytesAreImmutable(t *testing.T) {
	f := makeFixture(t)
	p, err := pullFixture(t, f, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.Digest() != digest(f.manifest) {
		t.Fatal("wrong package identity")
	}
	b, err := p.ReadFile("instructions/writer.md")
	if err != nil || string(b) != "Write fictional release notes.\n" {
		t.Fatalf("wrong verified instructions: %q, %v", b, err)
	}
	b[0] = 'X'
	again, _ := p.ReadFile("instructions/writer.md")
	if string(again) != "Write fictional release notes.\n" {
		t.Fatal("caller mutated verified content")
	}
	if _, err := p.ReadFile("../instructions/writer.md"); err == nil {
		t.Fatal("accepted noncanonical path")
	}
	m, c, l := p.OCIBytes()
	m[0] = 'X'
	c[0] = 'X'
	l[0] = 'X'
	m2, c2, l2 := p.OCIBytes()
	if !bytes.Equal(m2, f.manifest) || !bytes.Equal(c2, f.config) || !bytes.Equal(l2, f.layer) {
		t.Fatal("caller mutated retained OCI bytes")
	}
}
func TestPullRejectsReferencesBeforeRequest(t *testing.T) {
	f := makeFixture(t)
	s, calls := serveFixture(t, f, nil)
	repo := strings.TrimPrefix(s.URL, "https://") + "/test/suite"
	p, err := New(Policy{Repositories: []string{repo}}, s.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{repo + ":latest", repo + "@sha256:abc", repo + "@SHA256:" + strings.Repeat("a", 64), repo + "@sha256:" + strings.Repeat("A", 64), repo + ":tag@" + digest(f.manifest), "other.example/test/suite@" + digest(f.manifest), "https://" + repo + "@" + digest(f.manifest), "user:password@" + repo + "@" + digest(f.manifest), repo + "/../suite@" + digest(f.manifest)} {
		t.Run(ref, func(t *testing.T) {
			if _, err := p.Pull(t.Context(), ref); err == nil {
				t.Fatal("accepted unsupported reference")
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatal("refused input made network requests")
	}
}
func TestPullRedactsRegistryErrors(t *testing.T) {
	for _, code := range []int{http.StatusUnauthorized, http.StatusInternalServerError} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			f := makeFixture(t)
			p, err := pullFixture(t, f, func(w http.ResponseWriter, r *http.Request) bool {
				w.WriteHeader(code)
				io.WriteString(w, "private-provider-payload")
				return true
			})
			if err == nil || p != nil {
				t.Fatal("accepted failed registry read")
			}
			if strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "attacker") {
				t.Fatalf("leaked external response: %v", err)
			}
		})
	}
}
func TestPullCancellation(t *testing.T) {
	f := makeFixture(t)
	s, calls := serveFixture(t, f, nil)
	repo := strings.TrimPrefix(s.URL, "https://") + "/test/suite"
	p, _ := New(Policy{Repositories: []string{repo}}, s.Client().Transport)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := p.Pull(ctx, repo+"@"+digest(f.manifest)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation must remain detectable without leaking request details: %v", err)
	}
	if calls.Load() != 0 {
		t.Fatal("request after cancellation")
	}
}
