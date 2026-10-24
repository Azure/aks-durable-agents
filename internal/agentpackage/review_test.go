package agentpackage

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agent-primitives/suite/core"
	"github.com/agent-primitives/suite/oci"
)

func hasFailure(err, kind error, rule string) bool {
	var detail *Error
	return errors.Is(err, kind) && errors.As(err, &detail) && detail.Rule == rule
}

func TestRegistryErrorsCarryClassStatusAndRole(t *testing.T) {
	for _, role := range []string{"manifest", "config", "layer"} {
		for _, status := range []int{401, 403, 404, 429, 500} {
			t.Run(role+http.StatusText(status), func(t *testing.T) {
				f := makeFixture(t)
				_, err := pullFixture(t, f, func(w http.ResponseWriter, r *http.Request) bool {
					match := role == "manifest" && strings.Contains(r.URL.Path, "/manifests/") || role == "config" && strings.HasSuffix(r.URL.Path, digest(f.config)) || role == "layer" && strings.HasSuffix(r.URL.Path, digest(f.layer))
					if !match {
						return false
					}
					w.WriteHeader(status)
					w.Write([]byte("private registry payload"))
					return true
				})
				var detail *Error
				if !errors.Is(err, ErrUnavailable) || !errors.As(err, &detail) || detail.Role != role || detail.StatusCode != status {
					t.Fatalf("wrong registry failure classification: %#v, %v", detail, err)
				}
				if strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "https://") {
					t.Fatal("registry details leaked")
				}
			})
		}
	}
}
func TestSuccessfulResponseWithWrongDescriptorIsIntegrity(t *testing.T) {
	f := makeFixture(t)
	_, err := pullFixture(t, f, func(w http.ResponseWriter, r *http.Request) bool {
		if strings.HasSuffix(r.URL.Path, digest(f.layer)) {
			w.Header().Set("Content-Length", "1")
			w.Write([]byte("x"))
			return true
		}
		return false
	})
	var detail *Error
	if !errors.Is(err, ErrIntegrity) || !errors.As(err, &detail) || detail.Role != "layer" || detail.StatusCode != 200 {
		t.Fatalf("lost descriptor failure metadata: %#v %v", detail, err)
	}
}
func TestVerifyAnchorsExpectedManifestBeforeExtraction(t *testing.T) {
	f := makeFixture(t)
	if _, err := Verify(t.Context(), "sha256:"+strings.Repeat("0", 64), f.manifest, f.config, f.layer); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("unanchored manifest accepted: %v", err)
	}
	if _, err := Verify(t.Context(), "sha256:invalid", f.manifest, f.config, f.layer); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("invalid expected identity: %v", err)
	}
	p, err := Verify(t.Context(), digest(f.manifest), f.manifest, f.config, f.layer)
	if err != nil {
		t.Fatal(err)
	}
	report := p.Report()
	if report == nil || report.Name != "handmade" || report.Agents != 1 || report.AgentPlatforms[0].ID != "writer" || report.AgentPlatforms[0].Platforms[0].OS != "linux" {
		t.Fatalf("lost Suite report: %#v", report)
	}
	report.Name = "changed"
	report.AgentPlatforms[0].Platforms[0].OS = "changed"
	if again := p.Report(); again.Name != "handmade" || again.AgentPlatforms[0].Platforms[0].OS != "linux" {
		t.Fatal("caller changed verified report")
	}
}
func TestReportCopiesEveryCollection(t *testing.T) {
	p := &Package{report: &core.Report{Capabilities: []string{"fixture"}, AgentPlatforms: []core.AgentPlatform{{ID: "writer", Platforms: []core.Platform{{OS: "linux"}}}}, CompositionSelections: []core.CompositionSelection{{Agent: "writer"}}}}
	r := p.Report()
	r.Capabilities[0] = "changed"
	r.AgentPlatforms[0].ID = "changed"
	r.AgentPlatforms[0].Platforms[0].OS = "changed"
	r.CompositionSelections[0].Agent = "changed"
	again := p.Report()
	if again.Capabilities[0] != "fixture" || again.AgentPlatforms[0].ID != "writer" || again.AgentPlatforms[0].Platforms[0].OS != "linux" || again.CompositionSelections[0].Agent != "writer" {
		t.Fatal("report aliases retained collections")
	}
	if new(Package).Report() != nil {
		t.Fatal("zero Package has no verified report")
	}
}

// Prove these are deliberate host-profile refusals, not invalid Suite fixtures.
func TestHostProfileIsExplicitlyNarrowerThanSuite(t *testing.T) {
	for _, rule := range []string{"manifest-media-type", "descriptor-inline-data", "entry-type", "tar-format"} {
		t.Run(rule, func(t *testing.T) {
			f := makeFixture(t)
			switch rule {
			case "manifest-media-type", "descriptor-inline-data":
				var m map[string]any
				json.Unmarshal(f.manifest, &m)
				if rule == "manifest-media-type" {
					delete(m, "mediaType")
				} else {
					m["config"].(map[string]any)["data"] = f.config
				}
				f.manifest = jsonBytes(m)
			case "entry-type":
				f.layer = archive(t, f.files, &tar.Header{Name: "alias", Linkname: "instructions/writer.md", Mode: 0644, ModTime: time.Unix(0, 0), Typeflag: tar.TypeSymlink, Format: tar.FormatUSTAR})
				f.remanifest()
			case "tar-format":
				f.layer = archive(t, f.files, &tar.Header{Name: strings.Repeat("n", 120), Mode: 0644, ModTime: time.Unix(0, 0), Typeflag: tar.TypeReg, Format: tar.FormatPAX})
				f.remanifest()
			}
			layout := t.TempDir()
			if err := os.MkdirAll(filepath.Join(layout, "blobs", "sha256"), 0700); err != nil {
				t.Fatal(err)
			}
			index := map[string]any{"schemaVersion": 2, "manifests": []any{descriptor(manifestType, f.manifest)}}
			files := map[string][]byte{"oci-layout": []byte(`{"imageLayoutVersion":"1.0.0"}`), "index.json": jsonBytes(index)}
			for _, b := range [][]byte{f.manifest, f.config, f.layer} {
				files["blobs/sha256/"+strings.TrimPrefix(digest(b), "sha256:")] = b
			}
			for name, b := range files {
				if err := os.WriteFile(filepath.Join(layout, name), b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := oci.ValidatePath(layout); err != nil {
				t.Fatalf("fixture must pass Suite: %v", err)
			}
			if _, err := Verify(t.Context(), digest(f.manifest), f.manifest, f.config, f.layer); !hasFailure(err, ErrUnsupported, rule) {
				t.Fatalf("wrong documented profile rule: %v", err)
			}
		})
	}
}

func TestPullExplicitProxyTransport(t *testing.T) {
	f := makeFixture(t)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !r.URL.IsAbs() || r.URL.Host != "registry.example" {
			t.Error("request did not use explicit proxy")
		}
		for _, blob := range []struct {
			media string
			data  []byte
		}{{manifestType, f.manifest}, {configType, f.config}, {contentType, f.layer}} {
			if strings.HasSuffix(r.URL.Path, digest(blob.data)) {
				w.Header().Set("Content-Type", blob.media)
				w.Write(blob.data)
				return
			}
		}
		http.NotFound(w, r)
	}))
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer transport.CloseIdleConnections()
	p, err := New(Policy{Repositories: []string{"registry.example/test/suite"}, HTTPRegistry: "registry.example"}, transport)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Pull(t.Context(), "registry.example/test/suite@"+digest(f.manifest)); err != nil {
		t.Fatal(err)
	}
}

func TestTypedCancellationIsStillDetectable(t *testing.T) {
	f := makeFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	p, err := Verify(ctx, digest(f.manifest), f.manifest, f.config, f.layer)
	if p != nil || !errors.Is(err, ErrUnavailable) || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost class or cause: %v", err)
	}
}
