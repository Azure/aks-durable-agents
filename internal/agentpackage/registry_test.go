package agentpackage

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"oras.land/oras-go/v2/registry/remote/auth"
)

func TestPullAnonymousBearerChallenge(t *testing.T) {
	f := makeFixture(t)
	var tokens atomic.Int64
	var s *httptest.Server
	s, _ = serveFixture(t, f, func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/token" {
			tokens.Add(1)
			if r.Header.Get("Authorization") != "" || r.URL.Query().Get("scope") != "repository:test/suite:pull" {
				t.Error("anonymous token request carried credentials or wrong scope")
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"token":"anonymous-pull-token"}`)
			return true
		}
		if r.Header.Get("Authorization") != "Bearer anonymous-pull-token" {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s/token",service="registry",scope="repository:test/suite:pull"`, s.URL))
			w.WriteHeader(http.StatusUnauthorized)
			return true
		}
		return false
	})
	repo := strings.TrimPrefix(s.URL, "https://") + "/test/suite"
	p, err := New(Policy{Repositories: []string{repo}}, s.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := p.Pull(t.Context(), repo+"@"+digest(f.manifest))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pkg.ReadFile("instructions/writer.md")
	if string(b) != "Write fictional release notes.\n" || tokens.Load() == 0 {
		t.Fatal("challenged pull did not return verified content")
	}
	// A shared cold auth client must keep per-request response diagnostics isolated.
	cold, err := New(Policy{Repositories: []string{repo}}, s.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 4)
	for range 4 {
		go func() { _, err := cold.Pull(t.Context(), repo+"@"+digest(f.manifest)); results <- err }()
	}
	for range 4 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
}

func TestPullScopedCredentials(t *testing.T) {
	for _, mode := range []string{"anonymous", "other-repository", "controller"} {
		t.Run(mode, func(t *testing.T) {
			f := makeFixture(t)
			var tokens, redirects atomic.Int64
			blobs := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				redirects.Add(1)
				if r.Header.Get("Authorization") != "" {
					t.Error("redirect hop leaked authorization")
				}
				if !strings.HasPrefix(r.URL.Path, "/final/") {
					http.Redirect(w, r, "/final"+r.URL.Path, http.StatusTemporaryRedirect)
					return
				}
				if strings.HasSuffix(r.URL.Path, digest(f.config)) {
					w.Write(f.config)
				} else {
					w.Write(f.layer)
				}
			}))
			defer blobs.Close()
			var s *httptest.Server
			s, _ = serveFixture(t, f, func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path == "/token" {
					tokens.Add(1)
					user, pass, present := r.BasicAuth()
					if mode == "controller" {
						if !present || user != "controller" || pass != "fixture-only-password" {
							t.Error("explicit controller credential not used")
						}
					} else if present || r.Header.Get("Authorization") != "" {
						t.Error("anonymous pull used another credential")
					}
					if r.URL.Query().Get("scope") != "repository:test/suite:pull" {
						t.Error("token scope is not repository pull")
					}
					w.Header().Set("Content-Type", "application/json")
					fmt.Fprint(w, `{"token":"scoped-pull-token"}`)
					return true
				}
				if r.Header.Get("Authorization") != "Bearer scoped-pull-token" {
					w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s/token",service="registry",scope="repository:test/suite:pull"`, s.URL))
					w.WriteHeader(http.StatusUnauthorized)
					return true
				}
				if strings.Contains(r.URL.Path, "/blobs/") {
					http.Redirect(w, r, blobs.URL+r.URL.Path, http.StatusTemporaryRedirect)
					return true
				}
				return false
			})
			repo := strings.TrimPrefix(s.URL, "https://") + "/test/suite"
			other := strings.TrimPrefix(s.URL, "https://") + "/test/other"
			dockerConfig := t.TempDir()
			t.Setenv("DOCKER_CONFIG", dockerConfig)
			ambient := map[string]any{"auths": map[string]any{strings.TrimPrefix(s.URL, "https://"): map[string]string{"auth": base64.StdEncoding.EncodeToString([]byte("ambient:fixture-only-password"))}}}
			if err := os.WriteFile(filepath.Join(dockerConfig, "config.json"), jsonBytes(ambient), 0600); err != nil {
				t.Fatal(err)
			}
			credentials := map[string]auth.Credential{}
			if mode != "anonymous" {
				key := repo
				if mode == "other-repository" {
					key = other
				}
				credentials[key] = auth.Credential{Username: "controller", Password: "fixture-only-password"}
			}
			transport := s.Client().Transport.(*http.Transport).Clone()
			transport.TLSClientConfig.RootCAs.AddCert(blobs.Certificate())
			p, err := New(Policy{Repositories: []string{repo, other}, Credentials: credentials}, transport)
			if err != nil {
				t.Fatal(err)
			}
			// Caller changes cannot retarget a configured credential after construction.
			credentials[repo] = auth.Credential{Username: "wrong", Password: "wrong"}
			pkg, err := p.Pull(t.Context(), repo+"@"+digest(f.manifest))
			if err != nil {
				t.Fatal(err)
			}
			if pkg.Digest() != digest(f.manifest) || tokens.Load() == 0 || redirects.Load() != 4 {
				t.Fatal("authenticated redirected pull did not return verified content")
			}
		})
	}
}

func TestRegistryCredentialConfigurationIsExplicit(t *testing.T) {
	for _, policy := range []Policy{
		{Repositories: []string{"registry.example/suite"}, Credentials: map[string]auth.Credential{"other.example/suite": {Username: "controller", Password: "fixture"}}},
		{Repositories: []string{"registry.example/suite"}, HTTPRegistry: "registry.example", Credentials: map[string]auth.Credential{"registry.example/suite": {AccessToken: "fixture"}}},
		{Repositories: []string{"registry.example/suite"}, Credentials: map[string]auth.Credential{"registry.example/suite": {RefreshToken: "fixture"}}},
	} {
		if _, err := New(policy, nil); err == nil {
			t.Fatal("accepted credentials outside the supported explicit TLS scope")
		}
	}
}

func TestPullBlobRedirect(t *testing.T) {
	f := makeFixture(t)
	var redirected atomic.Int64
	blobs := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected.Add(1)
		if r.Header.Get("Authorization") != "" {
			t.Error("redirect forwarded registry authorization")
		}
		switch r.URL.Path {
		case "/config":
			w.Write(f.config)
		case "/layer":
			w.Write(f.layer)
		default:
			http.NotFound(w, r)
		}
	}))
	defer blobs.Close()
	s, _ := serveFixture(t, f, func(w http.ResponseWriter, r *http.Request) bool {
		if strings.Contains(r.URL.Path, "/blobs/") {
			dest := "/layer"
			if strings.HasSuffix(r.URL.Path, digest(f.config)) {
				dest = "/config"
			}
			http.Redirect(w, r, blobs.URL+dest, http.StatusTemporaryRedirect)
			return true
		}
		return false
	})
	repo := strings.TrimPrefix(s.URL, "https://") + "/test/suite"
	transport := s.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.RootCAs.AddCert(blobs.Certificate())
	p, err := New(Policy{Repositories: []string{repo}}, transport)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := p.Pull(t.Context(), repo+"@"+digest(f.manifest))
	if err != nil {
		t.Fatal(err)
	}
	if pkg.Digest() != digest(f.manifest) || redirected.Load() != 2 {
		t.Fatal("redirected blobs were not verified")
	}
}
