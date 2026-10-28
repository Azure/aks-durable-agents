package githubtools

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var clientTime = time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)

// One ephemeral test key avoids repeated entropy/key-generation work competing
// with short-deadline tests in other packages. Each client still loads its PEM.
var clientTestPEM = sync.OnceValues(func() ([]byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), nil
})

const fakeInstallationToken = "synthetic_installation_token_with_variable_length_not_a_real_secret"

// Only dialing/TLS trust is injected: the real client applies its own HTTP/1,
// no-reuse, deadline and redirect settings to this base transport.
func clientFixture(t *testing.T, handler func(http.ResponseWriter, *http.Request, *rsa.PrivateKey)) (*Client, ClientConfig) {
	t.Helper()
	raw, err := clientTestPEM()
	if err != nil {
		t.Fatal(err)
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM(raw)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "ephemeral-key.pem")
	if err = os.WriteFile(keyPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "api.github.com" || r.ProtoMajor != 1 {
			t.Errorf("unexpected origin/protocol: %s %s", r.Host, r.Proto)
		}
		handler(w, r, key)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	target, _ := url.Parse(server.URL)
	base := server.Client().Transport.(*http.Transport).Clone()
	base.Proxy = nil
	base.TLSClientConfig = base.TLSClientConfig.Clone()
	base.TLSClientConfig.ServerName = target.Hostname()
	base.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr != "api.github.com:443" {
			return nil, errors.New("unexpected test destination")
		}
		return (&net.Dialer{}).DialContext(ctx, network, target.Host)
	}
	config := ClientConfig{Account: GitHubAccount{AppID: "1", InstallationID: "2", RepositoryID: "3", Owner: "Example", Repository: "Repo"}, PrivateKeyFile: keyPath}
	client, err := newClient(config, base, func() time.Time { return clientTime })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.http.CloseIdleConnections)
	return client, config
}

func tokenReply(permission string) map[string]any {
	return map[string]any{"token": fakeInstallationToken, "expires_at": "2030-01-02T04:04:05Z", "permissions": map[string]string{"issues": permission, "metadata": "read"}, "repository_selection": "selected", "repositories": []map[string]any{{"id": 3, "full_name": "example/repo"}}}
}
func replyJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func checkMint(t *testing.T, r *http.Request, key *rsa.PrivateKey, permission string) {
	t.Helper()
	if r.Method != "POST" || r.URL.Path != "/app/installations/2/access_tokens" {
		t.Errorf("wrong mint request: %s %s", r.Method, r.URL.Path)
	}
	if r.Header.Get("Accept") != "application/vnd.github+json" || r.Header.Get("X-GitHub-Api-Version") != "2026-03-10" {
		t.Error("missing GitHub headers")
	}
	parsed, err := jwt.Parse(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), func(*jwt.Token) (any, error) { return &key.PublicKey, nil }, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer("1"), jwt.WithIssuedAt(), jwt.WithTimeFunc(func() time.Time { return clientTime }))
	if err != nil || !parsed.Valid {
		t.Errorf("invalid app JWT: %v", err)
		return
	}
	claims := parsed.Claims.(jwt.MapClaims)
	if claims["iat"] != float64(clientTime.Unix()-60) || claims["exp"] != float64(clientTime.Unix()+540) {
		t.Error("wrong JWT validity interval")
	}
	var body struct {
		RepositoryIDs []json.Number     `json:"repository_ids"`
		Permissions   map[string]string `json:"permissions"`
	}
	if json.NewDecoder(r.Body).Decode(&body) != nil || len(body.RepositoryIDs) != 1 || body.RepositoryIDs[0] != "3" || len(body.Permissions) != 1 || body.Permissions["issues"] != permission {
		t.Errorf("wrong token narrowing: %+v", body)
	}
}

func TestPreflightNarrowScopeAndRedactedCapability(t *testing.T) {
	for _, permission := range []string{"read", "write"} {
		t.Run(permission, func(t *testing.T) {
			var requests atomic.Int32
			client, config := clientFixture(t, func(w http.ResponseWriter, r *http.Request, key *rsa.PrivateKey) {
				requests.Add(1)
				checkMint(t, r, key, permission)
				replyJSON(w, 201, tokenReply(permission))
			})
			access, err := client.Preflight(t.Context(), permission)
			if err != nil {
				t.Fatal(err)
			}
			if access.Account() != config.Account || !access.ExpiresAt().Equal(clientTime.Add(time.Hour)) {
				t.Fatal("wrong account/expiry binding")
			}
			if requests.Load() != 1 {
				t.Fatalf("mint attempts=%d", requests.Load())
			}
			for _, value := range []any{client, *client, access, *access} {
				formatted := fmt.Sprintf("%v %+v %#v", value, value, value)
				if strings.Contains(formatted, fakeInstallationToken) || strings.Contains(formatted, "PRIVATE KEY") || strings.Contains(formatted, config.PrivateKeyFile) {
					t.Fatal("credential/configuration escaped in formatting")
				}
			}
		})
	}
}

func TestClientPreflightConcurrentScopes(t *testing.T) {
	client, _ := clientFixture(t, func(w http.ResponseWriter, r *http.Request, _ *rsa.PrivateKey) {
		var request struct {
			Permissions map[string]string `json:"permissions"`
		}
		if json.NewDecoder(r.Body).Decode(&request) != nil {
			t.Error("invalid scope request")
			w.WriteHeader(400)
			return
		}
		replyJSON(w, 201, tokenReply(request.Permissions["issues"]))
	})
	var work sync.WaitGroup
	for _, permission := range []string{"read", "write", "read", "write"} {
		work.Go(func() {
			access, err := client.Preflight(t.Context(), permission)
			if err != nil || access.permission != permission {
				t.Errorf("concurrent scope mismatch: %v", err)
			}
		})
	}
	work.Wait()
}

func TestClientTLSFailureDoesNotReachProvider(t *testing.T) {
	var requests atomic.Int32
	client, _ := clientFixture(t, func(w http.ResponseWriter, r *http.Request, _ *rsa.PrivateKey) { requests.Add(1); w.WriteHeader(500) })
	client.http.Transport.(*http.Transport).TLSClientConfig.RootCAs = x509.NewCertPool()
	if _, err := client.Preflight(t.Context(), "read"); !errors.Is(err, ErrGitHubAccess) || requests.Load() != 0 {
		t.Fatalf("untrusted TLS accepted: %v", err)
	}
}

func TestClientRefusesInvalidConfigurationAndKeyWithoutNetwork(t *testing.T) {
	var requests atomic.Int32
	_, valid := clientFixture(t, func(w http.ResponseWriter, r *http.Request, _ *rsa.PrivateKey) { requests.Add(1); w.WriteHeader(500) })
	for _, mutate := range []func(*ClientConfig){func(c *ClientConfig) { c.Account.RepositoryID = "03" }, func(c *ClientConfig) { c.Account.Owner = "../other" }, func(c *ClientConfig) { c.Account.Repository = ".." }, func(c *ClientConfig) { c.Account.Owner = "" }} {
		config := valid
		mutate(&config)
		if _, err := NewClient(config); !errors.Is(err, ErrGitHubInput) {
			t.Fatalf("invalid config accepted: %v", err)
		}
	}
	for _, name := range []string{"missing-private-key", "bad-private-key"} {
		config := valid
		config.PrivateKeyFile = filepath.Join(t.TempDir(), name)
		if name == "bad-private-key" {
			if err := os.WriteFile(config.PrivateKeyFile, []byte("synthetic-sensitive-input"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		_, err := NewClient(config)
		if !errors.Is(err, ErrGitHubAccess) || strings.Contains(err.Error(), name) || strings.Contains(err.Error(), "synthetic-sensitive-input") {
			t.Fatalf("unsafe key error: %v", err)
		}
	}
	if requests.Load() != 0 {
		t.Fatal("constructor sent network request")
	}
}

func TestClientReadAndExactCommentUseFreshHTTP1Connections(t *testing.T) {
	const body = "  exact <>& and Unicode ⚓\r\nsecond line\n"
	const displayURL = "https://github.com/example/repo/issues/7?view=full#comment-9007199254740993"
	var addresses sync.Map
	client, _ := clientFixture(t, func(w http.ResponseWriter, r *http.Request, key *rsa.PrivateKey) {
		addresses.Store(r.RemoteAddr, true)
		if r.URL.Path == "/app/installations/2/access_tokens" {
			checkMint(t, r, key, "write")
			replyJSON(w, 201, tokenReply("write"))
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+fakeInstallationToken || r.URL.RawQuery != "" {
			t.Error("wrong installation credential or destination")
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /repos/Example/Repo/issues/7":
			replyJSON(w, 200, map[string]any{"number": 7, "title": "Issue title", "body": body, "html_url": displayURL})
		case "POST /repos/Example/Repo/issues/7/comments":
			var request struct {
				Body string `json:"body"`
			}
			if json.NewDecoder(r.Body).Decode(&request) != nil || request.Body != body {
				t.Error("comment bytes changed")
			}
			replyJSON(w, 201, map[string]any{"id": json.Number("9007199254740993"), "html_url": displayURL, "token": "unused-provider-field"})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
		}
	})
	access, err := client.Preflight(t.Context(), "write")
	if err != nil {
		t.Fatal(err)
	}
	issue, err := access.GetIssue(t.Context(), 7)
	if err != nil || issue.Number != 7 || issue.Title != "Issue title" || issue.Body != body || issue.URL != displayURL {
		t.Fatalf("issue: %+v %v", issue, err)
	}
	comment, err := access.CommentOnIssue(t.Context(), 7, body)
	if err != nil || comment.ID != "9007199254740993" || comment.URL != displayURL {
		t.Fatalf("comment: %+v %v", comment, err)
	}
	count := 0
	addresses.Range(func(_, _ any) bool { count++; return true })
	if count != 3 {
		t.Fatalf("connections reused: %d distinct connections for three requests", count)
	}
}

func TestClientAccessCannotRefreshOrElevate(t *testing.T) {
	var requests atomic.Int32
	client, _ := clientFixture(t, func(w http.ResponseWriter, r *http.Request, _ *rsa.PrivateKey) {
		requests.Add(1)
		replyJSON(w, 201, tokenReply("read"))
	})
	if _, err := client.Preflight(t.Context(), "admin"); !errors.Is(err, ErrGitHubInput) || requests.Load() != 0 {
		t.Fatalf("invalid permission dispatched: %v", err)
	}
	access, err := client.Preflight(t.Context(), "read")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := access.CommentOnIssue(t.Context(), 7, "comment"); !errors.Is(err, ErrGitHubAccess) {
		t.Fatalf("read token wrote: %v", err)
	}
	if _, err := access.GetIssue(t.Context(), 0); !errors.Is(err, ErrGitHubInput) {
		t.Fatalf("invalid issue dispatched: %v", err)
	}
	access.now = func() time.Time { return access.expiresAt }
	if _, err := access.GetIssue(t.Context(), 7); !errors.Is(err, ErrGitHubAccess) {
		t.Fatalf("expired read: %v", err)
	}
	if _, err := access.CommentOnIssue(t.Context(), 7, "comment"); !errors.Is(err, ErrGitHubAccess) {
		t.Fatalf("expired write: %v", err)
	}
	if requests.Load() != 1 {
		t.Fatalf("capability acquired or used more credentials: %d requests", requests.Load())
	}
}

func TestClientCommentFailureClassificationAndNoRetry(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{"unauthorized", 401, "", ErrGitHubRejected}, {"forbidden", 403, "", ErrGitHubRejected},
		{"missing", 404, "", ErrGitHubRejected}, {"gone", 410, "", ErrGitHubRejected},
		{"invalid", 422, "", ErrGitHubRejected}, {"rate-limited", 429, "", ErrGitHubRejected},
		{"timeout", 408, "", ErrUnknownOutcome}, {"server", 500, "", ErrUnknownOutcome},
		{"unexpected", 200, `{"id":42,"html_url":"display"}`, ErrUnknownOutcome},
		{"malformed", 201, "invalid-sensitive-response", ErrUnknownOutcome},
		{"oversized", 201, strings.Repeat("x", (1<<20)+1), ErrUnknownOutcome},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var posts atomic.Int32
			client, _ := clientFixture(t, func(w http.ResponseWriter, r *http.Request, _ *rsa.PrivateKey) {
				if strings.HasSuffix(r.URL.Path, "/access_tokens") {
					replyJSON(w, 201, tokenReply("write"))
					return
				}
				posts.Add(1)
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body + fakeInstallationToken))
			})
			access, err := client.Preflight(t.Context(), "write")
			if err != nil {
				t.Fatal(err)
			}
			_, err = access.CommentOnIssue(t.Context(), 7, "exact comment")
			if !errors.Is(err, tc.want) || strings.Contains(err.Error(), fakeInstallationToken) || strings.Contains(err.Error(), "sensitive-response") {
				t.Fatalf("write outcome: %v", err)
			}
			if posts.Load() != 1 {
				t.Fatalf("POST retries=%d", posts.Load())
			}
		})
	}
}

func TestClientInvalidCommentRepresentationIsNotSent(t *testing.T) {
	var requests atomic.Int32
	client, _ := clientFixture(t, func(w http.ResponseWriter, r *http.Request, _ *rsa.PrivateKey) {
		requests.Add(1)
		replyJSON(w, 201, tokenReply("write"))
	})
	access, err := client.Preflight(t.Context(), "write")
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{string([]byte{0xff}), strings.Repeat("x", (1<<20)+1), strings.Repeat("<", 180000)} {
		if _, err := access.CommentOnIssue(t.Context(), 7, body); !errors.Is(err, ErrGitHubInput) {
			t.Fatalf("invalid body dispatched: %v", err)
		}
	}
	if requests.Load() != 1 {
		t.Fatalf("invalid body produced network requests: %d", requests.Load())
	}
}

func TestClientLostPOSTResponseIsUnknownWithoutReplay(t *testing.T) {
	var posts, mints atomic.Int32
	client, _ := clientFixture(t, func(w http.ResponseWriter, r *http.Request, _ *rsa.PrivateKey) {
		if strings.HasSuffix(r.URL.Path, "/access_tokens") {
			mints.Add(1)
			replyJSON(w, 201, tokenReply("write"))
			return
		}
		posts.Add(1)
		connection, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		_ = connection.Close()
	})
	access, err := client.Preflight(t.Context(), "write")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = access.CommentOnIssue(t.Context(), 7, "comment"); !errors.Is(err, ErrUnknownOutcome) {
		t.Fatalf("lost response: %v", err)
	}
	if posts.Load() != 1 || mints.Load() != 1 {
		t.Fatalf("automatic replay/refresh: posts=%d mints=%d", posts.Load(), mints.Load())
	}
}

func TestClientRefusesRedirectWithoutFollowing(t *testing.T) {
	for _, operation := range []string{"preflight", "read", "write"} {
		t.Run(operation, func(t *testing.T) {
			var redirected atomic.Int32
			client, _ := clientFixture(t, func(w http.ResponseWriter, r *http.Request, _ *rsa.PrivateKey) {
				if r.URL.Path == "/redirected" {
					redirected.Add(1)
					w.WriteHeader(204)
					return
				}
				if operation != "preflight" && strings.HasSuffix(r.URL.Path, "/access_tokens") {
					replyJSON(w, 201, tokenReply("write"))
					return
				}
				w.Header().Set("Location", "https://api.github.com/redirected")
				w.WriteHeader(303)
			})
			access, err := client.Preflight(t.Context(), "write")
			if operation == "preflight" {
				if !errors.Is(err, ErrGitHubAccess) {
					t.Fatal(err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if operation == "read" {
					_, err = access.GetIssue(t.Context(), 7)
					if !errors.Is(err, ErrGitHubRead) {
						t.Fatal(err)
					}
				} else {
					_, err = access.CommentOnIssue(t.Context(), 7, "comment")
					if !errors.Is(err, ErrUnknownOutcome) {
						t.Fatal(err)
					}
				}
			}
			if redirected.Load() != 0 {
				t.Fatal("followed credential-bearing redirect")
			}
		})
	}
}

func TestClientReadBodyNullAndUnavailable(t *testing.T) {
	for _, kind := range []string{"null-body", "title-controls", "wrong-number", "rejected", "malformed", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			client, _ := clientFixture(t, func(w http.ResponseWriter, r *http.Request, _ *rsa.PrivateKey) {
				if strings.HasSuffix(r.URL.Path, "/access_tokens") {
					replyJSON(w, 201, tokenReply("read"))
					return
				}
				if kind == "malformed" {
					_, _ = w.Write([]byte("malformed-sensitive-response"))
					return
				}
				if kind == "oversized" {
					_, _ = w.Write([]byte(strings.Repeat("x", (1<<20)+1)))
					return
				}
				number, status := 7, 200
				if kind == "wrong-number" {
					number = 8
				}
				if kind == "rejected" {
					status = 404
				}
				title := "Title"
				if kind == "title-controls" {
					title = "Title\twith control"
				}
				replyJSON(w, status, map[string]any{"number": number, "title": title, "body": nil, "html_url": "display", "sensitive": fakeInstallationToken})
			})
			access, err := client.Preflight(t.Context(), "read")
			if err != nil {
				t.Fatal(err)
			}
			issue, err := access.GetIssue(t.Context(), 7)
			if kind == "null-body" || kind == "title-controls" {
				if kind == "title-controls" && issue.Title != "Title\twith control" {
					t.Error("title text changed")
				}
				if err != nil || issue.Body != "" {
					t.Fatalf("null body: %+v %v", issue, err)
				}
			} else if !errors.Is(err, ErrGitHubRead) || strings.Contains(err.Error(), fakeInstallationToken) {
				t.Fatalf("read error: %v", err)
			}
		})
	}
}

func TestClientCancellationDuringResponseBody(t *testing.T) {
	for _, operation := range []string{"read", "write"} {
		t.Run(operation, func(t *testing.T) {
			started := make(chan struct{})
			client, _ := clientFixture(t, func(w http.ResponseWriter, r *http.Request, _ *rsa.PrivateKey) {
				if strings.HasSuffix(r.URL.Path, "/access_tokens") {
					replyJSON(w, 201, tokenReply("write"))
					return
				}
				// Consume the request so HTTP/1 can observe the later disconnect
				// while this handler deliberately leaves its response unfinished.
				_, _ = io.Copy(io.Discard, r.Body)
				status := 200
				if operation == "write" {
					status = 201
				}
				w.WriteHeader(status)
				w.(http.Flusher).Flush()
				close(started)
				<-r.Context().Done()
			})
			access, err := client.Preflight(t.Context(), "write")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				if operation == "read" {
					_, err := access.GetIssue(ctx, 7)
					done <- err
				} else {
					_, err := access.CommentOnIssue(ctx, 7, "comment")
					done <- err
				}
			}()
			<-started
			cancel()
			err = <-done
			want := ErrGitHubRead
			if operation == "write" {
				want = ErrUnknownOutcome
			}
			if !errors.Is(err, want) {
				t.Fatalf("cancelled body: %v", err)
			}
		})
	}
}

func TestPreflightRejectsUnusableTokenResponses(t *testing.T) {
	for _, kind := range []string{"missing-token", "expired", "bad-expiry", "wrong-id", "wrong-name", "extra-repo", "missing-repos", "wrong-permission", "extra-permission", "metadata-write", "all-repositories", "unsafe-token", "malformed", "oversized", "rejected"} {
		t.Run(kind, func(t *testing.T) {
			response := tokenReply("read")
			status := 201
			switch kind {
			case "missing-token":
				delete(response, "token")
			case "expired":
				response["expires_at"] = "2030-01-02T03:04:05Z"
			case "bad-expiry":
				response["expires_at"] = "invalid"
			case "wrong-id":
				response["repositories"] = []map[string]any{{"id": 4, "full_name": "example/repo"}}
			case "wrong-name":
				response["repositories"] = []map[string]any{{"id": 3, "full_name": "other/repo"}}
			case "extra-repo":
				response["repositories"] = []map[string]any{{"id": 3, "full_name": "example/repo"}, {"id": 4, "full_name": "example/other"}}
			case "missing-repos":
				delete(response, "repositories")
			case "wrong-permission":
				response["permissions"] = map[string]string{"issues": "write"}
			case "extra-permission":
				response["permissions"] = map[string]string{"issues": "read", "contents": "read"}
			case "metadata-write":
				response["permissions"] = map[string]string{"issues": "read", "metadata": "write"}
			case "all-repositories":
				response["repository_selection"] = "all"
			case "unsafe-token":
				response["token"] = fakeInstallationToken + "\ninvalid"
			case "rejected":
				status = 401
			}
			var requests atomic.Int32
			client, _ := clientFixture(t, func(w http.ResponseWriter, r *http.Request, _ *rsa.PrivateKey) {
				requests.Add(1)
				if kind == "malformed" {
					w.WriteHeader(201)
					_, _ = w.Write([]byte("synthetic-sensitive-response"))
					return
				}
				if kind == "oversized" {
					w.WriteHeader(201)
					_, _ = w.Write([]byte(strings.Repeat("x", (1<<20)+1)))
					return
				}
				replyJSON(w, status, response)
			})
			access, err := client.Preflight(t.Context(), "read")
			if access != nil || !errors.Is(err, ErrGitHubAccess) || strings.Contains(err.Error(), fakeInstallationToken) || strings.Contains(err.Error(), "synthetic-sensitive-response") {
				t.Fatalf("unusable preflight: %v", err)
			}
			if requests.Load() != 1 {
				t.Fatalf("attempts=%d", requests.Load())
			}
		})
	}
}
