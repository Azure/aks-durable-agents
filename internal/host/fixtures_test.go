package host

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
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

	"github.com/Azure/aks-durable-agents/entraauth"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/agent-primitives/sessions/api"
	v1 "github.com/agent-primitives/sessions/api/genpb"
	"github.com/agent-primitives/sessions/authn"
	"github.com/agent-primitives/sessions/client"
	"github.com/agent-primitives/sessions/harnesswire"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

const fixtureScope = "https://ai.azure.com/.default"
const fixtureModelToken = "workload-identity-model-only"
const fixtureIssuer = "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0"

type fixtureCredential struct{ t *testing.T }

func (c fixtureCredential) GetToken(_ context.Context, o policy.TokenRequestOptions) (azcore.AccessToken, error) {
	if len(o.Scopes) != 1 || o.Scopes[0] != fixtureScope {
		c.t.Errorf("wrong model audience: %v", o.Scopes)
	}
	return azcore.AccessToken{Token: fixtureModelToken, ExpiresOn: time.Now().Add(time.Hour)}, nil
}

type releaseFixture struct{ runs atomic.Int32 }

func (*releaseFixture) Describe(context.Context) (api.Descriptor, error) {
	return api.Descriptor{ID: "release-notes", Version: "session-fixture-v1", Models: []string{"fixture-model"}, Tools: []api.ToolSpec{{Name: "publish_release_notes", Mediation: api.MediationRequiresApproval}}, Capabilities: api.Capabilities{Resumability: api.ResumabilityStatelessReplay, ForkSafe: true, ReasoningReplay: true}}, nil
}

// The fixture's model draft is followed by a deterministic approval-gated publication.
// Only model completions, not publication receipts, enter conversation history.
func (h *releaseFixture) Run(ctx context.Context, s *api.Start, sink api.EventSink) error {
	h.runs.Add(1)
	messages := []api.Message{*api.TextMessage("system", "Draft release notes.")}
	pending := false
	for _, e := range s.History {
		switch e.Kind {
		case api.EventInput:
			messages = append(messages, *e.Message)
		case api.EventModelCall:
			pending = true
		case api.EventOutput:
			if pending {
				messages = append(messages, *e.Message)
				pending = false
			}
		}
	}
	messages = append(messages, s.Inputs...)
	response, err := sink.Model(ctx, api.ModelRequest{Model: "fixture-model", Messages: messages})
	if err != nil {
		return err
	}
	key := s.ExecutionID + "/publish_release_notes"
	result, err := sink.ToolCall(ctx, api.ToolCall{ID: key, Tool: "publish_release_notes", Args: map[string]any{"draft": response.Message.Text(), "destination": "release-notes-demo"}, Mediation: api.MediationRequiresApproval, IdempotencyKey: key})
	if err != nil {
		return err
	}
	if result.IsError {
		if result.Code == api.ToolResultCodeApprovalDenied {
			return sink.Output(ctx, "Publication denied; nothing published.")
		}
		return errors.New("publication failed")
	}
	return sink.Output(ctx, "Published locally: release-notes-demo.")
}

type hostFixture struct {
	config          Config
	harness         *releaseFixture
	models, sockets atomic.Int32
	effects         *sql.DB
	mu              sync.Mutex
	boundary        []byte
}

func (f *hostFixture) capture(v any) {
	b, _ := json.Marshal(v)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.boundary = append(f.boundary, b...)
}

func newHostFixture(t *testing.T) *hostFixture {
	t.Helper()
	f := &hostFixture{harness: &releaseFixture{}}
	dir := t.TempDir()
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.models.Add(1)
		body, _ := io.ReadAll(r.Body)
		f.capture(string(body))
		var req struct {
			Model  string
			Stream bool
		}
		if json.Unmarshal(body, &req) != nil || req.Model != "test-deployment" || !req.Stream || r.URL.Path != "/openai/v1/chat/completions" || r.Method != "POST" {
			t.Error("host did not pin deployment and route through streaming adapter")
		}
		if r.Header.Get("Authorization") != "Bearer "+fixtureModelToken || r.Header.Get("api-key") != "" {
			t.Error("model request did not use workload identity exclusively")
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"Fixed release draft.\"}}]}\n\ndata: [DONE]\n\n")
	}))
	t.Cleanup(provider.Close)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	check := func(ctx context.Context) {
		md, _ := metadata.FromIncomingContext(ctx)
		f.capture(md)
		if len(md.Get("authorization")) != 0 {
			t.Error("caller credential forwarded to harness")
		}
	}
	server := grpc.NewServer(grpc.UnaryInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
		check(ctx)
		return next(ctx, req)
	}), grpc.StreamInterceptor(func(srv any, stream grpc.ServerStream, _ *grpc.StreamServerInfo, next grpc.StreamHandler) error {
		check(stream.Context())
		return next(srv, stream)
	}))
	v1.RegisterHarnessServer(server, harnesswire.NewServer(f.harness))
	go server.Serve(ln)
	t.Cleanup(server.Stop)
	// A short socket path is needed even when Go's test temp directory is long.
	sockdir, err := os.MkdirTemp("", "host-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockdir) })
	socket, err := net.Listen("unix", filepath.Join(sockdir, "publish.sock"))
	if err != nil {
		t.Fatal(err)
	}
	f.effects, err = sql.Open("sqlite", filepath.Join(dir, "executor.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.effects.Exec(`CREATE TABLE effects(uid TEXT, key TEXT, draft TEXT, PRIMARY KEY(uid,key))`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.effects.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := socket.Accept()
			if err != nil {
				return
			}
			func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				var req struct {
					Version int            `json:"version"`
					CallID  string         `json:"call_id"`
					UID     string         `json:"session_uid"`
					Key     string         `json:"idempotency_key"`
					Tool    string         `json:"tool"`
					Args    map[string]any `json:"arguments"`
				}
				if err := json.NewDecoder(conn).Decode(&req); err != nil {
					t.Error(err)
					return
				}
				f.sockets.Add(1)
				f.capture(req)
				if req.Version != 1 || req.UID == "" || req.Key == "" || req.CallID != req.Key || req.Tool != "publish_release_notes" || req.Args["draft"] != "Fixed release draft." {
					t.Error("invalid fixture publication identity or draft")
				}
				if _, err := f.effects.Exec(`INSERT OR IGNORE INTO effects VALUES(?,?,?)`, req.UID, req.Key, req.Args["draft"]); err != nil {
					t.Error(err)
					return
				}
				_ = json.NewEncoder(conn).Encode(map[string]any{"version": 1, "call_id": req.CallID, "is_error": false, "output": map[string]any{"text": "published"}})
			}()
		}
	}()
	t.Cleanup(func() { _ = socket.Close(); <-done })
	tools := fmt.Sprintf(`{"version":1,"executors":[{"name":"publish","type":"unix","socket":%q}],"tools":[{"harness":"release-notes","tool":"publish_release_notes","executor":"publish","durable_dedup":true}]}`, socket.Addr().String())
	toolsPath := filepath.Join(dir, "tools.json")
	if err := os.WriteFile(toolsPath, []byte(tools), 0600); err != nil {
		t.Fatal(err)
	}
	f.config = Config{Addr: "127.0.0.1:0", HealthAddr: "127.0.0.1:0", Journal: filepath.Join(dir, "journal.db"), Mode: authn.Off, Harnesses: map[string]string{"release-notes": ln.Addr().String()}, ToolExecutors: toolsPath, ModelEndpoint: provider.URL + "/openai/v1/", Deployment: "test-deployment", ModelScope: fixtureScope, ModelTransport: provider.Client().Transport.(*http.Transport)}
	cert := provider.TLS.Certificates[0]
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	f.config.TLSCert, f.config.TLSKey = filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	for path, block := range map[string]*pem.Block{f.config.TLSCert: {Type: "CERTIFICATE", Bytes: cert.Certificate[0]}, f.config.TLSKey: {Type: "PRIVATE KEY", Bytes: key}} {
		if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func (f *hostFixture) start(t *testing.T) (*application, *client.Client, func()) {
	t.Helper()
	app, err := newApplication(t.Context(), f.config, fixtureCredential{t}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Close)
	if app.sessions == nil || app.health == nil || app.store == nil {
		t.Fatal("assembly did not construct sessions, health, and persistent journal")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go app.sessions.Serve(ln)
	var creds credentials.TransportCredentials = insecure.NewCredentials()
	if f.config.TLSCert != "" {
		creds, err = credentials.NewClientTLSFromFile(f.config.TLSCert, "")
		if err != nil {
			t.Fatal(err)
		}
	}
	c, err := client.Dial(ln.Addr().String(), client.WithDialOptions(grpc.WithTransportCredentials(creds)))
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	stop := func() { once.Do(func() { _ = c.Close(); app.Close() }) }
	t.Cleanup(stop)
	return app, c, stop
}

type fixtureRoundTrip func(*http.Request) (*http.Response, error)

func (f fixtureRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func entraFixture(t *testing.T) (entraauth.Config, func(string) string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const tenant = "11111111-2222-3333-4444-555555555555"
	const audience = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	const azp = "12345678-1234-1234-1234-123456789abc"
	const discovery = "/" + tenant + "/v2.0/.well-known/openid-configuration"
	const keys = "/" + tenant + "/discovery/v2.0/keys"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case discovery:
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": fixtureIssuer, "jwks_uri": "https://login.microsoftonline.com" + keys})
		case keys:
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "fixture", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
		default:
			t.Error("unexpected discovery path")
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	local, _ := url.Parse(server.URL)
	base := server.Client().Transport
	client := &http.Client{Transport: fixtureRoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Scheme != "https" || r.URL.Host != "login.microsoftonline.com" || (r.URL.Path != discovery && r.URL.Path != keys) || r.URL.RawQuery != "" {
			return nil, errors.New("off-pin trust request refused")
		}
		clone := r.Clone(r.Context())
		clone.URL.Host = local.Host
		return base.RoundTrip(clone)
	})}
	t.Cleanup(client.CloseIdleConnections)
	return entraauth.Config{TenantID: tenant, Issuer: fixtureIssuer, Audience: audience, AllowedClientIDs: []string{azp}, RequiredScope: "sessions.access", HTTPClient: client}, func(subject string) string {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": fixtureIssuer, "tid": tenant, "aud": audience, "azp": azp, "ver": "2.0", "scp": "sessions.access", "oid": subject, "sub": subject, "exp": time.Now().Add(time.Hour).Unix(), "nbf": time.Now().Add(-time.Minute).Unix()})
		token.Header["kid"] = "fixture"
		raw, err := token.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
}

func bearer(ctx context.Context, values ...string) context.Context {
	return metadata.NewOutgoingContext(ctx, metadata.MD{"authorization": values})
}

func (f *hostFixture) assertNoSecrets(t *testing.T, journal any, tokens ...string) {
	t.Helper()
	f.capture(journal)
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, token := range append(tokens, fixtureModelToken) {
		if strings.Contains(string(f.boundary), token) {
			t.Error("credential leaked into journal, harness metadata, model body, or executor request")
		}
	}
}
