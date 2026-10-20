package host

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/aks-durable-agents/entraauth"
	"github.com/agent-primitives/sessions/api"
	"github.com/agent-primitives/sessions/authn"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// logSecret stands in for token, claim and provider text that must never be logged.
const logSecret = "never-log-token-claim-or-provider-detail"

type logSink struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	wrote chan struct{}
}

func newLogSink() *logSink { return &logSink{wrote: make(chan struct{}, 1)} }
func (s *logSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case s.wrote <- struct{}{}:
	default:
	}
	return s.buf.Write(p)
}
func (s *logSink) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}
func (s *logSink) logger() *slog.Logger {
	return slog.New(slog.NewTextHandler(s, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// await waits for an asynchronous log line, such as the refresh hook's.
func (s *logSink) await(t *testing.T, line string) {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for !strings.Contains(s.String(), line) {
		select {
		case <-s.wrote:
		case <-deadline:
			t.Fatalf("missing log %q in:\n%s", line, s.String())
		}
	}
}

type reasonError struct{ reason string }

func (e *reasonError) Error() string       { return "authentication failed: " + logSecret }
func (e *reasonError) DebugReason() string { return e.reason }

type scriptedVerifier struct{ err error }

func (v *scriptedVerifier) Verify(context.Context) (authn.VerifiedCaller, error) {
	if v.err != nil {
		return authn.VerifiedCaller{}, v.err
	}
	return authn.VerifiedCaller{Identity: api.CallerIdentity{Issuer: "issuer", Subject: logSecret}}, nil
}

// Each reason logs at most once per interval, then reports what it suppressed.
// Only fixed codes reach the log; error text and unexpected codes never do.
func TestLoggingVerifierFixedReasonsAndRateLimit(t *testing.T) {
	sink := newLogSink()
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	inner := &scriptedVerifier{}
	v := newLoggingVerifier(inner, sink.logger(), func() time.Time { return now })
	fail := func(err error, advance time.Duration) {
		t.Helper()
		now = now.Add(advance)
		inner.err = err
		_, got := v.Verify(context.Background())
		if got != err {
			t.Fatalf("wrapper changed the verifier error: %v", got)
		}
	}
	fail(&reasonError{"token"}, 0)
	fail(&reasonError{"token"}, time.Second)
	fail(&reasonError{"token"}, time.Second)
	fail(&reasonError{"fetch"}, time.Second)
	fail(nil, time.Second)
	fail(&reasonError{"token"}, authLogInterval-3*time.Second)
	fail(&reasonError{"Bearer " + logSecret}, 0)
	fail(errors.New(logSecret), 0)
	fail(errors.New(logSecret), authLogInterval)
	fail(&reasonError{"key_unavailable"}, 0)
	fail(&reasonError{"canceled"}, 0)
	fail(&reasonError{"deadline"}, 0)
	fail(&reasonError{"canceled"}, time.Second)
	want := []string{
		`level=WARN msg="caller authentication failed" reason=token suppressed=0`,
		`level=WARN msg="caller authentication failed" reason=fetch suppressed=0`,
		`level=WARN msg="caller authentication failed" reason=token suppressed=2`,
		`level=WARN msg="caller authentication failed" reason=unclassified suppressed=0`,
		`level=WARN msg="caller authentication failed" reason=unclassified suppressed=1`,
		`level=WARN msg="caller authentication failed" reason=key_unavailable suppressed=0`,
		`level=DEBUG msg="caller context ended during authentication" reason=canceled suppressed=0`,
		`level=DEBUG msg="caller context ended during authentication" reason=deadline suppressed=0`,
	}
	lines := strings.Split(strings.TrimSpace(sink.String()), "\n")
	if len(lines) != len(want) {
		t.Fatalf("got %d log lines, want %d:\n%s", len(lines), len(want), sink.String())
	}
	for i, line := range lines {
		if !strings.HasSuffix(line, want[i]) {
			t.Errorf("line %d = %q, want suffix %q", i, line, want[i])
		}
	}
	if strings.Contains(sink.String(), logSecret) {
		t.Fatal("error text reached the log")
	}
}

// Refresh failures escalate as the unextended key snapshot nears expiry.
func TestRefreshErrorLogger(t *testing.T) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name   string
		reason string
		left   time.Duration
		want   string
	}{
		{"failed", "fetch", 23 * time.Hour, `level=WARN msg="Entra signing-key refresh failed" reason=fetch keys_expire_in=23h0m0s`},
		{"nears expiry", "jwks", keyExpiryWarning, `level=WARN msg="Entra signing-key refresh failed; key snapshot nears expiry" reason=jwks keys_expire_in=6h0m0s`},
		{"expired", "discovery", 0, `level=ERROR msg="Entra signing keys expired; all authentication fails until a key refresh succeeds" reason=discovery`},
		{"unexpected code", logSecret + " text", time.Hour, `reason=unclassified keys_expire_in=1h0m0s`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sink := newLogSink()
			refreshErrorLogger(sink.logger(), func() time.Time { return now })(tc.reason, now.Add(tc.left))
			got := strings.TrimSpace(sink.String())
			if !strings.HasSuffix(got, tc.want) || strings.Contains(got, logSecret) {
				t.Fatalf("log = %q, want suffix %q", got, tc.want)
			}
		})
	}
}

// trustSwitch controls an entraFixture trust client after startup: it can fail
// fetches with provider text, or hold a JWKS fetch and then serve a rotated key.
type trustSwitch struct {
	fail    atomic.Bool
	hold    atomic.Pointer[heldFetch]
	rotated *rsa.PrivateKey
}

type heldFetch struct{ entered, release chan struct{} }

func switchTrust(t *testing.T, identity *entraauth.Config) *trustSwitch {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s := &trustSwitch{rotated: key}
	base := identity.HTTPClient.Transport
	identity.HTTPClient = &http.Client{Transport: fixtureRoundTrip(func(r *http.Request) (*http.Response, error) {
		if s.fail.Load() {
			return nil, errors.New(logSecret)
		}
		h := s.hold.Load()
		if h == nil || !strings.HasSuffix(r.URL.Path, "/discovery/v2.0/keys") {
			return base.RoundTrip(r)
		}
		close(h.entered)
		select {
		case <-h.release:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
		body, _ := json.Marshal(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "rotated", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(body)), Request: r}, nil
	})}
	return s
}

// signRotated signs an otherwise-valid token whose kid is not in the startup keys.
func (s *trustSwitch) signRotated(t *testing.T, identity entraauth.Config, subject string) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": identity.Issuer, "tid": identity.TenantID, "aud": identity.Audience, "azp": identity.AllowedClientIDs[0], "ver": "2.0", "scp": identity.RequiredScope, "oid": subject, "sub": subject, "exp": time.Now().Add(time.Hour).Unix(), "nbf": time.Now().Add(-time.Minute).Unix()})
	token.Header["kid"] = "rotated"
	raw, err := token.SignedString(s.rotated)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// The assembled required-mode host logs rejected callers and failed key
// refreshes by fixed code only, never the token, claims or provider error.
func TestRequiredAuthFailureLogging(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	f := newHostFixture(t)
	identity, sign := entraFixture(t)
	trust := switchTrust(t, &identity)
	f.config.Mode, f.config.Identity = authn.Required, identity
	sink := newLogSink()
	_, c, _ := f.startWith(t, t.Context(), sink.logger())
	badToken := "Bearer " + logSecret + ".x.y"
	for range 3 {
		if _, err := c.ListSessions(bearer(ctx, badToken), ""); status.Code(err) != codes.Unauthenticated {
			t.Fatalf("bad token: %v", err)
		}
	}
	if _, err := c.ListSessions(bearer(ctx), ""); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("missing token: %v", err)
	}
	trust.fail.Store(true)
	rotated := trust.signRotated(t, identity, logSecret)
	if _, err := c.ListSessions(bearer(ctx, "Bearer "+rotated), ""); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unknown key during outage: %v", err)
	}
	sink.await(t, `msg="Entra signing-key refresh failed" reason=fetch keys_expire_in=`)
	owner := sign("owner")
	if _, err := c.ListSessions(bearer(ctx, "Bearer "+owner), ""); err != nil {
		t.Fatal("outage invalidated the cached snapshot", err)
	}
	logs := sink.String()
	for _, want := range []string{
		`msg="caller authentication failed" reason=token suppressed=0`,
		`msg="caller authentication failed" reason=credentials suppressed=0`,
		`msg="caller authentication failed" reason=fetch suppressed=0`,
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("missing log %q", want)
		}
	}
	if n := strings.Count(logs, "reason=token"); n != 1 {
		t.Errorf("token failures logged %d times, want 1 per interval", n)
	}
	for _, leaked := range []string{logSecret, rotated, owner, "owner", identity.Audience, identity.AllowedClientIDs[0]} {
		if strings.Contains(logs, leaked) {
			t.Errorf("log contains credential, claim or provider text %q", leaked)
		}
	}
}

// Run cancels its signal context and then drains. A caller already in
// verification (here waiting on an unknown-key refresh) must still be verified
// during the drain; the verifier closes only when the application does.
func TestEntraVerifierOutlivesSignalUntilDrain(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	f := newHostFixture(t)
	identity, sign := entraFixture(t)
	trust := switchTrust(t, &identity)
	f.config.Mode, f.config.Identity = authn.Required, identity
	signal, stop := context.WithCancel(ctx)
	defer stop()
	app, c, _ := f.startWith(t, signal, slog.New(slog.DiscardHandler))
	held := &heldFetch{entered: make(chan struct{}), release: make(chan struct{})}
	trust.hold.Store(held)
	result := make(chan error, 1)
	go func() {
		_, err := c.ListSessions(bearer(ctx, "Bearer "+trust.signRotated(t, identity, "owner")), "")
		result <- err
	}()
	select {
	case <-held.entered:
	case <-ctx.Done():
		t.Fatal("verification did not reach the key refresh")
	}
	stop()
	drained := make(chan struct{})
	go func() { app.sessions.GracefulStop(); close(drained) }()
	close(held.release)
	select {
	case err := <-result:
		if err != nil {
			t.Fatal("RPC admitted before shutdown was rejected during drain:", err)
		}
	case <-ctx.Done():
		t.Fatal("RPC did not finish")
	}
	select {
	case <-drained:
	case <-ctx.Done():
		t.Fatal("drain did not finish")
	}
	app.Close()
	_, err := app.verifier.Verify(metadata.NewIncomingContext(ctx, metadata.Pairs("authorization", "Bearer "+sign("owner"))))
	if debugReason(err) != "closed" {
		t.Fatalf("verifier outlived application Close: %v", err)
	}
}

// The signal context still cancels the synchronous startup key load.
func TestEntraVerifierStartupCancellation(t *testing.T) {
	identity, _ := entraFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	v, err := newEntraVerifier(ctx, identity)
	if v != nil {
		v.Close()
		t.Fatal("canceled startup returned a verifier")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled startup error = %v", err)
	}
}
