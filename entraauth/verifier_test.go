package entraauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agent-primitives/sessions/api"
	"github.com/agent-primitives/sessions/authn"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc/metadata"
)

const (
	tenant        = "11111111-2222-3333-4444-555555555555"
	audience      = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	clientID      = "12345678-1234-1234-1234-123456789abc"
	issuer        = "https://login.microsoftonline.com/" + tenant + "/v2.0"
	discoveryPath = "/" + tenant + "/v2.0/.well-known/openid-configuration"
	keysPath      = "/" + tenant + "/discovery/v2.0/keys"
	keysURL       = "https://login.microsoftonline.com" + keysPath
	secret        = "never-echo-token-or-provider-detail"
	objectID      = "0a1b2c3d-4e5f-6789-abcd-ef0123456789"
)

var (
	keyOnce              sync.Once
	signingKey, otherKey *rsa.PrivateKey
	keyErr               error
)

func testKeys(t *testing.T) (*rsa.PrivateKey, *rsa.PrivateKey) {
	t.Helper()
	keyOnce.Do(func() {
		signingKey, keyErr = rsa.GenerateKey(rand.Reader, 2048)
		if keyErr == nil {
			otherKey, keyErr = rsa.GenerateKey(rand.Reader, 2048)
		}
	})
	if keyErr != nil {
		t.Fatal(keyErr)
	}
	return signingKey, otherKey
}

func jwk(key *rsa.PrivateKey, kid string) map[string]any {
	return map[string]any{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
		"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type trustFixture struct {
	mu                      sync.Mutex
	keys                    []map[string]any
	metadataIssuer, jwksURI string
	status                  int
	hook                    func(http.ResponseWriter, *http.Request) bool
	client                  *http.Client
	requests, offPin        atomic.Int32
	now                     atomic.Int64
}

func fixture(t *testing.T) *trustFixture {
	t.Helper()
	key, _ := testKeys(t)
	f := &trustFixture{keys: []map[string]any{jwk(key, "initial")}, metadataIssuer: issuer, jwksURI: keysURL}
	f.now.Store(time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC).Unix())
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		f.mu.Lock()
		hook, status := f.hook, f.status
		meta := map[string]any{"issuer": f.metadataIssuer, "jwks_uri": f.jwksURI}
		keys := f.keys
		f.mu.Unlock()
		if hook != nil && hook(w, r) {
			return
		}
		if status != 0 {
			http.Error(w, secret, status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case discoveryPath:
			_ = json.NewEncoder(w).Encode(meta)
		case keysPath:
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
		default:
			t.Errorf("unexpected trust path %q", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	local, _ := url.Parse(server.URL)
	base := server.Client().Transport
	f.client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Scheme != "https" || r.URL.Host != "login.microsoftonline.com" ||
			(r.URL.Path != discoveryPath && r.URL.Path != keysPath) || r.URL.RawQuery != "" {
			f.offPin.Add(1)
			return nil, errors.New(secret)
		}
		clone := r.Clone(r.Context())
		clone.URL.Host = local.Host
		return base.RoundTrip(clone)
	})}
	t.Cleanup(f.client.CloseIdleConnections)
	return f
}
func (f *trustFixture) clock() time.Time { return time.Unix(f.now.Load(), 0).UTC() }
func (f *trustFixture) config() Config {
	return Config{TenantID: tenant, Issuer: issuer, Audience: audience, AllowedClientIDs: []string{clientID}, RequiredScope: "sessions.access", HTTPClient: f.client}
}
func (f *trustFixture) verifier(t *testing.T, modify func(*Config)) *Verifier {
	t.Helper()
	c := f.config()
	if modify != nil {
		modify(&c)
	}
	v, err := newVerifier(context.Background(), c, options{now: f.clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(v.Close)
	return v
}
func claims(now time.Time) jwt.MapClaims {
	return jwt.MapClaims{"iss": issuer, "tid": tenant, "aud": audience, "azp": clientID, "ver": "2.0",
		"scp": "other sessions.access extra", "oid": objectID, "sub": "pairwise-subject",
		"exp": now.Add(time.Hour).Unix(), "nbf": now.Add(-time.Minute).Unix()}
}
func signed(t *testing.T, c jwt.MapClaims, kid string, key *rsa.PrivateKey, headers map[string]any) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	token.Header["kid"] = kid
	for k, v := range headers {
		token.Header[k] = v
	}
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func incoming(raw string) context.Context {
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+raw))
}
func safeFailure(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("accepted invalid credential/configuration")
	}
	for e := err; e != nil; e = errors.Unwrap(e) {
		if e.Error() != "entraauth: authentication failed" {
			t.Fatalf("unsafe/non-generic error: %q", e.Error())
		}
	}
	var diagnostic interface{ DebugReason() string }
	if !errors.As(err, &diagnostic) || diagnostic.DebugReason() == "" || strings.Contains(diagnostic.DebugReason(), secret) {
		t.Fatal("missing fixed-code safe diagnostic")
	}
}

// Omitting any trust/identity/expiry claim check admits one of these signed attacks.
func TestVerifyClaims(t *testing.T) {
	f := fixture(t)
	v := f.verifier(t, nil)
	key, other := testKeys(t)
	var _ authn.CallerVerifier = v
	raw := signed(t, claims(f.clock()), "initial", key, nil)
	caller, err := v.Verify(incoming(raw))
	if err != nil {
		t.Error(err)
	}
	if caller.Identity.Issuer != issuer || caller.Identity.Subject != objectID || !caller.ValidUntil.Equal(f.clock().Add(time.Hour)) {
		t.Errorf("wrong verified caller: %+v", caller)
	}
	t.Run("explicit user token", func(t *testing.T) {
		c := claims(f.clock())
		c["idtyp"] = "user"
		caller, err := v.Verify(incoming(signed(t, c, "initial", key, nil)))
		if err != nil {
			t.Fatal(err)
		}
		if caller.Identity.Issuer != issuer || caller.Identity.Subject != objectID || !caller.ValidUntil.Equal(f.clock().Add(time.Hour)) {
			t.Errorf("wrong verified caller: %+v", caller)
		}
	})
	for _, tc := range []struct {
		name   string
		change func(jwt.MapClaims)
	}{
		{"wrong issuer", func(c jwt.MapClaims) { c["iss"] = "https://attacker.invalid/" + secret }},
		{"wrong tenant", func(c jwt.MapClaims) { c["tid"] = audience }},
		{"wrong audience", func(c jwt.MapClaims) { c["aud"] = clientID }},
		{"audience array", func(c jwt.MapClaims) { c["aud"] = []string{audience} }},
		{"wrong client", func(c jwt.MapClaims) { c["azp"] = audience }},
		{"wrong version", func(c jwt.MapClaims) { c["ver"] = "1.0" }},
		{"missing scope ID token", func(c jwt.MapClaims) { delete(c, "scp") }},
		{"scope substring", func(c jwt.MapClaims) { c["scp"] = "sessions.access.extra" }},
		{"scope array", func(c jwt.MapClaims) { c["scp"] = []string{"sessions.access"} }},
		{"app with scope", func(c jwt.MapClaims) { c["idtyp"] = "app" }},
		{"app roles only", func(c jwt.MapClaims) { delete(c, "scp"); c["roles"] = []string{"sessions.access"} }},
		{"expired", func(c jwt.MapClaims) { c["exp"] = f.clock().Add(-time.Second).Unix() }},
		{"expiry boundary", func(c jwt.MapClaims) { c["exp"] = f.clock().Unix() }},
		{"future", func(c jwt.MapClaims) { c["nbf"] = f.clock().Add(time.Second).Unix() }},
		{"missing exp", func(c jwt.MapClaims) { delete(c, "exp") }},
		{"missing nbf", func(c jwt.MapClaims) { delete(c, "nbf") }},
		{"string exp", func(c jwt.MapClaims) { c["exp"] = "9999999999" }},
		{"string nbf", func(c jwt.MapClaims) { c["nbf"] = "0" }},
		{"fractional exp", func(c jwt.MapClaims) { c["exp"] = float64(f.clock().Unix()) + 0.5 }},
		{"huge exp", func(c jwt.MapClaims) { c["exp"] = 1e100 }},
		{"null nbf", func(c jwt.MapClaims) { c["nbf"] = nil }},
		{"missing oid no fallback", func(c jwt.MapClaims) { delete(c, "oid"); c["email"] = secret; c["upn"] = secret }},
		{"empty oid", func(c jwt.MapClaims) { c["oid"] = "" }},
		{"wrong subject type", func(c jwt.MapClaims) { c["oid"] = 123 }},
		{"oid path and UPN", func(c jwt.MapClaims) { c["oid"] = "../x@y" }},
		{"oid UPN", func(c jwt.MapClaims) { c["oid"] = "user@contoso.example" }},
		{"oid uppercase GUID", func(c jwt.MapClaims) { c["oid"] = strings.ToUpper(objectID) }},
		{"oid braced GUID", func(c jwt.MapClaims) { c["oid"] = "{" + objectID + "}" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := claims(f.clock())
			tc.change(c)
			_, err := v.Verify(incoming(signed(t, c, "initial", key, nil)))
			safeFailure(t, err)
		})
	}
	t.Run("bad signature", func(t *testing.T) {
		_, err := v.Verify(incoming(signed(t, claims(f.clock()), "initial", other, nil)))
		safeFailure(t, err)
	})
}

// A permissive parser or ambiguous metadata must not bypass signature verification.
func TestCredentialsAndAlgorithms(t *testing.T) {
	f := fixture(t)
	v := f.verifier(t, nil)
	key, _ := testKeys(t)
	good := signed(t, claims(f.clock()), "initial", key, nil)
	hmac := jwt.NewWithClaims(jwt.SigningMethodHS256, claims(f.clock()))
	hmac.Header["kid"] = "initial"
	hs, _ := hmac.SignedString([]byte(secret))
	none := jwt.NewWithClaims(jwt.SigningMethodNone, claims(f.clock()))
	none.Header["kid"] = "initial"
	unsigned, _ := none.SignedString(jwt.UnsafeAllowNoneSignatureType)
	for _, tc := range []struct {
		name   string
		values []string
	}{
		{"missing", nil}, {"empty", []string{""}}, {"duplicate", []string{"Bearer " + good, "Bearer " + good}},
		{"basic", []string{"Basic " + good}}, {"no token", []string{"Bearer"}},
		{"extra whitespace", []string{"Bearer  " + good}}, {"comma combined", []string{"Bearer " + good + ",Bearer " + good}},
		{"oversized", []string{"Bearer " + strings.Repeat("x", 16*1024+1)}},
		{"malformed", []string{"Bearer " + secret}}, {"hmac", []string{"Bearer " + hs}}, {"none", []string{"Bearer " + unsigned}},
		{"missing kid", []string{"Bearer " + signed(t, claims(f.clock()), "", key, nil)}},
		{"wrong kid type", []string{"Bearer " + signed(t, claims(f.clock()), "initial", key, map[string]any{"kid": 123})}},
		{"oversized kid", []string{"Bearer " + signed(t, claims(f.clock()), strings.Repeat("k", 257), key, nil)}},
		{"unsupported critical header", []string{"Bearer " + signed(t, claims(f.clock()), "initial", key, map[string]any{"crit": []string{"unknown"}, "unknown": true})}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := metadata.NewIncomingContext(context.Background(), metadata.MD{"authorization": tc.values})
			_, err := v.Verify(ctx)
			safeFailure(t, err)
		})
	}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "bearer "+good))
	if _, err := v.Verify(ctx); err != nil {
		t.Fatalf("case-insensitive scheme: %v", err)
	}
	ctx, cancel := context.WithCancel(incoming(good))
	cancel()
	_, err := v.Verify(ctx)
	safeFailure(t, err)
	if !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation classification lost")
	}
}

// Skew must never extend usable expiry, and explicit sub selection must not use oid.
func TestSubjectAndSkew(t *testing.T) {
	f := fixture(t)
	key, _ := testKeys(t)
	v := f.verifier(t, func(c *Config) { c.SubjectClaim = "sub"; c.ClockSkew = 2 * time.Minute })
	c := claims(f.clock())
	c["nbf"] = f.clock().Add(2 * time.Minute).Unix()
	c["oid"] = "not-consulted"
	caller, err := v.Verify(incoming(signed(t, c, "initial", key, nil)))
	if err != nil || caller.Identity.Subject != "pairwise-subject" {
		t.Fatalf("sub/skew: %+v %v", caller, err)
	}
	delete(c, "sub")
	_, err = v.Verify(incoming(signed(t, c, "initial", key, nil)))
	safeFailure(t, err)
	c = claims(f.clock())
	c["exp"] = f.clock().Unix()
	_, err = v.Verify(incoming(signed(t, c, "initial", key, nil)))
	safeFailure(t, err)
	c = claims(f.clock())
	c["nbf"] = f.clock().Add(2*time.Minute + time.Second).Unix()
	_, err = v.Verify(incoming(signed(t, c, "initial", key, nil)))
	safeFailure(t, err)
}

// Allowlist entries must have the exact form Verify returns, or they never match.
func TestValidIdentity(t *testing.T) {
	c := Config{TenantID: tenant, Issuer: issuer, Audience: audience, AllowedClientIDs: []string{clientID}, RequiredScope: "sessions.access"}
	sub := c
	sub.SubjectClaim = "sub"
	for _, tc := range []struct {
		name     string
		config   Config
		identity api.CallerIdentity
		want     bool
	}{
		{"default oid GUID", c, api.CallerIdentity{Issuer: issuer, Subject: objectID}, true},
		{"explicit oid GUID", func() Config { o := c; o.SubjectClaim = "oid"; return o }(), api.CallerIdentity{Issuer: issuer, Subject: objectID}, true},
		{"v1 issuer", c, api.CallerIdentity{Issuer: "https://sts.windows.net/" + tenant + "/", Subject: objectID}, false},
		{"trailing slash issuer", c, api.CallerIdentity{Issuer: issuer + "/", Subject: objectID}, false},
		{"tenant alias issuer", c, api.CallerIdentity{Issuer: "https://login.microsoftonline.com/organizations/v2.0", Subject: objectID}, false},
		{"empty issuer", c, api.CallerIdentity{Subject: objectID}, false},
		{"oid UPN", c, api.CallerIdentity{Issuer: issuer, Subject: "user@contoso.example"}, false},
		{"oid path", c, api.CallerIdentity{Issuer: issuer, Subject: "../x@y"}, false},
		{"oid uppercase GUID", c, api.CallerIdentity{Issuer: issuer, Subject: strings.ToUpper(objectID)}, false},
		{"oid empty", c, api.CallerIdentity{Issuer: issuer}, false},
		{"sub pairwise", sub, api.CallerIdentity{Issuer: issuer, Subject: "pairwise-subject"}, true},
		{"sub whitespace", sub, api.CallerIdentity{Issuer: issuer, Subject: "pairwise subject"}, false},
		{"sub v1 issuer", sub, api.CallerIdentity{Issuer: "https://sts.windows.net/" + tenant + "/", Subject: "pairwise-subject"}, false},
		{"unsupported claim", func() Config { o := c; o.SubjectClaim = "email"; return o }(), api.CallerIdentity{Issuer: issuer, Subject: objectID}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.config.ValidIdentity(tc.identity); got != tc.want {
				t.Fatalf("ValidIdentity = %v, want %v", got, tc.want)
			}
		})
	}
}

// Invalid trust config must fail before network I/O; client allowlists are immutable snapshots.
func TestConfigValidationAndCopy(t *testing.T) {
	f := fixture(t)
	for _, tc := range []struct {
		name   string
		change func(*Config)
	}{
		{"tenant alias", func(c *Config) { c.TenantID = "common" }},
		{"tenant URL", func(c *Config) { c.TenantID = "../" + secret }},
		{"uppercase tenant and issuer", func(c *Config) {
			c.TenantID = strings.ToUpper(audience)
			c.Issuer = "https://login.microsoftonline.com/" + c.TenantID + "/v2.0"
		}},
		{"issuer mismatch", func(c *Config) { c.Issuer = "https://login.microsoftonline.com/organizations/v2.0" }},
		{"issuer empty", func(c *Config) { c.Issuer = "" }},
		{"audience not GUID", func(c *Config) { c.Audience = "api://" + audience }},
		{"uppercase audience", func(c *Config) { c.Audience = strings.ToUpper(audience) }},
		{"clients empty", func(c *Config) { c.AllowedClientIDs = nil }},
		{"client not GUID", func(c *Config) { c.AllowedClientIDs = []string{secret} }},
		{"uppercase client", func(c *Config) { c.AllowedClientIDs = []string{strings.ToUpper(clientID)} }},
		{"scope empty", func(c *Config) { c.RequiredScope = "" }},
		{"scope multiple", func(c *Config) { c.RequiredScope = "one two" }},
		{"mutable subject", func(c *Config) { c.SubjectClaim = "email" }},
		{"negative skew", func(c *Config) { c.ClockSkew = -time.Nanosecond }},
		{"excess skew", func(c *Config) { c.ClockSkew = 2*time.Minute + time.Nanosecond }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := f.config()
			tc.change(&c)
			v, err := New(context.Background(), c)
			if v != nil {
				v.Close()
			}
			safeFailure(t, err)
			var diagnostic interface{ DebugReason() string }
			if !errors.As(err, &diagnostic) || diagnostic.DebugReason() != "config" {
				t.Error("invalid configuration did not fail at the config boundary")
			}
		})
	}
	if f.requests.Load() != 0 || f.offPin.Load() != 0 {
		t.Fatal("invalid config performed network I/O")
	}
	c := f.config()
	v, err := newVerifier(context.Background(), c, options{now: f.clock})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	c.AllowedClientIDs[0] = audience
	key, _ := testKeys(t)
	if _, err := v.Verify(incoming(signed(t, claims(f.clock()), "initial", key, nil))); err != nil {
		t.Fatal("caller mutated configured allowlist", err)
	}
	claims := claims(f.clock())
	claims["azp"] = audience
	_, err = v.Verify(incoming(signed(t, claims, "initial", key, nil)))
	safeFailure(t, err)
}
