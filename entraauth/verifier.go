// Package entraauth verifies single-tenant Entra v2 delegated access tokens for
// sessions. It authenticates callers, not their authority to perform an action.
package entraauth

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/agent-primitives/sessions/api"
	"github.com/agent-primitives/sessions/authn"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc/metadata"
)

const (
	maxTokenBytes = 16 * 1024
	maxKidBytes   = 256
	fetchTimeout  = 10 * time.Second
)

// Config pins a public-cloud tenant, API audience and delegated client allowlist.
// Issuer must exactly match https://login.microsoftonline.com/<TenantID>/v2.0.
// TenantID, Audience and AllowedClientIDs must be lowercase GUIDs, not aliases or URLs.
type Config struct {
	TenantID, Issuer, Audience string
	AllowedClientIDs           []string
	RequiredScope              string
	// SubjectClaim is oid by default; only oid and sub are supported. Selecting
	// sub changes ownership mapping and requires an ownership/policy migration.
	SubjectClaim string
	// ClockSkew is 0..2 minutes. It relaxes nbf, never usable expiry.
	ClockSkew time.Duration
	// HTTPClient is trusted host code (for example, private TLS/network setup).
	// Its transport must honor context cancellation and not log credentials.
	// The client is copied; timeout and redirect policy are always enforced.
	HTTPClient *http.Client
	// OnRefreshError, if set, reports each failed background key refresh
	// (scheduled or unknown-key) with a fixed DebugReason code and the current
	// snapshot expiry, which a failure never extends. It is not called for the
	// initial load (New returns that error) or a refresh ended by Close or
	// lifetime cancellation. It runs on the refresh goroutine, which Close
	// joins: it must return promptly and must not call Close.
	OnRefreshError func(reason string, keysExpire time.Time)
}

type options struct {
	now      func() time.Time
	schedule func(time.Duration) (<-chan time.Time, func())
}

// Verifier is safe for concurrent use. Close releases its lifecycle resources.
type Verifier struct {
	config      Config
	clients     map[string]bool
	client      *http.Client
	ctx         context.Context
	cancel      context.CancelFunc
	now         func() time.Time
	mu          sync.Mutex
	keys        map[string]*rsa.PublicKey
	expires     time.Time
	nextUnknown time.Time
	flight      *refreshFlight
	closed      bool
	wg          sync.WaitGroup
}

var _ authn.CallerVerifier = (*Verifier)(nil)
var guid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// New validates trust configuration and synchronously loads tenant signing keys.
// The context owns the verifier lifetime, not an individual RPC. Errors have a
// generic message; callers may inspect interface{ DebugReason() string } for a
// fixed diagnostic code, never a raw parser, claim, token or network error.
func New(ctx context.Context, c Config) (*Verifier, error) { return newVerifier(ctx, c, options{}) }
func newVerifier(ctx context.Context, c Config, o options) (*Verifier, error) {
	if !guid.MatchString(c.TenantID) || !guid.MatchString(c.Audience) ||
		c.Issuer != "https://login.microsoftonline.com/"+c.TenantID+"/v2.0" ||
		len(c.AllowedClientIDs) == 0 || !plainWord(c.RequiredScope) || c.ClockSkew < 0 || c.ClockSkew > 2*time.Minute {
		return nil, failure("config")
	}
	if c.SubjectClaim == "" {
		c.SubjectClaim = "oid"
	}
	if c.SubjectClaim != "oid" && c.SubjectClaim != "sub" {
		return nil, failure("config")
	}
	clients := make(map[string]bool, len(c.AllowedClientIDs))
	for _, id := range c.AllowedClientIDs {
		if !guid.MatchString(id) {
			return nil, failure("config")
		}
		clients[id] = true
	}
	c.AllowedClientIDs = nil
	client := http.Client{}
	if c.HTTPClient != nil {
		client = *c.HTTPClient
	}
	c.HTTPClient = nil
	client.Timeout = fetchTimeout
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client.Jar = nil
	if o.now == nil {
		o.now = time.Now
	}
	life, cancel := context.WithCancel(ctx)
	v := &Verifier{config: c, clients: clients, client: &client, ctx: life, cancel: cancel, now: o.now}
	keys, err := v.fetchKeys()
	if err != nil {
		if ctxErr := contextFailure(life); ctxErr != nil {
			err = ctxErr
		}
		cancel()
		return nil, err
	}
	if err := contextFailure(life); err != nil {
		cancel()
		return nil, err
	}
	v.keys = keys
	v.expires = v.now().Add(24 * time.Hour)
	if o.schedule == nil {
		o.schedule = func(d time.Duration) (<-chan time.Time, func()) {
			t := time.NewTicker(d)
			return t.C, t.Stop
		}
	}
	ticks, stop := o.schedule(time.Hour)
	v.wg.Add(1)
	go v.run(ticks, stop)
	return v, nil
}

// Close cancels active trust I/O, stops the worker, and waits for both to exit.
// It is safe to call concurrently or more than once. Trusted transports must
// honor request cancellation, just as they must honor the fetch deadline.
func (v *Verifier) Close() {
	v.mu.Lock()
	v.closed = true
	v.cancel()
	v.mu.Unlock()
	v.wg.Wait()
}

// Verify reads exactly one incoming authorization value. No token or claim map
// is retained, forwarded, logged, or included in returned errors.
func (v *Verifier) Verify(ctx context.Context) (authn.VerifiedCaller, error) {
	if err := contextFailure(ctx); err != nil {
		return authn.VerifiedCaller{}, err
	}
	if v.ctx.Err() != nil {
		return authn.VerifiedCaller{}, failure("closed")
	}
	md, _ := metadata.FromIncomingContext(ctx)
	values := md.Get("authorization")
	if len(values) != 1 {
		return authn.VerifiedCaller{}, failure("credentials")
	}
	scheme, raw, ok := strings.Cut(values[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || len(raw) == 0 || len(raw) > maxTokenBytes || strings.Contains(raw, " ") {
		return authn.VerifiedCaller{}, failure("credentials")
	}
	claims := jwt.MapClaims{}
	var keyErr error
	var keyExpiry time.Time
	_, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		kid, ok := t.Header["kid"].(string)
		if t.Method != jwt.SigningMethodRS256 || !ok || len(kid) == 0 || len(kid) > maxKidBytes || t.Header["crit"] != nil {
			return nil, failure("token")
		}
		var key *rsa.PublicKey
		key, keyExpiry, keyErr = v.key(ctx, kid)
		return key, keyErr
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithJSONNumber(), jwt.WithoutClaimsValidation())
	// jwt errors can embed attacker-controlled header/claim values. Never wrap.
	if canceled := contextFailure(ctx); canceled != nil {
		return authn.VerifiedCaller{}, canceled
	}
	if v.ctx.Err() != nil {
		return authn.VerifiedCaller{}, failure("closed")
	}
	if keyErr != nil {
		return authn.VerifiedCaller{}, keyErr
	}
	if err != nil {
		return authn.VerifiedCaller{}, failure("token")
	}
	now := v.now()
	if !now.Before(keyExpiry) {
		return authn.VerifiedCaller{}, failure("key_unavailable")
	}
	exp, expOK := numericTime(claims["exp"])
	nbf, nbfOK := numericTime(claims["nbf"])
	subject, subjectOK := claims[v.config.SubjectClaim].(string)
	idtyp, idtypOK := claims["idtyp"]
	if claims["iss"] != v.config.Issuer || claims["tid"] != v.config.TenantID ||
		!stringClaimEquals(claims["aud"], v.config.Audience) || !v.clients[stringClaim(claims["azp"])] ||
		claims["ver"] != "2.0" || (idtypOK && idtyp != "user") ||
		!hasScope(claims["scp"], v.config.RequiredScope) || !subjectOK || !plainWord(subject) ||
		!expOK || !nbfOK || !exp.After(now) || nbf.After(now.Add(v.config.ClockSkew)) {
		return authn.VerifiedCaller{}, failure("claims")
	}
	return authn.VerifiedCaller{Identity: api.CallerIdentity{Issuer: v.config.Issuer, Subject: subject}, ValidUntil: exp}, nil
}
func stringClaim(v any) string                  { s, _ := v.(string); return s }
func stringClaimEquals(v any, want string) bool { s, ok := v.(string); return ok && s == want }
func plainWord(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r <= 32 || r == 127 {
			return false
		}
	}
	return true
}
func hasScope(v any, want string) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	for _, scope := range strings.Fields(s) {
		if scope == want {
			return true
		}
	}
	return false
}

// Entra NumericDates use integer seconds; reject strings, fractions and ranges
// that cannot represent a usable expiry rather than coercing untrusted values.
func numericTime(v any) (time.Time, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return time.Time{}, false
	}
	s, err := strconv.ParseInt(string(n), 10, 64)
	if err != nil || s < 0 || s > 253402300799 {
		return time.Time{}, false
	}
	return time.Unix(s, 0).UTC(), true
}

// verificationError exposes fixed diagnostic codes, never parser/network errors.
// Is preserves only standard context classification without an unsafe chain.
type verificationError struct{ reason string }

func (e *verificationError) Error() string       { return "entraauth: authentication failed" }
func (e *verificationError) DebugReason() string { return e.reason }
func (e *verificationError) Is(target error) bool {
	return (e.reason == "canceled" && target == context.Canceled) || (e.reason == "deadline" && target == context.DeadlineExceeded)
}
func failure(reason string) error { return &verificationError{reason: reason} }
func contextFailure(ctx context.Context) error {
	switch ctx.Err() {
	case context.Canceled:
		return failure("canceled")
	case context.DeadlineExceeded:
		return failure("deadline")
	}
	return nil
}
