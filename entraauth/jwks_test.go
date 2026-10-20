package entraauth

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func await(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for synchronized event")
	}
}
func awaitError(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("verification did not finish")
		return nil
	}
}

// observedContext proves a request entered the cancellable flight wait, without sleeps.
type observedContext struct {
	context.Context
	observed chan struct{}
	once     sync.Once
}

func (c *observedContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.observed) })
	return c.Context.Done()
}
func verifyAsync(v *Verifier, ctx context.Context) <-chan error {
	done := make(chan error, 1)
	go func() { _, err := v.Verify(ctx); done <- err }()
	return done
}

// signaledDeadlineContext models a deadline expiring only after the HTTP handler
// is entered. A test-controlled signal, not a wall-clock timer, makes the
// DeadlineExceeded path deterministic while using real HTTP cancellation.
type signaledDeadlineContext struct {
	context.Context
	done chan struct{}
}

func (c *signaledDeadlineContext) Done() <-chan struct{} { return c.done }
func (c *signaledDeadlineContext) Err() error {
	select {
	case <-c.done:
		return context.DeadlineExceeded
	default:
		return nil
	}
}

// Cancellation during initial discovery must retain standard context
// classification, not be masked by the sanitized network failure.
func TestInitialDiscoveryCancellation(t *testing.T) {
	for _, reason := range []string{"canceled", "deadline"} {
		t.Run(reason, func(t *testing.T) {
			f := fixture(t)
			var parent context.Context
			var stop context.CancelFunc
			want := context.Canceled
			if reason == "deadline" {
				deadline := &signaledDeadlineContext{Context: context.Background(), done: make(chan struct{})}
				var once sync.Once
				stop = func() { once.Do(func() { close(deadline.done) }) }
				parent = deadline
				want = context.DeadlineExceeded
			} else {
				parent, stop = context.WithCancel(context.Background())
			}
			defer stop()
			entered, networkCanceled := make(chan struct{}), make(chan struct{})
			f.hook = func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != discoveryPath {
					t.Error("initial discovery cancellation reached JWKS")
					return false
				}
				close(entered)
				<-r.Context().Done()
				close(networkCanceled)
				return true
			}
			done := make(chan error, 1)
			go func() {
				v, err := New(parent, f.config())
				if v != nil {
					v.Close()
				}
				done <- err
			}()
			await(t, entered)
			stop()
			err := awaitError(t, done)
			await(t, networkCanceled)
			safeFailure(t, err)
			if !errors.Is(err, want) {
				t.Errorf("initial fetch lost %s classification", reason)
			}
			var diagnostic interface{ DebugReason() string }
			if !errors.As(err, &diagnostic) || diagnostic.DebugReason() != reason {
				t.Errorf("initial fetch did not return fixed %s diagnostic", reason)
			}
			if f.requests.Load() != 1 || f.offPin.Load() != 0 {
				t.Fatal("initial cancellation made unexpected trust requests")
			}
		})
	}
}

// Optional Entra certificate/issuer metadata does not replace the n/e trust
// key or require alg to be present. All fixture material is generated offline.
func TestEntraSigningKeyMetadata(t *testing.T) {
	f := fixture(t)
	key, _ := testKeys(t)
	raw := signed(t, claims(f.clock()), "initial", key, nil)
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    f.clock().Add(-time.Hour), NotAfter: f.clock().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	k := jwk(key, "initial")
	delete(k, "alg")
	k["x5c"] = []string{base64.StdEncoding.EncodeToString(der)}
	// x5t is the standard SHA-1 certificate thumbprint, not a signing algorithm.
	thumbprint := sha1.Sum(der)
	k["x5t"] = base64.RawURLEncoding.EncodeToString(thumbprint[:])
	k["issuer"] = issuer
	k["cloud_instance_name"] = "microsoftonline.com"
	f.keys = []map[string]any{k}
	v := f.verifier(t, nil)
	caller, err := v.Verify(incoming(raw))
	if err != nil {
		t.Fatal(err)
	}
	if caller.Identity.Issuer != issuer || caller.Identity.Subject != "immutable-object-id" || !caller.ValidUntil.Equal(f.clock().Add(time.Hour)) {
		t.Fatalf("optional key metadata changed verified caller: %+v", caller)
	}
}

// Weak, ambiguous or unusable signing sets must not produce a usable verifier.
func TestInvalidSigningSets(t *testing.T) {
	key, _ := testKeys(t)
	for _, tc := range []struct {
		name   string
		change func(map[string]any) []map[string]any
	}{
		{"empty", func(k map[string]any) []map[string]any { return nil }},
		{"too many", func(k map[string]any) []map[string]any {
			keys := make([]map[string]any, 101)
			for i := range keys {
				keys[i] = jwk(key, fmt.Sprint(i))
			}
			return keys
		}},
		{"duplicate kid", func(k map[string]any) []map[string]any { return []map[string]any{k, jwk(key, "initial")} }},
		{"unsupported kty", func(k map[string]any) []map[string]any { k["kty"] = "EC"; return []map[string]any{k} }},
		{"wrong algorithm", func(k map[string]any) []map[string]any { k["alg"] = "HS256"; return []map[string]any{k} }},
		{"encryption use", func(k map[string]any) []map[string]any { k["use"] = "enc"; return []map[string]any{k} }},
		{"sign key operation", func(k map[string]any) []map[string]any { k["key_ops"] = []string{"sign"}; return []map[string]any{k} }},
		{"malformed modulus", func(k map[string]any) []map[string]any { k["n"] = secret; return []map[string]any{k} }},
		{"weak modulus", func(k map[string]any) []map[string]any {
			k["n"] = base64.RawURLEncoding.EncodeToString(big.NewInt(65537).Bytes())
			return []map[string]any{k}
		}},
		{"even modulus", func(k map[string]any) []map[string]any {
			n := new(big.Int).Sub(key.N, big.NewInt(1))
			k["n"] = base64.RawURLEncoding.EncodeToString(n.Bytes())
			return []map[string]any{k}
		}},
		{"bad exponent", func(k map[string]any) []map[string]any { k["e"] = "Ag"; return []map[string]any{k} }},
		{"missing kid", func(k map[string]any) []map[string]any { delete(k, "kid"); return []map[string]any{k} }},
		{"oversized kid", func(k map[string]any) []map[string]any {
			k["kid"] = strings.Repeat("x", 257)
			return []map[string]any{k}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := fixture(t)
			f.keys = tc.change(jwk(key, "initial"))
			v, err := New(context.Background(), f.config())
			if v != nil {
				v.Close()
			}
			safeFailure(t, err)
		})
	}
}

// Pin metadata and JWKS byte-for-byte; no redirect or token-supplied URL gains authority.
func TestPinnedDiscoveryAndBoundedResponses(t *testing.T) {
	for _, uri := range []string{
		"https://attacker.invalid/" + secret, "http://login.microsoftonline.com" + keysPath,
		"https://login.microsoftonline.com/common/discovery/v2.0/keys",
		"https://login.microsoftonline.com/organizations/discovery/v2.0/keys",
		"https://login.microsoftonline.com/" + audience + "/discovery/v2.0/keys",
		keysURL + "?appid=" + audience, keysURL + "#fragment", "https://login.microsoftonline.com:443" + keysPath,
	} {
		t.Run(uri, func(t *testing.T) {
			f := fixture(t)
			f.jwksURI = uri
			v, err := New(context.Background(), f.config())
			if v != nil {
				v.Close()
			}
			safeFailure(t, err)
			if f.requests.Load() != 1 || f.offPin.Load() != 0 {
				t.Fatal("followed off-pin metadata target")
			}
		})
	}
	for _, tc := range []struct {
		name   string
		path   string
		body   string
		status int
	}{
		{"wrong metadata issuer", discoveryPath, `{"issuer":"` + secret + `","jwks_uri":"` + keysURL + `"}`, 200},
		{"malformed discovery", discoveryPath, secret, 200},
		{"trailing discovery JSON", discoveryPath, `{"issuer":"` + issuer + `","jwks_uri":"` + keysURL + `"} {}`, 200},
		{"oversized discovery", discoveryPath, strings.Repeat(" ", 1024*1024+1), 200},
		{"oversized JWKS", keysPath, strings.Repeat(" ", 1024*1024+1), 200},
		{"malformed JWKS", keysPath, secret, 200},
		{"trailing JWKS JSON", keysPath, `{"keys":[]} {}`, 200},
		{"discovery outage", discoveryPath, secret, 503},
		{"JWKS outage", keysPath, secret, 503},
		{"discovery redirect", discoveryPath, secret, 302},
		{"JWKS redirect", keysPath, secret, 307},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := fixture(t)
			f.hook = func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != tc.path {
					return false
				}
				w.Header().Set("Location", "https://attacker.invalid/"+secret)
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
				return true
			}
			v, err := New(context.Background(), f.config())
			if v != nil {
				v.Close()
			}
			safeFailure(t, err)
			if f.offPin.Load() != 0 {
				t.Fatal("followed redirect")
			}
		})
	}
	t.Run("network error sanitized", func(t *testing.T) {
		c := fixture(t).config()
		c.HTTPClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New(secret) })}
		_, err := New(context.Background(), c)
		safeFailure(t, err)
	})
}

// A miss immediately after startup must refresh once, and all overlapping
// requests share both successful and failed refreshes. Floods remain bounded.
func TestUnknownKidCoalescingAndCooldown(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint("failure=", fail), func(t *testing.T) {
			f := fixture(t)
			v := f.verifier(t, nil)
			_, key := testKeys(t)
			entered, release := make(chan struct{}), make(chan struct{})
			var enterOnce, releaseOnce sync.Once
			t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
			f.mu.Lock()
			f.keys = []map[string]any{jwk(key, "rotated")}
			f.hook = func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != keysPath {
					return false
				}
				enterOnce.Do(func() { close(entered) })
				select {
				case <-release:
				case <-r.Context().Done():
					return true
				}
				if fail {
					http.Error(w, secret, http.StatusServiceUnavailable)
					return true
				}
				return false
			}
			f.mu.Unlock()
			raw := signed(t, claims(f.clock()), "rotated", key, nil)
			results := []<-chan error{verifyAsync(v, incoming(raw))}
			await(t, entered)
			for range 12 {
				ctx := &observedContext{Context: incoming(raw), observed: make(chan struct{})}
				results = append(results, verifyAsync(v, ctx))
				await(t, ctx.observed)
			}
			releaseOnce.Do(func() { close(release) })
			for _, r := range results {
				err := awaitError(t, r)
				if fail {
					safeFailure(t, err)
				} else if err != nil {
					t.Fatal(err)
				}
			}
			if f.requests.Load() != 4 {
				t.Fatalf("refresh was not shared: %d HTTP requests", f.requests.Load())
			}
			for range 10 {
				_, err := v.Verify(incoming(signed(t, claims(f.clock()), "unknown", key, nil)))
				safeFailure(t, err)
			}
			if f.requests.Load() != 4 {
				t.Fatal("unknown-kid flood bypassed cooldown")
			}
			f.now.Add(int64((5*time.Minute - time.Second) / time.Second))
			_, err := v.Verify(incoming(signed(t, claims(f.clock()), "unknown", key, nil)))
			safeFailure(t, err)
			if f.requests.Load() != 4 {
				t.Fatal("cooldown ended too soon")
			}
			f.now.Add(1)
			_, err = v.Verify(incoming(signed(t, claims(f.clock()), "unknown", key, nil)))
			safeFailure(t, err)
			if f.requests.Load() != 6 {
				t.Fatal("cooldown did not permit bounded retry at five minutes")
			}
		})
	}
}

// Successful refreshes replace rather than merge snapshots; invalid refreshes
// retain only the previous good snapshot and cannot authenticate unusable keys.
func TestRotationRemovalAndMalformedRefresh(t *testing.T) {
	for _, badSet := range []bool{false, true} {
		t.Run(fmt.Sprint("invalid=", badSet), func(t *testing.T) {
			f := fixture(t)
			v := f.verifier(t, nil)
			old, key := testKeys(t)
			f.mu.Lock()
			f.keys = []map[string]any{jwk(key, "rotated")}
			if badSet {
				f.keys = append(f.keys, jwk(old, "rotated"))
			}
			f.mu.Unlock()
			_, err := v.Verify(incoming(signed(t, claims(f.clock()), "rotated", key, nil)))
			if badSet {
				safeFailure(t, err)
			} else if err != nil {
				t.Fatal("rotation failed", err)
			}
			_, err = v.Verify(incoming(signed(t, claims(f.clock()), "initial", old, nil)))
			if badSet {
				if err != nil {
					t.Fatal("bad refresh discarded still-valid good snapshot", err)
				}
			} else {
				safeFailure(t, err)
			}
			if f.requests.Load() != 4 {
				t.Fatal("removal/failure triggered extra retry")
			}
		})
	}
}

// Failed fetches never extend the original 24h trust lifetime.
func TestOutageTTLAndRecovery(t *testing.T) {
	f := fixture(t)
	v := f.verifier(t, nil)
	key, _ := testKeys(t)
	c := claims(f.clock())
	c["exp"] = f.clock().Add(48 * time.Hour).Unix()
	good := signed(t, c, "initial", key, nil)
	unknown := signed(t, c, "unknown", key, nil)
	f.mu.Lock()
	f.status = 503
	f.mu.Unlock()
	f.now.Add(int64(23 * time.Hour / time.Second))
	_, err := v.Verify(incoming(unknown))
	safeFailure(t, err)
	if _, err := v.Verify(incoming(good)); err != nil {
		t.Fatal("outage invalidated unexpired snapshot", err)
	}
	f.now.Add(int64(time.Hour/time.Second) - 1)
	if _, err := v.Verify(incoming(good)); err != nil {
		t.Fatal("snapshot expired before 24h", err)
	}
	f.now.Add(1)
	_, err = v.Verify(incoming(good))
	safeFailure(t, err)
	if f.requests.Load() != 4 {
		t.Fatalf("expected startup and two failed discovery fetches, got %d", f.requests.Load())
	}
	f.mu.Lock()
	f.status = 0
	f.mu.Unlock()
	f.now.Add(int64(5 * time.Minute / time.Second))
	if _, err := v.Verify(incoming(good)); err != nil {
		t.Fatal("did not recover", err)
	}
}

// Scheduled refresh has an hourly lifecycle, not an RPC lifetime. A scheduled
// replacement removes old keys without requiring an unknown-kid first.
func TestScheduledRefreshAndClose(t *testing.T) {
	f := fixture(t)
	key, rotated := testKeys(t)
	ticks := make(chan time.Time, 1)
	stopped := make(chan struct{})
	c := f.config()
	c.OnRefreshError = func(reason string, _ time.Time) { t.Errorf("successful refresh or Close reported %q", reason) }
	v, err := newVerifier(context.Background(), c, options{now: f.clock, schedule: func(d time.Duration) (<-chan time.Time, func()) {
		if d != time.Hour {
			t.Errorf("refresh interval = %v", d)
		}
		return ticks, func() { close(stopped) }
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	f.mu.Lock()
	f.keys = []map[string]any{jwk(rotated, "rotated")}
	f.hook = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != keysPath {
			return false
		}
		close(entered)
		select {
		case <-release:
		case <-r.Context().Done():
		}
		return false
	}
	f.mu.Unlock()
	ticks <- f.clock().Add(time.Hour)
	await(t, entered)
	ctx := &observedContext{Context: incoming(signed(t, claims(f.clock()), "rotated", rotated, nil)), observed: make(chan struct{})}
	result := verifyAsync(v, ctx)
	await(t, ctx.observed)
	once.Do(func() { close(release) })
	if err := awaitError(t, result); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.hook = nil
	f.mu.Unlock()
	_, err = v.Verify(incoming(signed(t, claims(f.clock()), "initial", key, nil)))
	safeFailure(t, err)
	v.Close()
	await(t, stopped)
	_, err = v.Verify(incoming(signed(t, claims(f.clock()), "rotated", rotated, nil)))
	safeFailure(t, err)
	if f.offPin.Load() != 0 {
		t.Fatal("off-pin scheduled fetch")
	}
}

// Canceling either the initiator or another waiter must not cancel shared I/O;
// the lifecycle alone owns that flight and another live waiter still succeeds.
func TestRefreshInitiatorAndWaiterCancellation(t *testing.T) {
	f := fixture(t)
	v := f.verifier(t, nil)
	_, key := testKeys(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	var canceled atomic.Bool
	f.mu.Lock()
	f.keys = []map[string]any{jwk(key, "rotated")}
	f.hook = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != keysPath {
			return false
		}
		close(entered)
		select {
		case <-release:
		case <-r.Context().Done():
			canceled.Store(true)
			return true
		}
		return false
	}
	f.mu.Unlock()
	raw := signed(t, claims(f.clock()), "rotated", key, nil)
	leaderCtx, cancelLeader := context.WithCancel(incoming(raw))
	defer cancelLeader()
	leader := verifyAsync(v, leaderCtx)
	await(t, entered)
	waiterBase, cancelWaiter := context.WithCancel(incoming(raw))
	defer cancelWaiter()
	waiterCtx := &observedContext{Context: waiterBase, observed: make(chan struct{})}
	waiter := verifyAsync(v, waiterCtx)
	await(t, waiterCtx.observed)
	liveCtx := &observedContext{Context: incoming(raw), observed: make(chan struct{})}
	live := verifyAsync(v, liveCtx)
	await(t, liveCtx.observed)
	cancelLeader()
	cancelWaiter()
	for _, r := range []<-chan error{leader, waiter} {
		err := awaitError(t, r)
		safeFailure(t, err)
		if !errors.Is(err, context.Canceled) {
			t.Fatal("cancellation classification lost")
		}
	}
	once.Do(func() { close(release) })
	if err := awaitError(t, live); err != nil {
		t.Fatal("canceled RPC poisoned shared flight", err)
	}
	if canceled.Load() || f.requests.Load() != 4 {
		t.Fatal("refresh lifetime attached to RPC")
	}
}

// Background refresh failures reach the optional hook as fixed codes with the
// unextended snapshot expiry. The initial load does not (New returns it).
func TestRefreshErrorHook(t *testing.T) {
	key, other := testKeys(t)
	t.Run("initial load", func(t *testing.T) {
		f := fixture(t)
		f.status = http.StatusServiceUnavailable
		c := f.config()
		c.OnRefreshError = func(string, time.Time) { t.Error("initial load failure reached refresh hook") }
		v, err := New(context.Background(), c)
		if v != nil {
			v.Close()
		}
		safeFailure(t, err)
	})
	for _, tc := range []struct {
		name      string
		scheduled bool
		breakSet  func(*trustFixture)
		want      string
	}{
		{"scheduled outage", true, func(f *trustFixture) { f.status = http.StatusServiceUnavailable }, "fetch"},
		{"scheduled foreign issuer", true, func(f *trustFixture) { f.metadataIssuer = secret }, "discovery"},
		{"scheduled unsupported key", true, func(f *trustFixture) {
			k := jwk(other, secret)
			k["kty"] = "EC"
			f.keys = append(f.keys, k)
		}, "jwks"},
		{"unknown-key outage", false, func(f *trustFixture) { f.status = http.StatusServiceUnavailable }, "fetch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := fixture(t)
			type report struct {
				reason  string
				expires time.Time
			}
			reports := make(chan report, 4)
			c := f.config()
			c.OnRefreshError = func(reason string, expires time.Time) { reports <- report{reason, expires} }
			ticks := make(chan time.Time, 1)
			v, err := newVerifier(context.Background(), c, options{now: f.clock, schedule: func(time.Duration) (<-chan time.Time, func()) {
				return ticks, func() {}
			}})
			if err != nil {
				t.Fatal(err)
			}
			defer v.Close()
			expires := f.clock().Add(24 * time.Hour)
			f.mu.Lock()
			tc.breakSet(f)
			f.mu.Unlock()
			f.now.Add(int64(23 * time.Hour / time.Second))
			if tc.scheduled {
				ticks <- f.clock()
			} else {
				_, err := v.Verify(incoming(signed(t, claims(f.clock()), "unknown", key, nil)))
				safeFailure(t, err)
			}
			select {
			case r := <-reports:
				if r.reason != tc.want || strings.Contains(r.reason, secret) {
					t.Fatalf("refresh reason = %q, want fixed %q", r.reason, tc.want)
				}
				if !r.expires.Equal(expires) {
					t.Fatalf("reported expiry %v, want unextended %v", r.expires, expires)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("refresh failure not reported")
			}
			if _, err := v.Verify(incoming(signed(t, claims(f.clock()), "initial", key, nil))); err != nil {
				t.Fatal("failed refresh discarded good snapshot", err)
			}
		})
	}
}

// Close and parent cancellation cancel active trust I/O and join the worker.
func TestLifecycleCancellationDuringRefresh(t *testing.T) {
	for _, parentCancel := range []bool{false, true} {
		t.Run(fmt.Sprint("parent=", parentCancel), func(t *testing.T) {
			f := fixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			c := f.config()
			c.OnRefreshError = func(reason string, _ time.Time) { t.Errorf("shutdown reported as refresh failure %q", reason) }
			v, err := newVerifier(ctx, c, options{now: f.clock})
			if err != nil {
				t.Fatal(err)
			}
			defer v.Close()
			entered, networkCanceled := make(chan struct{}), make(chan struct{})
			f.mu.Lock()
			f.hook = func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != keysPath {
					return false
				}
				close(entered)
				<-r.Context().Done()
				close(networkCanceled)
				return true
			}
			f.mu.Unlock()
			key, _ := testKeys(t)
			result := verifyAsync(v, incoming(signed(t, claims(f.clock()), "unknown", key, nil)))
			await(t, entered)
			closed := make(chan struct{})
			go func() {
				if parentCancel {
					cancel()
				}
				v.Close()
				close(closed)
			}()
			await(t, networkCanceled)
			await(t, closed)
			safeFailure(t, awaitError(t, result))
		})
	}
}

// Token headers are data, never fetch targets, even on an unknown kid.
func TestTokenURLsAndIndependentCaches(t *testing.T) {
	f := fixture(t)
	first := f.verifier(t, nil)
	key, other := testKeys(t)
	headers := map[string]any{"jku": "https://attacker.invalid/" + secret, "x5u": "http://169.254.169.254/" + secret}
	if _, err := first.Verify(incoming(signed(t, claims(f.clock()), "initial", key, headers))); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.keys = []map[string]any{jwk(other, "initial")}
	f.mu.Unlock()
	second := f.verifier(t, nil)
	if _, err := second.Verify(incoming(signed(t, claims(f.clock()), "initial", other, nil))); err != nil {
		t.Fatal(err)
	}
	_, err := second.Verify(incoming(signed(t, claims(f.clock()), "initial", key, nil)))
	safeFailure(t, err)
	if _, err := first.Verify(incoming(signed(t, claims(f.clock()), "initial", key, nil))); err != nil {
		t.Fatal("cache crossed verifier boundaries", err)
	}
	_, err = first.Verify(incoming(signed(t, claims(f.clock()), "unknown", key, headers)))
	safeFailure(t, err)
	if f.requests.Load() != 6 || f.offPin.Load() != 0 {
		t.Fatal("token URL used, or missing bounded refresh")
	}
}

// The entire discovery+JWKS flight has one ten-second deadline, and copying the
// trusted client's configuration never mutates the host's client.
func TestFetchDeadlineAndClientCopy(t *testing.T) {
	f := fixture(t)
	base := f.client.Transport
	var deadlines []time.Time
	f.client.Timeout = time.Hour
	f.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		d, ok := r.Context().Deadline()
		if !ok || time.Until(d) > 10*time.Second {
			t.Error("trust fetch unbounded")
		}
		deadlines = append(deadlines, d)
		return base.RoundTrip(r)
	})
	v := f.verifier(t, nil)
	if len(deadlines) != 2 || !deadlines[0].Equal(deadlines[1]) {
		t.Fatal("timeout resets between discovery and JWKS")
	}
	if f.client.Timeout != time.Hour || f.client.CheckRedirect != nil {
		t.Fatal("host client mutated")
	}
	v.Close()
}
