package entraauth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"time"
)

const maxResponseBytes = 1024 * 1024

type refreshFlight struct {
	done chan struct{}
	err  error
}

func (v *Verifier) run(ticks <-chan time.Time, stop func()) {
	defer v.wg.Done()
	defer stop()
	for {
		select {
		case <-v.ctx.Done():
			return
		case <-ticks:
			v.mu.Lock()
			v.startRefreshLocked(false)
			v.mu.Unlock()
		}
	}
}

// One lifecycle-owned flight serves scheduled and unknown-key refreshes. An RPC
// only waits: canceling even the initiating RPC cannot poison other waiters.
// The unknown-key cooldown is independent of initial and scheduled loads.
func (v *Verifier) startRefreshLocked(unknown bool) *refreshFlight {
	if v.closed || v.ctx.Err() != nil {
		return nil
	}
	if v.flight != nil {
		return v.flight
	}
	now := v.now()
	if unknown {
		if now.Before(v.nextUnknown) {
			return nil
		}
		v.nextUnknown = now.Add(5 * time.Minute)
	}
	f := &refreshFlight{done: make(chan struct{})}
	v.flight = f
	v.wg.Add(1)
	go func() {
		defer v.wg.Done()
		keys, err := v.fetchKeys()
		v.mu.Lock()
		closed := v.ctx.Err() != nil
		if closed {
			err = failure("closed")
		}
		if err == nil {
			// Replace atomically. A failure leaves the original expiry untouched.
			v.keys = keys
			v.expires = v.now().Add(24 * time.Hour)
		}
		f.err = err
		v.flight = nil
		expires := v.expires
		close(f.done)
		v.mu.Unlock()
		// Report outside the lock; Close waits for this goroutine, hook included.
		// fetchKeys returns only fixed-code failures, never raw network text.
		if e, ok := err.(*verificationError); ok && !closed && v.config.OnRefreshError != nil {
			v.config.OnRefreshError(e.reason, expires)
		}
	}()
	return f
}

func (v *Verifier) key(ctx context.Context, kid string) (*rsa.PublicKey, time.Time, error) {
	v.mu.Lock()
	if v.closed || v.ctx.Err() != nil {
		v.mu.Unlock()
		return nil, time.Time{}, failure("closed")
	}
	if key := v.keys[kid]; key != nil && v.now().Before(v.expires) {
		expires := v.expires
		v.mu.Unlock()
		return key, expires, nil
	}
	f := v.startRefreshLocked(true)
	v.mu.Unlock()
	if f == nil {
		return nil, time.Time{}, failure("key_unavailable")
	}
	select {
	case <-ctx.Done():
		return nil, time.Time{}, contextFailure(ctx)
	case <-v.ctx.Done():
		return nil, time.Time{}, failure("closed")
	case <-f.done:
	}
	if f.err != nil {
		return nil, time.Time{}, f.err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if key := v.keys[kid]; key != nil && v.now().Before(v.expires) {
		return key, v.expires, nil
	}
	return nil, time.Time{}, failure("key_unavailable")
}

type jwkKey struct {
	Kty    string   `json:"kty"`
	Kid    string   `json:"kid"`
	Use    string   `json:"use"`
	Alg    string   `json:"alg"`
	KeyOps []string `json:"key_ops"`
	N      string   `json:"n"`
	E      string   `json:"e"`
}

func (v *Verifier) fetchKeys() (map[string]*rsa.PublicKey, error) {
	ctx, cancel := context.WithTimeout(v.ctx, fetchTimeout)
	defer cancel()
	var metadata struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	origin := "https://login.microsoftonline.com/" + v.config.TenantID
	if err := v.getJSON(ctx, origin+"/v2.0/.well-known/openid-configuration", &metadata); err != nil {
		return nil, err
	}
	// Exact comparison excludes aliases, foreign tenants, alternate ports,
	// queries, credentials, encoded paths and redirects without URL normalization.
	if metadata.Issuer != v.config.Issuer || metadata.JWKSURI != origin+"/discovery/v2.0/keys" {
		return nil, failure("discovery")
	}
	var set struct {
		Keys []jwkKey `json:"keys"`
	}
	if err := v.getJSON(ctx, metadata.JWKSURI, &set); err != nil {
		return nil, err
	}
	if len(set.Keys) == 0 || len(set.Keys) > 100 {
		return nil, failure("jwks")
	}
	keys := make(map[string]*rsa.PublicKey, len(set.Keys))
	for _, k := range set.Keys {
		if k.Kty != "RSA" || k.Kid == "" || len(k.Kid) > maxKidBytes || keys[k.Kid] != nil ||
			(k.Use != "" && k.Use != "sig") || (k.Alg != "" && k.Alg != "RS256") ||
			(len(k.KeyOps) != 0 && (len(k.KeyOps) != 1 || k.KeyOps[0] != "verify")) {
			return nil, failure("jwks")
		}
		n, ok := keyInteger(k.N, 1024)
		if !ok || n.BitLen() < 2048 || n.Bit(0) != 1 {
			return nil, failure("jwks")
		}
		e, ok := keyInteger(k.E, 4)
		if !ok || e.BitLen() > 31 || e.Int64() < 3 || e.Bit(0) != 1 {
			return nil, failure("jwks")
		}
		keys[k.Kid] = &rsa.PublicKey{N: n, E: int(e.Int64())}
	}
	return keys, nil
}
func keyInteger(s string, maxBytes int) (*big.Int, bool) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || len(b) == 0 || len(b) > maxBytes || b[0] == 0 {
		return nil, false
	}
	return new(big.Int).SetBytes(b), true
}
func (v *Verifier) getJSON(ctx context.Context, target string, dest any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return failure("discovery")
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return failure("fetch")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return failure("fetch")
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil || len(b) > maxResponseBytes {
		return failure("fetch")
	}
	if json.Unmarshal(b, dest) != nil {
		return failure("discovery")
	}
	return nil
}
