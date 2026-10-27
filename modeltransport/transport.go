// Package modeltransport authenticates sessions OpenAI Chat Completions requests
// with Azure workload identity, without API keys or a credential fallback chain.
package modeltransport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

const (
	DefaultScope  = "https://ai.azure.com/.default"
	refreshBefore = 2 * time.Minute
)

// Config pins the endpoint, audience, and deployment together. Use Endpoint and
// Deployment with sessions openai.WithBaseURL and WithModel, respectively. This
// transport constrains destinations. With Policy it also bounds Chat JSON and
// durably accounts for attempts; nil Policy retains legacy library behavior.
// Changing the tuple requires constructing a new transport; no audience probing occurs.
type Config struct {
	// Endpoint must be an HTTPS URL ending in /openai/v1/, without query or userinfo.
	Endpoint   string
	Scope      string // Empty selects DefaultScope.
	Deployment string
	// Credential is a trusted injection seam. Nil uses WorkloadIdentityCredential only.
	Credential azcore.TokenCredential
	// Transport optionally supplies trusted TLS/network settings, and is cloned.
	// HTTP/2 and connection reuse are disabled to prevent implicit POST replay.
	Transport *http.Transport
	// Policy optionally enforces bounded Chat requests and a durable run budget.
	Policy *Policy
	// CallSlot selects one declared v3 slot at trusted host construction time.
	// Requests cannot select slots. Empty is required for nil or legacy Policy.
	CallSlot string
}

// Transport is safe for concurrent use after construction. Bounded Policy use
// enforces 25 seconds through body reads. Without Policy, use NewClient for a
// two-minute overall timeout or bound direct RoundTrip contexts explicitly.
type Transport struct {
	endpoint   *url.URL
	scope      string
	credential azcore.TokenCredential
	base       *http.Transport
	now        func() time.Time
	mu         sync.Mutex
	token      azcore.AccessToken
	flight     *refresh
	policy     *Policy
	callSlot   string
}
type refresh struct {
	done  chan struct{}
	token azcore.AccessToken
	err   error
}

// NewTransport validates the destination before initializing workload identity.
// Credential construction errors are deliberately not wrapped: SDK errors can
// contain authentication response bodies or sensitive configuration.
func NewTransport(c Config) (*Transport, error) {
	u, err := url.Parse(c.Endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" ||
		u.Path != "/openai/v1/" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.TrimSpace(c.Deployment) == "" {
		return nil, errors.New("modeltransport: invalid endpoint or missing deployment")
	}
	if c.Scope == "" {
		c.Scope = DefaultScope
	}
	if strings.TrimSpace(c.Scope) != c.Scope || strings.ContainsAny(c.Scope, " \t\r\n") {
		return nil, errors.New("modeltransport: invalid scope")
	}
	if c.Policy != nil {
		c.Policy.mu.Lock()
		valid := !c.Policy.closed && c.Policy.ledger != nil && c.Policy.config.Deployment == c.Deployment && c.Policy.acceptsCallSlot(c.CallSlot)
		c.Policy.mu.Unlock()
		if !valid {
			return nil, errors.New("modeltransport: policy deployment, slot, or lifecycle mismatch")
		}
	}
	if c.Policy == nil && c.CallSlot != "" {
		return nil, errors.New("modeltransport: call slot requires a planned policy")
	}
	cred := c.Credential
	if cred == nil {
		cred, err = azidentity.NewWorkloadIdentityCredential(nil)
		if err != nil {
			return nil, errors.New("modeltransport: workload identity configuration unavailable")
		}
	}
	base := c.Transport
	if base == nil {
		base = &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
		}
	}
	base = base.Clone()
	// net/http may replay requests on reused connections, including POSTs with
	// GetBody or an idempotency header. Fresh HTTP/1 connections avoid that path;
	// HTTP/2 has independent internal retry paths, so it is deliberately disabled.
	base.DisableKeepAlives = true
	base.Protocols = new(http.Protocols)
	base.Protocols.SetHTTP1(true)
	return &Transport{endpoint: u, scope: c.Scope, credential: cred, base: base, now: time.Now, policy: c.Policy, callSlot: c.CallSlot}, nil
}

// NewClient returns a bounded client that refuses every redirect. RoundTrip also
// rejects redirect statuses so the policy survives client wrappers or replacement.
func NewClient(c Config) (*http.Client, error) {
	transport, err := NewTransport(c)
	if err != nil {
		return nil, err
	}
	timeout := 2 * time.Minute
	if c.Policy != nil {
		timeout = modelTimeout
	}
	return &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("modeltransport: redirects refused")
	}}, nil
}

// RoundTrip clones the request and headers before replacing caller credentials.
// It never retries a model request or returns provider/credential error text.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	sent := false
	defer func() {
		if !sent && req != nil && req.Body != nil {
			_ = req.Body.Close()
		}
	}()
	if req == nil || req.URL == nil || !t.allowed(req) {
		return nil, errors.New("modeltransport: destination refused")
	}
	if err := req.Context().Err(); err != nil {
		return nil, err
	}
	if t.policy != nil {
		return t.policyRoundTrip(req)
	}
	token, err := t.accessToken(req.Context())
	if err != nil {
		return nil, err
	}
	if err := req.Context().Err(); err != nil {
		return nil, err
	}
	clone := req.Clone(req.Context())
	if clone.Header == nil {
		clone.Header = make(http.Header)
	}
	for name := range clone.Header {
		if strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "api-key") || strings.EqualFold(name, "x-api-key") {
			delete(clone.Header, name)
		}
	}
	clone.Header.Set("Authorization", "Bearer "+token.Token)
	sent = true
	resp, err := t.base.RoundTrip(clone)
	if err != nil {
		return nil, safeError(req.Context(), "modeltransport: request failed")
	}
	// The sessions Chat Completions adapter embeds bodies for ALL non-200
	// statuses, not only 4xx/5xx. Reject before it can read any provider detail.
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("modeltransport: provider returned HTTP %d", resp.StatusCode)
	}
	resp.Body = &safeBody{ReadCloser: resp.Body, ctx: req.Context()}
	return resp, nil
}

func (t *Transport) allowed(req *http.Request) bool {
	u := req.URL
	if u.Scheme != "https" || !strings.EqualFold(u.Hostname(), t.endpoint.Hostname()) || port(u) != port(t.endpoint) ||
		u.User != nil || u.Opaque != "" || u.Fragment != "" || (req.Host != "" && !strings.EqualFold(req.Host, u.Host)) {
		return false
	}
	// Reject normalization ambiguities rather than relying on the provider or a
	// proxy to decode, clean, or double-decode a different security boundary.
	return strings.HasPrefix(u.Path, "/openai/v1/") && u.EscapedPath() == u.Path &&
		!strings.ContainsAny(u.Path, "\\%") && path.Clean(u.Path) == strings.TrimSuffix(u.Path, "/")
}
func port(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	return "443"
}

func (t *Transport) accessToken(ctx context.Context) (azcore.AccessToken, error) {
	t.mu.Lock()
	if t.token.ExpiresOn.After(t.now().Add(refreshBefore)) {
		token := t.token
		t.mu.Unlock()
		return token, nil
	}
	if f := t.flight; f != nil {
		t.mu.Unlock()
		select {
		case <-ctx.Done():
			return azcore.AccessToken{}, ctx.Err()
		case <-f.done:
			return f.token, f.err
		}
	}
	f := &refresh{done: make(chan struct{})}
	t.flight = f
	t.mu.Unlock()
	token, err := t.credential.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{t.scope}})
	if err != nil {
		err = safeError(ctx, "modeltransport: token acquisition failed")
	} else if !validBearer(token.Token) || !token.ExpiresOn.After(t.now().Add(refreshBefore)) {
		err = errors.New("modeltransport: no usable access token")
	}
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	t.mu.Lock()
	if err == nil {
		t.token = token
		f.token = token
	}
	f.err = err
	t.flight = nil
	close(f.done)
	t.mu.Unlock()
	return f.token, f.err
}
func validBearer(token string) bool {
	if token == "" {
		return false
	}
	for _, c := range token {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~+/=", c)) {
			return false
		}
	}
	return true
}
func safeError(ctx context.Context, message string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return errors.New(message)
}

// Body reads can fail after RoundTrip succeeds (for example, malformed chunked
// trailers include server-controlled text in net/http errors). Sanitize those
// errors too, while preserving EOF and context cancellation/deadline semantics.
type safeBody struct {
	io.ReadCloser
	ctx context.Context
}

func (b *safeBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil && err != io.EOF {
		err = safeError(b.ctx, "modeltransport: response read failed")
	}
	return n, err
}
func (b *safeBody) Close() error {
	if err := b.ReadCloser.Close(); err != nil {
		return safeError(b.ctx, "modeltransport: response close failed")
	}
	return nil
}

// CloseIdleConnections releases any idle network resources owned by this transport.
func (t *Transport) CloseIdleConnections() { t.base.CloseIdleConnections() }
