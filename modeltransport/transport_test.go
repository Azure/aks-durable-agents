package modeltransport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

const secret = "fake-secret-never-in-errors"

type credentialFunc func(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error)

func (f credentialFunc) GetToken(ctx context.Context, o policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return f(ctx, o)
}
func goodCredential() credentialFunc {
	return func(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
		return azcore.AccessToken{Token: secret, ExpiresOn: time.Now().Add(time.Hour)}, nil
	}
}

func fixture(t *testing.T, handler http.HandlerFunc, cred azcore.TokenCredential) (*http.Client, *httptest.Server) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	client, err := NewClient(Config{Endpoint: server.URL + "/openai/v1/", Deployment: "test-deployment", Credential: cred, Transport: server.Client().Transport.(*http.Transport)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)
	return client, server
}
func request(t *testing.T, client *http.Client, ctx context.Context, target string) error {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(`{"model":"test-deployment"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if resp != nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	return err
}

// Removing header replacement or cloning must fail this test at the actual TLS receiver.
func TestBearerReplacesCallerCredentialsWithoutMutation(t *testing.T) {
	client, server := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Values("Authorization"); len(got) != 1 || got[0] != "Bearer "+secret {
			t.Errorf("wrong authorization header")
		}
		if r.Header.Get("api-key") != "" || r.Header.Get("x-api-key") != "" {
			t.Error("caller key leaked")
		}
		if r.Header.Get("X-Trace") != "keep" {
			t.Error("ordinary header lost")
		}
		if r.ProtoMajor != 1 {
			t.Error("retry-sensitive request negotiated HTTP/2")
		}
	}, goodCredential())
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/openai/v1/chat/completions", strings.NewReader("{}"))
	req.Header = http.Header{"authorization": {"caller"}, "API-KEY": {"caller-key"}, "X-Api-Key": {"other-key"}, "X-Trace": {"keep"}}
	resp, err := client.Transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	//lint:ignore SA1008 Deliberately noncanonical caller keys exercise case-insensitive scrubbing and cloning.
	if req.Header["authorization"][0] != "caller" || req.Header["API-KEY"][0] != "caller-key" {
		t.Fatal("original request mutated")
	}
	if client.Timeout != 2*time.Minute {
		t.Fatalf("timeout = %s", client.Timeout)
	}
}

// A refresh made too late, skipped, or made for the wrong audience changes observed bearer headers.
func TestRefreshBeforeExpiry(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	var calls int
	cred := credentialFunc(func(_ context.Context, o policy.TokenRequestOptions) (azcore.AccessToken, error) {
		calls++
		if len(o.Scopes) != 1 || o.Scopes[0] != "https://ai.azure.com/.default" {
			t.Error("wrong default scope")
		}
		return azcore.AccessToken{Token: fmt.Sprintf("token-%d", calls), ExpiresOn: now.Add(10 * time.Minute)}, nil
	})
	var seen []string
	client, server := fixture(t, func(w http.ResponseWriter, r *http.Request) { seen = append(seen, r.Header.Get("Authorization")) }, cred)
	transport := client.Transport.(*Transport)
	transport.now = func() time.Time { return now }
	for _, advance := range []time.Duration{0, 7 * time.Minute, time.Minute} {
		now = now.Add(advance)
		if err := request(t, client, context.Background(), server.URL+"/openai/v1/chat/completions"); err != nil {
			t.Fatal(err)
		}
	}
	if fmt.Sprint(seen) != "[Bearer token-1 Bearer token-1 Bearer token-2]" {
		t.Fatalf("refresh sequence: %v", seen)
	}
}

// Credential errors, invalid tokens, and cancellation must never reach the model server.
func TestAuthenticationFailureSendsNothing(t *testing.T) {
	for _, tc := range []struct {
		name, token  string
		expiry       time.Duration
		fail, cancel bool
	}{
		{name: "credential error", fail: true}, {name: "empty token", expiry: time.Hour},
		{name: "expired", token: secret, expiry: -time.Minute}, {name: "refresh boundary", token: secret, expiry: 2 * time.Minute},
		{name: "invalid bearer", token: secret + "\r\nInjected: value", expiry: time.Hour},
		{name: "cancelled", cancel: true, token: secret, expiry: time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var sends atomic.Int32
			now := time.Now()
			cred := credentialFunc(func(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
				if tc.fail {
					return azcore.AccessToken{}, errors.New("provider body " + secret)
				}
				return azcore.AccessToken{Token: tc.token, ExpiresOn: now.Add(tc.expiry)}, nil
			})
			client, server := fixture(t, func(http.ResponseWriter, *http.Request) { sends.Add(1) }, cred)
			client.Transport.(*Transport).now = func() time.Time { return now }
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancel {
				cancel()
			}
			err := request(t, client, ctx, server.URL+"/openai/v1/chat/completions")
			if err == nil || strings.Contains(err.Error(), secret) {
				t.Fatal("missing or unsafe error")
			}
			if tc.cancel && !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation classification lost")
			}
			if sends.Load() != 0 {
				t.Fatal("sent without usable credential")
			}
		})
	}
}

// observedContext synchronizes entry into the cancelable refresh wait without
// sleeps, scheduler assumptions, or production test hooks.
type observedContext struct {
	context.Context
	observed chan struct{}
	once     sync.Once
}

func (c *observedContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.observed) })
	return c.Context.Done()
}

// Removing inflight sharing duplicates token fetches; sharing only successes
// makes overlapping failures issue serialized refreshes instead.
func TestConcurrentRefreshCoalesced(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint("failure=", fail), func(t *testing.T) {
			var calls, sends atomic.Int32
			entered, release := make(chan struct{}), make(chan struct{})
			cred := credentialFunc(func(ctx context.Context, o policy.TokenRequestOptions) (azcore.AccessToken, error) {
				if calls.Add(1) == 1 {
					close(entered)
				}
				<-release
				if fail {
					return azcore.AccessToken{}, errors.New(secret)
				}
				return goodCredential()(ctx, o)
			})
			client, server := fixture(t, func(http.ResponseWriter, *http.Request) { sends.Add(1) }, cred)
			var wg sync.WaitGroup
			send := func(ctx context.Context) {
				defer wg.Done()
				req, _ := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/openai/v1/chat/completions", strings.NewReader("{}"))
				resp, err := client.Transport.RoundTrip(req)
				if resp != nil {
					_ = resp.Body.Close()
				}
				if fail && (err == nil || strings.Contains(err.Error(), secret)) {
					t.Error("missing or unsafe shared failure")
				}
				if !fail && err != nil {
					t.Error(err)
				}
			}
			wg.Add(1)
			go send(context.Background())
			<-entered
			for range 12 {
				ctx := &observedContext{Context: context.Background(), observed: make(chan struct{})}
				wg.Add(1)
				go send(ctx)
				select {
				case <-ctx.observed:
				case <-time.After(time.Second):
					t.Error("waiter did not join refresh")
				}
			}
			close(release)
			wg.Wait()
			wantSends := int32(13)
			if fail {
				wantSends = 0
			}
			if calls.Load() != 1 || sends.Load() != wantSends {
				t.Fatalf("refreshes=%d sends=%d", calls.Load(), sends.Load())
			}
		})
	}
}

// Canceled waiters must not wait for the credential holder or send with its eventual token.
func TestCancellationDuringRefresh(t *testing.T) {
	var sends atomic.Int32
	entered, release := make(chan struct{}), make(chan struct{})
	cred := credentialFunc(func(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
		close(entered)
		<-release
		return goodCredential()(context.Background(), policy.TokenRequestOptions{})
	})
	client, server := fixture(t, func(http.ResponseWriter, *http.Request) { sends.Add(1) }, cred)
	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderDone := make(chan error, 1)
	go func() { leaderDone <- request(t, client, leaderCtx, server.URL+"/openai/v1/chat/completions") }()
	<-entered
	waiterCtx, cancelWaiter := context.WithCancel(context.Background())
	observed := &observedContext{Context: waiterCtx, observed: make(chan struct{})}
	waiterDone := make(chan error, 1)
	go func() {
		req, _ := http.NewRequestWithContext(observed, http.MethodPost, server.URL+"/openai/v1/chat/completions", nil)
		_, err := client.Transport.RoundTrip(req)
		waiterDone <- err
	}()
	<-observed.observed
	cancelWaiter()
	select {
	case err := <-waiterDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Error("canceled waiter blocked")
	}
	cancelLeader()
	close(release)
	if err := <-leaderDone; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if sends.Load() != 0 {
		t.Fatal("canceled request sent")
	}
}

// Refresh failure must not fall back to a cached, still unexpired token inside the refresh window.
func TestRefreshFailureDoesNotUseStaleToken(t *testing.T) {
	now := time.Now()
	var calls, sends int
	cred := credentialFunc(func(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
		calls++
		if calls > 1 {
			return azcore.AccessToken{}, errors.New(secret)
		}
		return azcore.AccessToken{Token: secret, ExpiresOn: now.Add(10 * time.Minute)}, nil
	})
	client, server := fixture(t, func(http.ResponseWriter, *http.Request) { sends++ }, cred)
	client.Transport.(*Transport).now = func() time.Time { return now }
	if err := request(t, client, context.Background(), server.URL+"/openai/v1/chat/completions"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(9 * time.Minute)
	if err := request(t, client, context.Background(), server.URL+"/openai/v1/chat/completions"); err == nil {
		t.Fatal("refresh failure ignored")
	}
	if sends != 1 {
		t.Fatal("stale token sent")
	}
}

// Authorization is never attached to wrong-origin, ambiguous-path, or Host-overridden requests.
func TestDestinationRestrictions(t *testing.T) {
	var sends atomic.Int32
	client, server := fixture(t, func(http.ResponseWriter, *http.Request) { sends.Add(1) }, goodCredential())
	other := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { sends.Add(1) }))
	defer other.Close()
	for _, suffix := range []string{"/other", "/openai/v10/chat", "/openai/v1", "/openai/v1/../secret", "/openai/v1/%2e%2e/secret", "/openai/v1/%252e%252e/secret", "/openai/v1/a%2fb", "/openai/v1/a\\b", "/openai/v1//chat"} {
		t.Run(suffix, func(t *testing.T) {
			if err := request(t, client, context.Background(), server.URL+suffix); err == nil {
				t.Fatal("unsafe path accepted")
			}
		})
	}
	for _, target := range []string{other.URL + "/openai/v1/chat/completions", strings.Replace(server.URL, "https:", "http:", 1) + "/openai/v1/chat/completions"} {
		if err := request(t, client, context.Background(), target); err == nil {
			t.Fatal("wrong origin accepted")
		}
	}
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/openai/v1/chat/completions", nil)
	req.Host = "elsewhere.example"
	if _, err := client.Do(req); err == nil {
		t.Fatal("Host override accepted")
	}
	if sends.Load() != 0 {
		t.Fatal("forbidden destination reached")
	}
}

// Even same-origin redirects and retryable provider statuses must cause only one send, with no body leakage.
func TestNon200ResponsesAreSanitizedWithoutRetry(t *testing.T) {
	for _, status := range []int{201, 202, 204, 206, 301, 302, 303, 307, 308, 400, 401, 429, 500, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var sends atomic.Int32
			client, server := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				sends.Add(1)
				w.Header().Set("Location", "/openai/v1/redirect")
				w.WriteHeader(status)
				_, _ = io.WriteString(w, "provider-body-"+secret)
			}, goodCredential())
			err := request(t, client, context.Background(), server.URL+"/openai/v1/chat/completions")
			if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "provider-body") {
				t.Fatal("missing or unsafe status error")
			}
			if sends.Load() != 1 {
				t.Fatal("redirect or retry sent")
			}
		})
	}
}

// A dropped POST must not be resent, even with a replayable body and idempotency marker.
func TestDisconnectedPOSTIsNotRetried(t *testing.T) {
	var sends atomic.Int32
	client, server := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		sends.Add(1)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		_ = conn.Close()
	}, goodCredential())
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/openai/v1/chat/completions", strings.NewReader("{}"))
	req.Header.Set("Idempotency-Key", "test")
	if _, err := client.Do(req); err == nil {
		t.Fatal("disconnect ignored")
	}
	if sends.Load() != 1 {
		t.Fatal("POST replayed")
	}
}

func TestInvalidConfigurationAndNoCredentialFallback(t *testing.T) {
	for _, endpoint := range []string{"", "http://example.com/openai/v1/", "https://example.com/", "https://user:pass@example.com/openai/v1/", "https://example.com/openai/v1/?key=secret", "https://example.com/openai/v1/#fragment"} {
		if _, err := NewClient(Config{Endpoint: endpoint, Deployment: "test", Credential: goodCredential()}); err == nil {
			t.Errorf("accepted invalid endpoint %q", endpoint)
		}
	}
	if _, err := NewClient(Config{Endpoint: "https://example.com/openai/v1/", Credential: goodCredential()}); err == nil {
		t.Error("accepted missing deployment")
	}
	t.Setenv("AZURE_CLIENT_ID", "")
	t.Setenv("AZURE_TENANT_ID", "")
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", "")
	if _, err := NewClient(Config{Endpoint: "https://example.com/openai/v1/", Deployment: "test"}); err == nil {
		t.Error("missing workload identity did not fail closed")
	}
}
