package modeltransport

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func policyConfig(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	ledger := filepath.Join(dir, "budget.sqlite")
	config := filepath.Join(dir, "policy.json")
	data := fmt.Sprintf(`{"version":1,"runID":"test-run","ledgerPath":%q,"deployment":"test-deployment","pricing":{"inputMicroUSDPerMillionTokens":100000,"outputMicroUSDPerMillionTokens":500000,"extraMicroUSDPerCall":0,"source":"https://example.invalid/official-pricing","asOf":"2026-09-22"}}`, ledger)
	if err := os.WriteFile(config, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	return config, ledger
}
func openTestPolicy(t *testing.T) (*Policy, string, string) {
	t.Helper()
	config, ledger := policyConfig(t)
	p, err := OpenPolicyFile(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p, config, ledger
}
func boundedFixture(t *testing.T, p *Policy, h http.HandlerFunc, cred credentialFunc) (*http.Client, string) {
	t.Helper()
	s := httptest.NewTLSServer(h)
	t.Cleanup(s.Close)
	c, err := NewClient(Config{Endpoint: s.URL + "/openai/v1/", Deployment: "test-deployment", Credential: cred, Transport: s.Client().Transport.(*http.Transport), Policy: p})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.CloseIdleConnections)
	return c, s.URL + "/openai/v1/chat/completions"
}
func boundedSend(c *http.Client, target, body string) error {
	req, _ := http.NewRequest(http.MethodPost, target, strings.NewReader(body))
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	_, err = io.Copy(io.Discard, resp.Body)
	closeErr := resp.Body.Close()
	if err != nil {
		return err
	}
	return closeErr
}
func chat(text string, stream bool) string {
	b, _ := json.Marshal(map[string]any{"model": "test-deployment", "messages": []map[string]string{{"role": "user", "content": text}}, "stream": stream})
	return string(b)
}

const usageResponse = `{"choices":[{"message":{"role":"assistant","content":"hello"}}],"usage":{"prompt_tokens":12,"completion_tokens":4,"completion_tokens_details":{"reasoning_tokens":1}}}`

func ledgerRows(t *testing.T, path string) (int, string, sql.NullInt64, sql.NullInt64, sql.NullInt64) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	var outcome string
	var in, out, reason sql.NullInt64
	if err = db.QueryRow("SELECT count(*) FROM model_attempts").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n > 0 {
		if err = db.QueryRow("SELECT outcome,input_tokens,output_tokens,reasoning_tokens FROM model_attempts ORDER BY id DESC LIMIT 1").Scan(&outcome, &in, &out, &reason); err != nil {
			t.Fatal(err)
		}
	}
	return n, outcome, in, out, reason
}

// Removing cap injection or durable accounting changes the TLS request/ledger.
func TestPolicyCapsAndDurableTwoAttempts(t *testing.T) {
	p, config, ledger := openTestPolicy(t)
	var sends atomic.Int32
	c, target := boundedFixture(t, p, func(w http.ResponseWriter, r *http.Request) {
		sends.Add(1)
		var v map[string]any
		if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
			t.Error(err)
		}
		if v["max_completion_tokens"] != float64(4096) {
			t.Error("completion cap absent")
		}
		io.WriteString(w, usageResponse)
	}, goodCredential())
	if err := boundedSend(c, target, chat("first", false)); err != nil {
		t.Fatal(err)
	}
	if err := boundedSend(c, target, chat("first", false)); err == nil {
		t.Fatal("duplicate sent")
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenPolicyFile(config)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	c, target = boundedFixture(t, reopened, func(w http.ResponseWriter, r *http.Request) { sends.Add(1); io.WriteString(w, usageResponse) }, goodCredential())
	if err = boundedSend(c, target, chat("second", false)); err != nil {
		t.Fatal(err)
	}
	if err = boundedSend(c, target, chat("third", false)); err == nil {
		t.Fatal("third sent")
	}
	n, outcome, in, out, reason := ledgerRows(t, ledger)
	if n != 2 || sends.Load() != 2 || outcome != "succeeded" || !in.Valid || in.Int64 != 12 || out.Int64 != 4 || reason.Int64 != 1 {
		t.Fatalf("ledger: %d %s %v %v %v; sends %d", n, outcome, in, out, reason, sends.Load())
	}
	raw, err := os.ReadFile(ledger)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "first") || strings.Contains(string(raw), secret) {
		t.Fatal("sensitive data in ledger")
	}
}

// Every refusal must happen before credentials, not merely before POST.
func TestPolicyRejectsUnboundedRequestBeforeCredentials(t *testing.T) {
	cases := []string{chat(strings.Repeat("x", 8192), false), `{"model":"other","messages":[{"role":"user","content":"x"}]}`, `{"model":"test-deployment","messages":[{"role":"user","content":[{"type":"text","text":"x"}]}]}`, `{"model":"test-deployment","messages":[{"role":"tool","content":"x"}]}`, `{"model":"test-deployment","messages":[{"role":"user","content":"x"}],"tools":[]}`, `{"model":"test-deployment","messages":[{"role":"user","content":"x"}],"max_completion_tokens":9999}`, `{"model":"test-deployment","model":"other","messages":[]}`, `{"model":"test-deployment","messages":[{"role":"user","content":null}]}`}
	for i, body := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			p, _, ledger := openTestPolicy(t)
			var creds, sends atomic.Int32
			c, target := boundedFixture(t, p, func(http.ResponseWriter, *http.Request) { sends.Add(1) }, func(ctx context.Context, o policy.TokenRequestOptions) (azcore.AccessToken, error) {
				creds.Add(1)
				return goodCredential()(ctx, o)
			})
			if err := boundedSend(c, target, body); err == nil {
				t.Fatal("unsafe accepted")
			}
			n, _, _, _, _ := ledgerRows(t, ledger)
			if sends.Load() != 0 || creds.Load() != 0 || n != 0 {
				t.Fatal("refusal performed I/O/reservation")
			}
		})
	}
}
func TestPolicyStrictPricingAndImmutableSnapshot(t *testing.T) {
	changes := [][2]string{{`100000`, `0`}, {`100000`, `-1`}, {`100000`, `1.5`}, {`100000`, `9223372036854775807`}, {`500000`, `244000001`}, {`"extraMicroUSDPerCall":0`, `"extraMicroUSDPerCall":1`}, {`"extraMicroUSDPerCall":0,`, ``}, {`"asOf":"2026-09-22"`, `"asOf":"2026-02-30"`}, {`https://example.invalid`, `http://example.invalid`}, {`"version":1`, `"version":2`}, {`"version":1`, `"version":1,"currency":"USD"`}, {`"version":1`, `"version":1,"version":1`}}
	for _, change := range changes {
		t.Run(change[1], func(t *testing.T) {
			config, _ := policyConfig(t)
			data, _ := os.ReadFile(config)
			data = []byte(strings.Replace(string(data), change[0], change[1], 1))
			os.WriteFile(config, data, 0600)
			p, err := OpenPolicyFile(config)
			if err == nil {
				p.Close()
				t.Fatal("invalid config accepted")
			}
		})
	}
	p, config, _ := openTestPolicy(t)
	p.Close()
	data, _ := os.ReadFile(config)
	os.WriteFile(config, []byte(strings.Replace(string(data), "test-run", "different-run", 1)), 0600)
	if p, err := OpenPolicyFile(config); err == nil {
		p.Close()
		t.Fatal("snapshot changed")
	}
}
func TestPolicyUsageAndFailuresStopFutureSends(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		stream     bool
		status     int
		want       string
	}{
		{"plain", usageResponse, false, 200, "succeeded"}, {"missing", `{"choices":[]}`, false, 200, "unknown"}, {"null", `{"usage":{"prompt_tokens":null,"completion_tokens":null}}`, false, 200, "unknown"}, {"truncated", `{"usage":`, false, 200, "unknown"},
		{"stream", "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":12,\"completion_tokens\":4}}\n\ndata: [DONE]\n\n", true, 200, "succeeded"},
		{"stream-no-done", "data: {\"usage\":{\"prompt_tokens\":12,\"completion_tokens\":4}}\n\n", true, 200, "unknown"}, {"stream-no-usage", "data: [DONE]\n\n", true, 200, "unknown"}, {"throttle", "", false, 429, "failed"}, {"over-cap", `{"usage":{"prompt_tokens":8193,"completion_tokens":4}}`, false, 200, "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _, ledger := openTestPolicy(t)
			var sends atomic.Int32
			c, target := boundedFixture(t, p, func(w http.ResponseWriter, r *http.Request) {
				sends.Add(1)
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			}, goodCredential())
			err := boundedSend(c, target, chat("first", tc.stream))
			if tc.want == "succeeded" && err != nil {
				t.Fatal(err)
			}
			if tc.want != "succeeded" && err == nil {
				t.Fatal("uncertain accepted")
			}
			n, outcome, in, out, reason := ledgerRows(t, ledger)
			if n != 1 || outcome != tc.want {
				t.Fatalf("ledger %d %s", n, outcome)
			}
			if tc.name == "missing" || tc.name == "null" {
				if in.Valid || out.Valid || reason.Valid {
					t.Fatal("unknown recorded as zero")
				}
			}
			if tc.want != "succeeded" {
				if err = boundedSend(c, target, chat("second", tc.stream)); err == nil {
					t.Fatal("sent after failure")
				}
				if sends.Load() != 1 {
					t.Fatal("retried")
				}
			}
		})
	}
}
func TestPolicyDeadlineIncludesCredentialsAndBody(t *testing.T) {
	p, _, ledger := openTestPolicy(t)
	var credentialContext context.Context
	cred := credentialFunc(func(ctx context.Context, o policy.TokenRequestOptions) (azcore.AccessToken, error) {
		credentialContext = ctx
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 25*time.Second {
			t.Error("credential deadline missing")
		}
		return goodCredential()(ctx, o)
	})
	c, target := boundedFixture(t, p, func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}, cred)
	// Exercise the transport's deadline, not the client's duplicate timeout.
	c.Timeout = 0
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(chat("first", false)))
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("request did not reach response-body phase: %v", err)
	}
	defer resp.Body.Close()
	if credentialContext == nil || credentialContext.Err() != nil {
		t.Fatal("credential context ended before body consumption")
	}
	// Headers establish the body phase. A short setup timer could instead expire
	// during admission or credentials, where a failed (not unknown) row is valid.
	cancel()
	_, err = io.ReadAll(resp.Body)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("body cancellation not preserved: %v", err)
	}
	n, outcome, _, _, _ := ledgerRows(t, ledger)
	if n != 1 || outcome != "unknown" {
		t.Fatalf("ledger %d %s", n, outcome)
	}
}
