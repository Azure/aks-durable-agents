package modeltransport

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

func runConfig(t *testing.T, n int) RunConfig {
	t.Helper()
	zero := int64(0)
	c := RunConfig{RunID: "run", LedgerPath: filepath.Join(t.TempDir(), "budget.sqlite"), PlanDigest: "sha256:" + strings.Repeat("a", 64), Bindings: []RunBinding{{ID: "candidate", Endpoint: "https://example.invalid/openai/v1/", Scope: DefaultScope, Deployment: "test-deployment", Pricing: RunPricing{Input: 100000, Output: 500000, Extra: &zero, Source: "https://example.invalid/prices", AsOf: "2026-09-22"}}}}
	for i := 0; i < n; i++ {
		c.Slots = append(c.Slots, RunSlot{ID: fmt.Sprintf("case/%d", i), BindingID: "candidate"})
	}
	return c
}
func openRun(t *testing.T, c RunConfig) *Policy {
	t.Helper()
	p, err := OpenRunPolicy(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	return p
}

// Omitting inventory, provenance or full-price validation would admit an unreserved run.
func TestRunPolicyPreflight(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*RunConfig)
		ok     bool
	}{
		{"one", func(*RunConfig) {}, true},
		{"64", func(c *RunConfig) {
			for i := 1; i < 64; i++ {
				c.Slots = append(c.Slots, RunSlot{ID: fmt.Sprint(i), BindingID: "candidate"})
			}
		}, true},
		{"64-bindings", func(c *RunConfig) {
			for i := 1; i < 64; i++ {
				b := c.Bindings[0]
				b.ID = fmt.Sprint(i)
				c.Bindings = append(c.Bindings, b)
				c.Slots = append(c.Slots, RunSlot{ID: b.ID, BindingID: b.ID})
			}
		}, true},
		{"zero", func(c *RunConfig) { c.Slots = nil }, false},
		{"65", func(c *RunConfig) {
			for i := 1; i < 65; i++ {
				c.Slots = append(c.Slots, RunSlot{ID: fmt.Sprint(i), BindingID: "candidate"})
			}
		}, false},
		{"duplicate-slot", func(c *RunConfig) { c.Slots = append(c.Slots, c.Slots[0]) }, false},
		{"duplicate-binding", func(c *RunConfig) { c.Bindings = append(c.Bindings, c.Bindings[0]) }, false},
		{"unused-binding", func(c *RunConfig) { b := c.Bindings[0]; b.ID = "unused"; c.Bindings = append(c.Bindings, b) }, false},
		{"no-binding", func(c *RunConfig) { c.Bindings = nil }, false},
		{"unknown-binding", func(c *RunConfig) { c.Slots[0].BindingID = "other" }, false},
		{"id128", func(c *RunConfig) { c.Slots[0].ID = strings.Repeat("x", 128) }, true},
		{"id129", func(c *RunConfig) { c.Slots[0].ID = strings.Repeat("x", 129) }, false},
		{"empty-id", func(c *RunConfig) { c.Bindings[0].ID = ""; c.Slots[0].BindingID = "" }, false},
		{"unicode-id", func(c *RunConfig) { c.Slots[0].ID = "é" }, false},
		{"binding-id", func(c *RunConfig) { c.Bindings[0].ID = "bad id" }, false},
		{"run", func(c *RunConfig) { c.RunID = " run" }, false},
		{"long-run", func(c *RunConfig) { c.RunID = strings.Repeat("a", 257) }, false},
		{"path", func(c *RunConfig) { c.LedgerPath = "relative" }, false},
		{"unclean-path", func(c *RunConfig) { c.LedgerPath += "/../other" }, false},
		{"digest-case", func(c *RunConfig) { c.PlanDigest = "sha256:" + strings.Repeat("A", 64) }, false},
		{"digest-prefix", func(c *RunConfig) { c.PlanDigest = strings.Repeat("a", 64) }, false},
		{"endpoint", func(c *RunConfig) { c.Bindings[0].Endpoint = "http://example.invalid/openai/v1/" }, false},
		{"endpoint-query", func(c *RunConfig) { c.Bindings[0].Endpoint += "?" }, false},
		{"scope", func(c *RunConfig) { c.Bindings[0].Scope = "" }, false},
		{"scope-space", func(c *RunConfig) { c.Bindings[0].Scope = "a b" }, false},
		{"scope-unicode-space", func(c *RunConfig) { c.Bindings[0].Scope = "a\u00a0b" }, false},
		{"scope-control-space", func(c *RunConfig) { c.Bindings[0].Scope = "a\fb" }, false},
		{"deployment", func(c *RunConfig) { c.Bindings[0].Deployment = " " }, false},
		{"input", func(c *RunConfig) { c.Bindings[0].Pricing.Input = 0 }, false},
		{"output", func(c *RunConfig) { c.Bindings[0].Pricing.Output = -1 }, false},
		{"extra-omitted", func(c *RunConfig) { c.Bindings[0].Pricing.Extra = nil }, false},
		{"extra", func(c *RunConfig) { *c.Bindings[0].Pricing.Extra = 1 }, false},
		{"source", func(c *RunConfig) { c.Bindings[0].Pricing.Source = "http://example.invalid" }, false},
		{"date", func(c *RunConfig) { c.Bindings[0].Pricing.AsOf = "2026-02-30" }, false},
		{"input-bound", func(c *RunConfig) { v := 8192; c.MaxInputTokens = &v }, false},
		{"large-input", func(c *RunConfig) { v := 32768; c.MaxInputTokens = &v }, true},
		{"large-input-cap", func(c *RunConfig) {
			v := 32768
			c.MaxInputTokens = &v
			c.Bindings[0].Pricing.Input = 100000000
			c.Bindings[0].Pricing.Output = 100000000
		}, false},
		{"snapshot-bound", func(c *RunConfig) {
			c.Bindings[0].Pricing.Source = "https://example.invalid/" + strings.Repeat("x", 65536)
		}, false},
		// 8192*1 + 4096*488281248 = 2,000,000,000,000 exactly.
		{"exact-USD2", func(c *RunConfig) { c.Bindings[0].Pricing.Input = 1; c.Bindings[0].Pricing.Output = 488281248 }, true},
		{"smallest-excess", func(c *RunConfig) { c.Bindings[0].Pricing.Input = 1; c.Bindings[0].Pricing.Output = 488281249 }, false},
		{"overflow", func(c *RunConfig) {
			c.Bindings[0].Pricing.Input = math.MaxInt64
			c.Bindings[0].Pricing.Output = math.MaxInt64
		}, false},
		{"candidate-cap-alone", func(c *RunConfig) { c.Bindings[0].Pricing.Input = 50000000; c.Bindings[0].Pricing.Output = 50000000 }, true},
		{"judge-cap-alone", func(c *RunConfig) { c.Bindings[0].Pricing.Input = 200000000; c.Bindings[0].Pricing.Output = 1 }, true},
		// 614,400,000,000 + 1,638,400,004,096 exceeds USD2; pricing both
		// slots at the cheaper candidate rate would wrongly admit the run.
		{"combined-cap", func(c *RunConfig) {
			c.Bindings[0].Pricing.Input = 50000000
			c.Bindings[0].Pricing.Output = 50000000
			b := c.Bindings[0]
			b.ID = "judge"
			b.Endpoint = "https://judge.invalid/openai/v1/"
			b.Pricing.Input, b.Pricing.Output = 200000000, 1
			c.Bindings = append(c.Bindings, b)
			c.Slots = append(c.Slots, RunSlot{ID: "judge", BindingID: "judge"})
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := runConfig(t, 1)
			originalPath := c.LedgerPath
			tc.change(&c)
			if err := ValidateRunConfig(c); (err == nil) != tc.ok {
				t.Fatalf("pure validation: %v", err)
			}
			if _, err := os.Stat(originalPath); !os.IsNotExist(err) {
				t.Fatal("pure validation opened ledger", err)
			}
			p, err := OpenRunPolicy(c)
			if p != nil {
				defer p.Close()
			}
			if (err == nil) != tc.ok {
				t.Fatalf("open accepted=%v: %v", tc.ok, err)
			}
			if !tc.ok {
				if _, err := os.Stat(originalPath); !os.IsNotExist(err) {
					t.Fatal("refusal created ledger", err)
				}
			} else if p.AttemptLimit() != len(c.Slots) {
				t.Fatal("inventory count changed")
			}
		})
	}
}

func runClient(t *testing.T, p *Policy, c RunConfig, i int, s *httptest.Server, creds *atomic.Int32) *http.Client {
	t.Helper()
	slot := c.Slots[i]
	var b RunBinding
	for _, v := range c.Bindings {
		if v.ID == slot.BindingID {
			b = v
		}
	}
	client, err := NewClient(Config{Endpoint: b.Endpoint, Scope: b.Scope, Deployment: b.Deployment, Policy: p, CallSlot: slot.ID, Transport: s.Client().Transport.(*http.Transport), Credential: credentialFunc(func(ctx context.Context, o policy.TokenRequestOptions) (azcore.AccessToken, error) {
		creds.Add(1)
		if len(o.Scopes) != 1 || o.Scopes[0] != b.Scope {
			t.Error("wrong binding scope", o.Scopes)
		}
		return goodCredential()(ctx, o)
	})})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)
	return client
}

// Ignoring any frozen tuple member must fail before credential construction, not only GetToken.
func TestRunPolicySelectorBeforeCredentials(t *testing.T) {
	t.Setenv("AZURE_TENANT_ID", "")
	t.Setenv("AZURE_CLIENT_ID", "")
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", "")
	c := runConfig(t, 1)
	p := openRun(t, c)
	base := Config{Endpoint: c.Bindings[0].Endpoint, Scope: DefaultScope, Deployment: "test-deployment", Policy: p, CallSlot: c.Slots[0].ID}
	for _, change := range []func(*Config){func(c *Config) { c.Endpoint = "https://other.invalid/openai/v1/" }, func(c *Config) { c.Scope = "https://other.invalid/.default" }, func(c *Config) { c.Deployment = "other" }, func(c *Config) { c.CallSlot = "other" }, func(c *Config) { c.CallSlot = "" }} {
		v := base
		change(&v)
		_, err := NewTransport(v)
		if err == nil || !strings.Contains(err.Error(), "mismatch") {
			t.Fatal("did not reject before credential construction", err)
		}
	}
	base.Credential = goodCredential()
	base.Scope = "" // Config's established default still matches.
	if _, err := NewTransport(base); err != nil {
		t.Fatal(err)
	}
}

// Per-transport or per-endpoint ledgers would replenish slots, admit wrong models, or evade Close.
func TestRunPolicySharedTransports(t *testing.T) {
	c := runConfig(t, 3)
	var sends, creds atomic.Int32
	servers := make([]*httptest.Server, 2)
	for i, model := range []string{"test-deployment", "judge-model"} {
		servers[i] = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			data, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(data), `"model":"`+model+`"`) || !strings.Contains(string(data), `"max_completion_tokens":4096`) {
				t.Error("wrong frozen request", string(data))
			}
			sends.Add(1)
			io.WriteString(w, usageResponse)
		}))
		defer servers[i].Close()
	}
	c.Bindings[0].Endpoint = servers[0].URL + "/openai/v1/"
	judge := c.Bindings[0]
	judge.ID = "judge"
	judge.Endpoint = servers[1].URL + "/openai/v1/"
	judge.Scope = "https://judge.invalid/.default"
	judge.Deployment = "judge-model"
	judge.Pricing.Input = 200000
	c.Bindings = append(c.Bindings, judge)
	c.Slots[1].BindingID = "judge"
	p := openRun(t, c)
	q := openRun(t, c)
	first := runClient(t, p, c, 0, servers[0], &creds)
	second := runClient(t, p, c, 1, servers[1], &creds)
	last := runClient(t, p, c, 2, servers[0], &creds)
	target := func(i int) string { return servers[i].URL + "/openai/v1/chat/completions" }
	if err := boundedSend(second, target(1), chat("same", false)); err == nil || creds.Load() != 0 || sends.Load() != 0 {
		t.Fatal("wrong body model reached credentials", err)
	}
	if err := boundedSend(second, target(0), strings.Replace(chat("same", false), "test-deployment", "judge-model", 1)); err == nil || creds.Load() != 0 {
		t.Fatal("wrong destination reached credentials", err)
	}
	if err := boundedSend(first, target(0), chat("same", false)); err != nil {
		t.Fatal(err)
	}
	if err := boundedSend(runClient(t, q, c, 0, servers[0], &creds), target(0), chat("changed", false)); err == nil {
		t.Fatal("other handle replenished slot")
	}
	if err := boundedSend(second, target(1), strings.Replace(chat("same", false), "test-deployment", "judge-model", 1)); err != nil {
		t.Fatal(err)
	}
	p.Close()
	for _, v := range []struct {
		client       *http.Client
		target, body string
	}{{first, target(0), chat("x", false)}, {second, target(1), strings.Replace(chat("x", false), "test-deployment", "judge-model", 1)}, {last, target(0), chat("x", false)}} {
		if err := boundedSend(v.client, v.target, v.body); err == nil {
			t.Fatal("closed policy sent")
		}
	}
	q.Close()
	p = openRun(t, c)
	if err := boundedSend(runClient(t, p, c, 2, servers[0], &creds), target(0), chat("same", false)); err != nil {
		t.Fatal(err)
	}
	if sends.Load() != 3 {
		t.Fatal("wrong shared dispatch count", sends.Load())
	}
	var slots, hashes int
	if err := p.ledger.db.QueryRow("SELECT count(DISTINCT call_slot),count(DISTINCT request_hash) FROM model_attempts").Scan(&slots, &hashes); err != nil || slots != 3 || hashes != 2 {
		t.Fatal("equal bodies lost slot identity", slots, hashes, err)
	}
}

// Mutation of caller-owned slices and both pointer kinds must not retarget/reprice the opened run.
func TestRunPolicySnapshotImmutable(t *testing.T) {
	c := runConfig(t, 1)
	limit := 32768
	c.MaxInputTokens = &limit
	p := openRun(t, c)
	before := p.Snapshot()
	c.Bindings[0].Endpoint = "https://other.invalid/openai/v1/"
	c.Bindings[0].Pricing.Input = 9
	*c.Bindings[0].Pricing.Extra = 1
	c.Slots[0].ID = "other"
	limit = 1
	if !bytes.Equal(before, p.Snapshot()) || p.InputLimit() != 32768 || p.AttemptLimit() != 1 {
		t.Fatal("caller mutated frozen policy")
	}
	before[0] = 'x'
	if p.Snapshot()[0] != '{' {
		t.Fatal("snapshot bytes aliased")
	}
	_, err := NewTransport(Config{Endpoint: "https://example.invalid/openai/v1/", Deployment: "test-deployment", Credential: goodCredential(), Policy: p, CallSlot: "case/0"})
	if err != nil {
		t.Fatal("mutation retargeted binding", err)
	}
}

func TestRunPolicyUnknownStopsAllBindings(t *testing.T) {
	for _, mode := range []string{"failed", "unknown", "large-input", "over-input"} {
		t.Run(mode, func(t *testing.T) {
			c := runConfig(t, 2)
			var sends, creds atomic.Int32
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				sends.Add(1)
				switch mode {
				case "failed":
					w.WriteHeader(429)
				case "unknown":
					io.WriteString(w, `{"choices":[]}`)
				case "large-input":
					io.WriteString(w, strings.Replace(usageResponse, `"prompt_tokens":12`, `"prompt_tokens":32768`, 1))
				case "over-input":
					io.WriteString(w, strings.Replace(usageResponse, `"prompt_tokens":12`, `"prompt_tokens":32769`, 1))
				}
			}))
			defer s.Close()
			c.Bindings[0].Endpoint = s.URL + "/openai/v1/"
			b := c.Bindings[0]
			b.ID = "judge"
			b.Deployment = "judge"
			b.Pricing.Output = 1
			c.Bindings = append(c.Bindings, b)
			c.Slots[0].BindingID = "judge"
			limit := 32768
			c.MaxInputTokens = &limit
			p := openRun(t, c)
			target := s.URL + "/openai/v1/chat/completions"
			err := boundedSend(runClient(t, p, c, 0, s, &creds), target, strings.Replace(chat("x", false), "test-deployment", "judge", 1))
			if (err == nil) != (mode == "large-input") {
				t.Fatal("wrong usage result", err)
			}
			p.Close()
			p = openRun(t, c)
			err = boundedSend(runClient(t, p, c, 1, s, &creds), target, chat("x", false))
			if mode == "large-input" {
				if err != nil || sends.Load() != 2 {
					t.Fatal("uniform root input bound not used", err)
				}
			} else if err == nil || sends.Load() != 1 || creds.Load() != 1 {
				t.Fatal("judge stop did not fence candidate", err)
			}
		})
	}
}

// Even empty state is immutable; v4 is not an operator-file format or a v1-v3 migration.
func TestRunPolicyNoMigration(t *testing.T) {
	for _, change := range []func(*RunConfig){func(c *RunConfig) { c.PlanDigest = "sha256:" + strings.Repeat("b", 64) }, func(c *RunConfig) { c.Bindings[0].Pricing.Output++ }, func(c *RunConfig) { c.Bindings[0].Deployment = "other" }, func(c *RunConfig) { c.Slots[0].ID = "other" }, func(c *RunConfig) { c.Bindings[0].Endpoint = "https://other.invalid/openai/v1/" }, func(c *RunConfig) { c.Slots = c.Slots[:1] }, func(c *RunConfig) { c.Slots[0], c.Slots[1] = c.Slots[1], c.Slots[0] }, func(c *RunConfig) { v := 32768; c.MaxInputTokens = &v }} {
		c := runConfig(t, 2)
		p := openRun(t, c)
		p.Close()
		before, _ := os.ReadFile(c.LedgerPath)
		change(&c)
		q, err := OpenRunPolicy(c)
		if q != nil {
			q.Close()
		}
		if err == nil {
			t.Fatal("adopted changed snapshot")
		}
		after, _ := os.ReadFile(c.LedgerPath)
		if !bytes.Equal(before, after) {
			t.Fatal("refusal changed ledger")
		}
	}
	c := runConfig(t, 1)
	p := openRun(t, c)
	file := filepath.Join(t.TempDir(), "snapshot.json")
	if err := os.WriteFile(file, p.Snapshot(), 0600); err != nil {
		t.Fatal(err)
	}
	if q, err := OpenPolicyFile(file); err == nil {
		q.Close()
		t.Fatal("v4 accepted as policy file")
	}
	for _, version := range []int{1, 2, 3} {
		for _, runFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("v%d/runFirst%v", version, runFirst), func(t *testing.T) {
				var file, ledger string
				switch version {
				case 1:
					file, ledger = policyConfig(t)
				case 2:
					file, ledger = v2PolicyConfig(t)
				case 3:
					file, ledger = plannedPolicyConfig(t)
				}
				c := runConfig(t, 1)
				c.LedgerPath = ledger
				if runFirst {
					openRun(t, c).Close()
					q, err := OpenPolicyFile(file)
					if q != nil {
						q.Close()
					}
					if err == nil {
						t.Fatal("legacy adopted run")
					}
				} else {
					openPlannedPolicy(t, file).Close()
					q, err := OpenRunPolicy(c)
					if q != nil {
						q.Close()
					}
					if err == nil {
						t.Fatal("run adopted legacy")
					}
				}
			})
		}
	}
}

func TestRunPolicyRejectBlobIdentity(t *testing.T) {
	for _, column := range []string{"call_slot", "request_hash"} {
		t.Run(column, func(t *testing.T) {
			c := runConfig(t, 1)
			p := openRun(t, c)
			id, err := p.reserve(strings.Repeat("a", 64), c.Slots[0].ID)
			if err != nil {
				t.Fatal(err)
			}
			in, out, reason := int64(12), int64(4), int64(1)
			if err = p.change(id, "succeeded", tokenUsage{Input: &in, Output: &out, Reasoning: &reason}); err != nil {
				t.Fatal(err)
			}
			p.Close()
			db, err := sql.Open("sqlite", c.LedgerPath)
			if err != nil {
				t.Fatal(err)
			}
			_, err = db.Exec("UPDATE model_attempts SET " + column + "=CAST(" + column + " AS BLOB)")
			db.Close()
			if err != nil {
				t.Fatal(err)
			}
			q, err := OpenRunPolicy(c)
			if q != nil {
				q.Close()
			}
			if err == nil {
				t.Fatal("BLOB identity accepted")
			}
		})
	}
}
