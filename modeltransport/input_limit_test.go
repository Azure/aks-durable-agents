package modeltransport

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

func inputPolicyConfig(t *testing.T, version int, field string) (string, string) {
	t.Helper()
	path, ledger := policyConfig(t)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if version == 2 {
		raw = []byte(strings.Replace(string(raw), `"version":1`, `"version":2,"maxAttempts":3`, 1))
	}
	if field != "" {
		raw = []byte(strings.Replace(string(raw), `"runID"`, field+`,"runID"`, 1))
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return path, ledger
}

// Captured from the base implementation before adding the input-limit option.
func TestInputLimitHistoricalSnapshotsAndRequests(t *testing.T) {
	const pricing = `"runID":"test-run","ledgerPath":"LEDGER","deployment":"test-deployment","pricing":{"inputMicroUSDPerMillionTokens":100000,"outputMicroUSDPerMillionTokens":500000,"extraMicroUSDPerCall":0,"source":"https://example.invalid/official-pricing","asOf":"2026-09-22"}}`
	const format = `{"type":"json_schema","json_schema":{"name":"example","strict":true,"schema":{"type":"object","additionalProperties":false,"properties":{}}}}`
	const prefix = `{"model":"test-deployment","messages":[{"role":"user","content":"historical"}],`
	const streaming = `"stream":true,"stream_options":{"include_usage":true},`
	const cap = `"max_completion_tokens":4096`
	const schema = `,"response_format":{"type":"json_schema","json_schema":{"name":"example","strict":true,"schema":{"additionalProperties":false,"properties":{},"type":"object"}}}`
	fixtures := []struct {
		structured, stream bool
		body, hash         string
	}{
		{false, false, prefix + cap + `}`, "01fc24b4b8a7c08bbf6eb701f5161033b51a76a86432d80467c118449100334e"},
		{false, true, prefix + streaming + cap + `}`, "e0eefe83f2a576628d9d1eddf1974bc48620f207828301040f6c32bb459c8d17"},
		{true, false, prefix + cap + schema + `}`, "17c4cd45d39b2485f7228a2e1b2c5bcac82347505e29b3460c529ec2aa5871fc"},
		{true, true, prefix + streaming + cap + schema + `}`, "b3ea8fd847b8bc2b92e23df9878dd183decafd28a651aedf6b54e1ae3b78831c"},
	}
	for _, version := range []int{1, 2} {
		for _, field := range []string{"", `"maxInputTokens":32768`} {
			t.Run(fmt.Sprintf("v%d/%s", version, field), func(t *testing.T) {
				path, _ := inputPolicyConfig(t, version, field)
				p, err := OpenPolicyFile(path)
				if err != nil {
					t.Fatal(err)
				}
				defer p.Close()
				var snapshot string
				if err := p.ledger.db.QueryRow("SELECT snapshot FROM model_budget").Scan(&snapshot); err != nil {
					t.Fatal(err)
				}
				expected := fmt.Sprintf(`{"version":%d,`, version)
				if version == 2 {
					expected += `"maxAttempts":3,`
				}
				if field != "" {
					expected += field + `,`
				}
				expected += pricing
				if strings.ReplaceAll(snapshot, p.config.LedgerPath, "LEDGER") != expected {
					t.Fatalf("snapshot changed: %s", snapshot)
				}
				for _, f := range fixtures {
					body := chat("historical", f.stream)
					if f.structured {
						body = structuredChat("historical", format, f.stream)
					}
					req, _ := http.NewRequest("POST", "https://example.invalid/openai/v1/chat/completions", strings.NewReader(body))
					got, hash, _, _, err := p.prepare(req)
					if err != nil || string(got) != f.body || hash != f.hash {
						t.Fatalf("historical request changed: %s %s %v", got, hash, err)
					}
				}
				if err := p.Close(); err != nil {
					t.Fatal(err)
				}
				p, err = OpenPolicyFile(path)
				if err != nil {
					t.Fatal(err)
				}
				p.Close()
			})
		}
	}
}

func TestInputLimitConfigRefusesBeforeLedger(t *testing.T) {
	for _, field := range []string{`"maxInputTokens":0`, `"maxInputTokens":-1`, `"maxInputTokens":8192`, `"maxInputTokens":8193`, `"maxInputTokens":32769`, `"maxInputTokens":null`, `"maxInputTokens":"32768"`, `"maxInputTokens":32768.5`, `"maxInputTokens":32768,"maxInputTokens":32768`, `"MaxInputTokens":32768`} {
		t.Run(field, func(t *testing.T) {
			path, ledger := inputPolicyConfig(t, 1, field)
			p, err := OpenPolicyFile(path)
			if p != nil {
				p.Close()
			}
			if err == nil || !strings.Contains(err.Error(), "invalid policy") {
				t.Fatal("invalid limit did not fail policy validation", err)
			}
			if _, err := os.Stat(ledger); !os.IsNotExist(err) {
				t.Fatal("invalid limit touched ledger", err)
			}
		})
	}
}

func TestInputLimitSnapshotCannotChange(t *testing.T) {
	for _, v := range []int{1, 2} {
		for _, old := range []string{"", `"maxInputTokens":32768`} {
			t.Run(fmt.Sprintf("v%d/%s", v, old), func(t *testing.T) {
				path, ledger := inputPolicyConfig(t, v, old)
				p, err := OpenPolicyFile(path)
				if err != nil {
					t.Fatal(err)
				}
				p.Close()
				before, err := os.ReadFile(ledger)
				if err != nil {
					t.Fatal(err)
				}
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				text := string(raw)
				if old == "" {
					text = strings.Replace(text, `"runID"`, `"maxInputTokens":32768,"runID"`, 1)
				} else {
					text = strings.Replace(text, old+`,`, "", 1)
				}
				if err := os.WriteFile(path, []byte(text), 0600); err != nil {
					t.Fatal(err)
				}
				p, err = OpenPolicyFile(path)
				if p != nil {
					p.Close()
				}
				if err == nil || !strings.Contains(err.Error(), "ledger unavailable, inconsistent, or policy stop") {
					t.Fatal("changed existing policy was not refused by the ledger", err)
				}
				after, err := os.ReadFile(ledger)
				if err != nil || string(before) != string(after) {
					t.Fatal("refusal changed ledger", err)
				}
			})
		}
	}
}

func TestInputLimitWholeContextBeforeIO(t *testing.T) {
	var format any
	if err := json.Unmarshal([]byte(testFormat), &format); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(format)
	for _, limit := range []int{8192, 32768} {
		for _, delta := range []int{0, 1} {
			t.Run(fmt.Sprintf("%d/%d", limit, delta), func(t *testing.T) {
				field := ""
				if limit == 32768 {
					field = `"maxInputTokens":32768`
				}
				path, ledger := inputPolicyConfig(t, 1, field)
				p, err := OpenPolicyFile(path)
				if err != nil {
					t.Fatal(err)
				}
				defer p.Close()
				var sends, creds atomic.Int32
				c, target := boundedFixture(t, p, func(w http.ResponseWriter, r *http.Request) {
					sends.Add(1)
					var body boundedChat
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Error(err)
					}
					if body.MaxCompletionTokens == nil || *body.MaxCompletionTokens != 4096 {
						t.Error("completion cap changed")
					}
					io.WriteString(w, structuredSuccess())
				}, func(ctx context.Context, o policy.TokenRequestOptions) (azcore.AccessToken, error) {
					creds.Add(1)
					return goodCredential()(ctx, o)
				})
				size := limit - 256 - 64 - len("system") - len("é") - 64 - len("user") - len(encoded) + delta
				text := strings.Repeat("界", size/3) + strings.Repeat("x", size%3)
				raw, _ := json.Marshal(map[string]any{"model": "test-deployment", "messages": []map[string]string{{"role": "system", "content": "é"}, {"role": "user", "content": text}}, "response_format": format})
				err = boundedSend(c, target, string(raw))
				n, _, _, _, _ := ledgerRows(t, ledger)
				if delta == 0 {
					if err != nil || sends.Load() != 1 || creds.Load() != 1 || n != 1 {
						t.Fatalf("exact boundary: %v sends%d creds%d rows%d", err, sends.Load(), creds.Load(), n)
					}
				} else if err == nil || !strings.Contains(err.Error(), "full context exceeds input bound") || sends.Load() != 0 || creds.Load() != 0 || n != 0 {
					t.Fatalf("over bound reached IO: %v sends%d creds%d rows%d", err, sends.Load(), creds.Load(), n)
				}
			})
		}
	}
}

func TestInputLimitUsageAndRestart(t *testing.T) {
	for _, stream := range []bool{false, true} {
		for _, tc := range []struct {
			field                 string
			input, output, reason int
			ok                    bool
		}{
			{"", 8193, 4, 1, false}, {`"maxInputTokens":32768`, 8193, 4, 1, true}, {`"maxInputTokens":32768`, 32768, 4096, 4096, true}, {`"maxInputTokens":32768`, 32769, 4, 1, false}, {`"maxInputTokens":32768`, 12, 4097, 1, false}, {`"maxInputTokens":32768`, 12, 4, 5, false},
		} {
			t.Run(fmt.Sprintf("stream%t/%s/%d/%d/%d", stream, tc.field, tc.input, tc.output, tc.reason), func(t *testing.T) {
				path, ledger := inputPolicyConfig(t, 2, tc.field)
				var sends atomic.Int32
				for i := 0; i < 4; i++ {
					p, err := OpenPolicyFile(path)
					if err != nil {
						t.Fatal(err)
					}
					c, target := boundedFixture(t, p, func(w http.ResponseWriter, r *http.Request) {
						sends.Add(1)
						response := fmt.Sprintf(`{"choices":[{"message":{"role":"assistant","content":"hello"}}],"usage":{"prompt_tokens":%d,"completion_tokens":%d,"completion_tokens_details":{"reasoning_tokens":%d}}}`, tc.input, tc.output, tc.reason)
						if stream {
							response = "data: " + response + "\n\ndata: [DONE]\n\n"
						}
						io.WriteString(w, response)
					}, goodCredential())
					err = boundedSend(c, target, chat(fmt.Sprint(i), stream))
					p.Close()
					if (tc.ok && i < 3) != (err == nil) {
						t.Fatalf("attempt%d: %v", i+1, err)
					}
					if err != nil {
						want := "ledger unavailable, inconsistent, or policy stop"
						if !tc.ok && i == 0 {
							want = "response usage or completion unknown"
						}
						if !strings.Contains(err.Error(), want) {
							t.Fatalf("wrong refusal: %v", err)
						}
					}
				}
				n, outcome, _, _, _ := ledgerRows(t, ledger)
				want := int32(1)
				status := "unknown"
				if tc.ok {
					want = 3
					status = "succeeded"
				}
				if sends.Load() != want || n != int(want) || outcome != status {
					t.Fatalf("calls%d rows%d outcome%s", sends.Load(), n, outcome)
				}
			})
		}
	}
}

func TestInputLimitChartPolicy(t *testing.T) {
	raw, err := os.ReadFile("../charts/aks-durable-agents/tests/model-policy-three-calls.json")
	if err != nil {
		t.Fatal(err)
	}
	path, ledger := policyConfig(t)
	// Only the absolute ledger location changes from the chart-rendered fixture.
	raw = []byte(strings.Replace(string(raw), "/data/real-attempts.db", ledger, 1))
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	p, err := OpenPolicyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if p.InputLimit() != 32768 || p.AttemptLimit() != 3 {
		t.Fatal("chart/host limits disagree")
	}
}

func TestInputLimitReservation(t *testing.T) {
	// At three attempts and output rate 1, these adjacent input rates straddle USD2.
	for _, tc := range []struct {
		rate string
		ok   bool
	}{{"20345051", true}, {"20345052", false}} {
		t.Run(tc.rate, func(t *testing.T) {
			path, ledger := inputPolicyConfig(t, 2, `"maxInputTokens":32768`)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			raw = []byte(strings.Replace(strings.Replace(string(raw), "100000", tc.rate, 1), "500000", "1", 1))
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			p, err := OpenPolicyFile(path)
			if p != nil {
				p.Close()
			}
			if tc.ok != (err == nil) {
				t.Fatal("wrong reservation", err)
			}
			if !tc.ok {
				if !strings.Contains(err.Error(), "full run reservation exceeds USD 2") {
					t.Fatal("wrong reservation refusal", err)
				}
				if _, err := os.Stat(ledger); !os.IsNotExist(err) {
					t.Fatal("reservation refusal touched ledger", err)
				}
			}
		})
	}
}
