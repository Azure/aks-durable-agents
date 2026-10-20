package host

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/Azure/aks-durable-agents/modeltransport"

	"github.com/agent-primitives/sessions/api"
	v1 "github.com/agent-primitives/sessions/api/genpb"
	"github.com/agent-primitives/sessions/authn"
	"github.com/agent-primitives/sessions/client"
	"github.com/agent-primitives/sessions/harnesswire"
	"google.golang.org/grpc"
)

const hostFormat = `{"type":"json_schema","json_schema":{"name":"document_changes","strict":true,"schema":{"type":"object","additionalProperties":false,"required":["changes"],"properties":{"changes":{"type":"array","items":{"type":"object","additionalProperties":false,"required":["document","operation","content"],"properties":{"document":{"type":"string"},"operation":{"type":"string","enum":["replace"]},"content":{"type":"string"}}}}}}}}`
const hostOutput = `{"changes":[{"document":"notes","operation":"replace","content":"Upgrade advice"}]}`

func hostParams() map[string]string {
	return map[string]string{"max_tokens": "16384", "temperature": "0.2", "response_format": hostFormat}
}

type structuredHarness struct{ params map[string]string }

func (structuredHarness) Describe(context.Context) (api.Descriptor, error) {
	return api.Descriptor{ID: "structured", Version: "1", Models: []string{"test-deployment"}, Capabilities: api.Capabilities{Resumability: api.ResumabilityStatelessReplay, ForkSafe: true}}, nil
}
func (h structuredHarness) Run(ctx context.Context, s *api.Start, sink api.EventSink) error {
	_, err := sink.Model(ctx, api.ModelRequest{Model: "test-deployment", Messages: s.Inputs, Params: h.params})
	return err
}

// The real newApplication path selects StreamModel even for an ordinary Exec.
// The separate unary call pins the other bridge path to the same HTTP body.
func TestStructuredChatWire(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprint(stream), func(t *testing.T) {
			var sends atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				sends.Add(1)
				var body map[string]json.RawMessage
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				var gotFormat, wantFormat any
				json.Unmarshal(body["response_format"], &gotFormat)
				json.Unmarshal([]byte(hostFormat), &wantFormat)
				if !reflect.DeepEqual(gotFormat, wantFormat) || string(body["max_completion_tokens"]) != "4096" || body["max_tokens"] != nil || body["temperature"] != nil {
					t.Errorf("structured cap/schema shaping missing: %s", body)
				}
				if (string(body["stream"]) == "true") != stream || r.Header.Get("Authorization") != "Bearer "+fixtureModelToken {
					t.Error("wrong stream or keyless credential")
				}
				if stream {
					fmt.Fprintf(w, "data: {\"choices\":[{\"delta\":{\"content\":%q}}]}\n\ndata: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: {\"choices\":[],\"usage\":{\"prompt_tokens\":750,\"completion_tokens\":120}}\n\ndata: [DONE]\n\n", hostOutput)
				} else {
					fmt.Fprintf(w, `{"choices":[{"message":{"role":"assistant","content":%q,"refusal":null},"finish_reason":"stop"}],"usage":{"prompt_tokens":750,"completion_tokens":120}}`, hostOutput)
				}
			}))
			defer server.Close()
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			policyPath := filepath.Join(dir, "policy.json")
			policy := fmt.Sprintf(`{"version":1,"runID":"structured","ledgerPath":%q,"deployment":"test-deployment","pricing":{"inputMicroUSDPerMillionTokens":100000,"outputMicroUSDPerMillionTokens":500000,"extraMicroUSDPerCall":0,"source":"https://example.invalid/prices","asOf":"2026-10-19"}}`, filepath.Join(dir, "budget.db"))
			if err := os.WriteFile(policyPath, []byte(policy), 0600); err != nil {
				t.Fatal(err)
			}
			harnessListener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			harnessServer := grpc.NewServer()
			v1.RegisterHarnessServer(harnessServer, harnesswire.NewServer(structuredHarness{hostParams()}))
			go harnessServer.Serve(harnessListener)
			defer harnessServer.Stop()
			c := Config{Addr: "127.0.0.1:0", HealthAddr: "127.0.0.1:0", Journal: filepath.Join(dir, "journal.db"), Mode: authn.Off, Harnesses: map[string]string{"structured": harnessListener.Addr().String()}, ModelEndpoint: server.URL + "/openai/v1/", Deployment: "test-deployment", ModelTransport: server.Client().Transport.(*http.Transport), ModelPolicy: policyPath}
			app, err := newApplication(t.Context(), c, fixtureCredential{t}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer app.Close()
			if stream {
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				go app.sessions.Serve(ln)
				cl, err := client.Dial(ln.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				defer cl.Close()
				turn, err := cl.Exec(t.Context(), client.ExecOptions{Harness: "structured", Inputs: []string{"Draft release notes"}})
				if err != nil || turn.Output != hostOutput {
					t.Fatalf("host structured output: %v %+v", err, turn)
				}
			} else {
				// Use the same constructor and context bridge as both host ModelFuncs.
				provider, err := newChatModel(c, app.modelPolicy, fixtureCredential{t})
				if err != nil {
					t.Fatal(err)
				}
				params := hostParams()
				ctx, err := chatParamsContext(t.Context(), params)
				if err != nil {
					t.Fatal(err)
				}
				result, err := provider.Model(ctx, api.ModelRequest{Model: c.Deployment, Params: params, Messages: []api.Message{*api.TextMessage("user", "Draft release notes")}})
				if err != nil || result.Message.Text() != hostOutput {
					t.Fatalf("unary structured output: %v %+v", err, result)
				}
				if !reflect.DeepEqual(params, hostParams()) {
					t.Fatal("bridge mutated recorded Params")
				}
			}
			if sends.Load() != 1 {
				t.Fatalf("POSTs=%d", sends.Load())
			}
		})
	}
}

// This exercises the sessions adapter after the response bytes cross host policy.
func TestStructuredChatResponseBeforeAdapter(t *testing.T) {
	for _, stream := range []bool{false, true} {
		for _, outcome := range []string{"length", "refusal", "missing"} {
			t.Run(fmt.Sprintf("%t/%s", stream, outcome), func(t *testing.T) {
				var sends atomic.Int32
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					sends.Add(1)
					finish, refusal := `"stop"`, `null`
					if outcome == "length" {
						finish = `"length"`
					}
					if outcome == "missing" {
						finish = `null`
					}
					if outcome == "refusal" {
						refusal = `"provider-private-refusal"`
					}
					body := fmt.Sprintf(`{"choices":[{"message":{"role":"assistant","content":%q,"refusal":%s},"finish_reason":%s}],"usage":{"prompt_tokens":750,"completion_tokens":120}}`, hostOutput, refusal, finish)
					if stream {
						body = "data: " + strings.Replace(body, `"message":`, `"delta":`, 1) + "\n\ndata: [DONE]\n\n"
					}
					io.WriteString(w, body)
				}))
				defer server.Close()
				dir := t.TempDir()
				if err := os.Chmod(dir, 0700); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(dir, "policy.json")
				data := fmt.Sprintf(`{"version":1,"runID":"response","ledgerPath":%q,"deployment":"test-deployment","pricing":{"inputMicroUSDPerMillionTokens":100000,"outputMicroUSDPerMillionTokens":500000,"extraMicroUSDPerCall":0,"source":"https://example.invalid/prices","asOf":"2026-10-19"}}`, filepath.Join(dir, "budget.db"))
				if err := os.WriteFile(path, []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
				p, err := modeltransport.OpenPolicyFile(path)
				if err != nil {
					t.Fatal(err)
				}
				defer p.Close()
				provider, err := newChatModel(Config{ModelEndpoint: server.URL + "/openai/v1/", Deployment: "test-deployment", ModelTransport: server.Client().Transport.(*http.Transport)}, p, fixtureCredential{t})
				if err != nil {
					t.Fatal(err)
				}
				ctx, err := chatParamsContext(t.Context(), hostParams())
				if err != nil {
					t.Fatal(err)
				}
				req := api.ModelRequest{Model: "test-deployment", Messages: []api.Message{*api.TextMessage("user", "draft")}, Params: hostParams()}
				if stream {
					_, err = provider.StreamModel(ctx, req, nil)
				} else {
					_, err = provider.Model(ctx, req)
				}
				if err == nil || strings.Contains(err.Error(), "provider-private") {
					t.Fatalf("adapter accepted invalid completion or leaked refusal: %v", err)
				}
				if sends.Load() != 1 {
					t.Fatalf("POSTs=%d", sends.Load())
				}
			})
		}
	}
}

func TestStructuredChatRequiresBoundedPolicy(t *testing.T) {
	var sends atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sends.Add(1)
		io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"{}"}}]}`)
	}))
	defer server.Close()
	provider, err := newChatModel(Config{ModelEndpoint: server.URL + "/openai/v1/", Deployment: "test-deployment", ModelTransport: server.Client().Transport.(*http.Transport)}, nil, fixtureCredential{t})
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := chatParamsContext(t.Context(), hostParams())
	if err != nil {
		t.Fatal(err)
	}
	_, err = provider.Model(ctx, api.ModelRequest{Model: "test-deployment", Messages: []api.Message{*api.TextMessage("user", "x")}})
	if err == nil || !strings.Contains(err.Error(), "structured output requires bounded policy") || sends.Load() != 0 {
		t.Fatalf("unbounded schema mode reached adapter: %v sends%d", err, sends.Load())
	}
}

func TestStructuredChatRejectsUnsupportedParams(t *testing.T) {
	for _, params := range []map[string]string{{"tools": "[]"}, {"max_tokens": "99999"}, {"temperature": "1"}, {"response_format": ""}, {"response_format": "not JSON"}} {
		if _, err := chatParamsContext(t.Context(), params); err == nil {
			t.Fatalf("unsupported Params accepted: %v", params)
		}
	}
	for _, params := range []map[string]string{nil, {}, {"max_tokens": "700", "temperature": "0.2"}} {
		if _, err := chatParamsContext(t.Context(), params); err != nil {
			t.Fatalf("legacy plain Params rejected: %v", err)
		}
	}
}
