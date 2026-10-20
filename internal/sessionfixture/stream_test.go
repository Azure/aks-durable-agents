package sessionfixture

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agent-primitives/sessions/api"
	"github.com/agent-primitives/sessions/model/openai"
)

// Stock v0.2.0 always configures the streaming model. Exercise its actual
// adapter, not a unary test approximation, preserving one durable fake call.
func TestFakeStockStreamingAdapterOneMeteredCompletion(t *testing.T) {
	for _, variant := range []string{"A", "B"} {
		t.Run(variant, func(t *testing.T) {
			ledger := filepath.Join(t.TempDir(), "fake-calls.jsonl")
			handler, err := newFakeHandler(ledger)
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(handler)
			defer server.Close()
			provider, err := openai.New(openai.WithBaseURL(server.URL+"/v1"), openai.WithModel(modelID), openai.WithHTTPClient(server.Client()))
			if err != nil {
				t.Fatal(err)
			}
			var chunks strings.Builder
			response, err := provider.StreamModel(t.Context(), api.ModelRequest{Model: modelID, Messages: []api.Message{*api.TextMessage("system", FrozenInstructions), *api.TextMessage("user", "REFERENCE fictional proposal, variant "+variant)}}, func(chunk string) { chunks.WriteString(chunk) })
			if err != nil {
				t.Fatal(err)
			}
			want := draftA
			if variant == "B" {
				want = draftB
			}
			if response.Message.Text() != want || chunks.String() != want || response.Usage.InputTokens != 1 || response.Usage.OutputTokens != 1 {
				t.Fatalf("stream response: %#v chunks=%q", response, chunks.String())
			}
			count, err := meterCount(ledger)
			if err != nil || count != 1 {
				t.Fatalf("stream meter: %d %v", count, err)
			}
		})
	}
}
func TestFakeStreamingFramingAndStrictOptions(t *testing.T) {
	ledger := filepath.Join(t.TempDir(), "fake-calls.jsonl")
	handler, err := newFakeHandler(ledger)
	if err != nil {
		t.Fatal(err)
	}
	req := map[string]any{"model": modelID, "messages": []map[string]string{{"role": "system", "content": FrozenInstructions}, {"role": "user", "content": "REFERENCE fictional proposal, variant A"}}, "stream": true, "stream_options": map[string]any{"include_usage": true}}
	raw, _ := json.Marshal(req)
	out := httptest.NewRecorder()
	handler.ServeHTTP(out, httptest.NewRequest(http.MethodPost, "http://127.0.0.1/v1/chat/completions", bytes.NewReader(raw)))
	if out.Code != 200 || out.Header().Get("Content-Type") != "text/event-stream" || !strings.HasSuffix(out.Body.String(), "data: [DONE]\n\n") || strings.Count(out.Body.String(), "[DONE]") != 1 {
		t.Fatalf("invalid SSE: %d %s %s", out.Code, out.Header(), out.Body.String())
	}
	for _, options := range []any{nil, map[string]any{}, map[string]any{"include_usage": false}, map[string]any{"include_usage": true, "extra": 1}, map[string]any{"Include_Usage": true}} {
		req["stream_options"] = options
		raw, _ = json.Marshal(req)
		out = httptest.NewRecorder()
		handler.ServeHTTP(out, httptest.NewRequest(http.MethodPost, "http://127.0.0.1/v1/chat/completions", bytes.NewReader(raw)))
		if out.Code < 400 {
			t.Fatalf("unsafe stream options accepted: %#v", options)
		}
	}
	count, err := meterCount(ledger)
	if err != nil || count != 1 {
		t.Fatalf("invalid stream was metered: %d %v", count, err)
	}
}
