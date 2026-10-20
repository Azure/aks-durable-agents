package modeltransport

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/agent-primitives/sessions/api"
	"github.com/agent-primitives/sessions/model/openai"
)

// This imports the real v0.2.0 adapter, not a lookalike request builder.
// It catches header overwrites, lost redirect policy, default deployment wiring, and provider-error leakage.
func TestSessionsAdapter(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		status                   int
		malformedTrailer, stream bool
	}{
		{name: "chat success", status: 200}, {name: "stream success", status: 200, stream: true},
		{name: "provider error", status: 400}, {name: "non-200 success status", status: 202},
		{name: "same origin redirect", status: 307},
		{name: "body read error", status: 200, malformedTrailer: true},
		{name: "stream read error", status: 200, malformedTrailer: true, stream: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var sends atomic.Int32
			client, server := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				sends.Add(1)
				if r.URL.Path != "/openai/v1/chat/completions" || r.Method != "POST" {
					t.Error("wrong adapter route")
				}
				if r.Header.Get("Authorization") != "Bearer "+secret || r.Header.Get("api-key") != "" {
					t.Error("adapter credentials not replaced")
				}
				var body struct {
					Model string `json:"model"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Model != "test-deployment" {
					t.Error("deployment tuple not wired")
				}
				if tc.malformedTrailer {
					conn, buf, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					defer conn.Close()
					// net/http includes this malformed trailer text in its raw body-read error.
					_, _ = fmt.Fprintf(buf, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-End\r\n\r\n0\r\n%s\r\n\r\n", secret)
					_ = buf.Flush()
					return
				}
				if tc.status != 200 {
					w.Header().Set("Location", "/openai/v1/redirect")
					w.WriteHeader(tc.status)
					_, _ = io.WriteString(w, `{"error":{"message":"provider-body-`+secret+`"}}`)
					return
				}
				if tc.stream {
					_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\ndata: [DONE]\n\n")
					return
				}
				_, _ = io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"hello"}}]}`)
			}, goodCredential())
			adapter, err := openai.New(openai.WithBaseURL(server.URL+"/openai/v1/"), openai.WithModel("test-deployment"), openai.WithHTTPClient(client), openai.WithAPIKey("caller"), openai.WithHeader("api-key", "caller-key"))
			if err != nil {
				t.Fatal(err)
			}
			req := api.ModelRequest{Messages: []api.Message{{Role: "user", Parts: []api.Part{{Text: &api.TextPart{Text: "hello"}}}}}}
			var response api.ModelResponse
			if tc.stream {
				response, err = adapter.StreamModel(context.Background(), req, nil)
			} else {
				response, err = adapter.Model(context.Background(), req)
			}
			if tc.status == 200 && !tc.malformedTrailer {
				if err != nil {
					t.Fatal(err)
				}
				if len(response.Message.Parts) != 1 || response.Message.Parts[0].Text == nil || response.Message.Parts[0].Text.Text != "hello" {
					t.Fatal("adapter failed to decode response")
				}
			} else if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "provider-body") {
				t.Fatal("missing or unsafe adapter error")
			}
			if sends.Load() != 1 {
				t.Fatalf("sends=%d", sends.Load())
			}
		})
	}
}
