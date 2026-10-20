package modeltransport

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/agent-primitives/sessions/api"
	"github.com/agent-primitives/sessions/model/openai"
)

func TestInvalidAdapterCompletionWithKnownUsageStopsRun(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		stream     bool
	}{
		{"no choices", `{"choices":[],"usage":{"prompt_tokens":12,"completion_tokens":4}}`, false},
		{"invalid message", `{"choices":[{"message":{"content":{}}}],"usage":{"prompt_tokens":12,"completion_tokens":4}}`, false},
		{"invalid streamed delta", "data: {\"choices\":[{\"delta\":{\"content\":{}}}],\"usage\":{\"prompt_tokens\":12,\"completion_tokens\":4}}\ndata: [DONE]\n\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _, ledger := openTestPolicy(t)
			var sends atomic.Int32
			c, target := boundedFixture(t, p, func(w http.ResponseWriter, r *http.Request) { sends.Add(1); _, _ = io.WriteString(w, tc.body) }, goodCredential())
			adapter, err := openai.New(openai.WithBaseURL(strings.TrimSuffix(target, "chat/completions")), openai.WithHTTPClient(c), openai.WithModel("test-deployment"))
			if err != nil {
				t.Fatal(err)
			}
			call := func(text string) error {
				req := api.ModelRequest{Model: "test-deployment", Messages: []api.Message{*api.TextMessage("user", text)}}
				if tc.stream {
					_, err = adapter.StreamModel(context.Background(), req, func(string) {})
				} else {
					_, err = adapter.Model(context.Background(), req)
				}
				return err
			}
			if call("original") == nil {
				t.Fatal("invalid adapter completion accepted")
			}
			n, outcome, in, out, _ := ledgerRows(t, ledger)
			if n != 1 || outcome == "succeeded" || !in.Valid || in.Int64 != 12 || !out.Valid || out.Int64 != 4 {
				t.Fatalf("response disagreement/usage: n%d outcome%s input%+v output%+v", n, outcome, in, out)
			}
			if call("different") == nil || sends.Load() != 1 {
				t.Fatalf("another dispatch after adapter failure: posts%d", sends.Load())
			}
		})
	}
}
