package agentcontroller

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Azure/aks-durable-agents/internal/qualification"
)

func TestDurableCandidateQualificationJoin(t *testing.T) {
	for _, mode := range []string{"pass", "one-wrong", "failed", "provider"} {
		t.Run(mode, func(t *testing.T) {
			var n int
			f := newExecutionFixture(t, func(w http.ResponseWriter, r *http.Request) {
				n++
				if mode == "provider" {
					w.WriteHeader(503)
					_, _ = io.WriteString(w, `{"error":{"code":"unavailable","message":"fake failure"}}`)
					return
				}
				answer := "hello yes"
				if mode == "failed" || mode == "one-wrong" && n == 1 {
					answer = "wrong"
				}
				body, _ := json.Marshal(answer)
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = fmt.Fprintf(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":%s},\"finish_reason\":null}]}\n\ndata: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: {\"choices\":[],\"usage\":{\"prompt_tokens\":12,\"completion_tokens\":4,\"completion_tokens_details\":{\"reasoning_tokens\":1}}}\n\ndata: [DONE]\n\n", body)
			})
			parent := t.TempDir()
			if err := os.Chmod(parent, 0700); err != nil {
				t.Fatal(err)
			}
			store, err := qualification.Create(filepath.Join(parent, "qualification"))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			prepared, err := PrepareCandidate(f.pkg, f.expected)
			if err != nil {
				t.Fatal(err)
			}
			r, err := store.Admit(context.Background(), qualification.Request{Key: "request", Requester: "host", Plan: prepared.Plan})
			if err != nil {
				t.Fatal(err)
			}
			var scopes []qualification.ExecutionScope
			factory := func(ctx context.Context, scope qualification.ExecutionScope) (qualification.Executor, error) {
				scopes = append(scopes, scope)
				root := filepath.Join(parent, strings.TrimPrefix(scope.RunID, "sha256:"))
				return NewDurableCandidateExecutor(f.pkg, f.expected, scope, DurableExecutionConfig{Directory: root, Pricing: f.budget.Config.Bindings[0].Pricing, Credential: f.credential, Transport: f.config.Transport})
			}
			got, err := store.Run(context.Background(), r.ID, factory)
			want := qualification.Passed
			if mode == "failed" {
				want = qualification.Failed
			}
			if mode == "provider" {
				want = qualification.Incomplete
			}
			if got.State != want || (mode != "provider" && err != nil) || (mode == "provider" && err == nil) {
				t.Fatalf("join %s: %+v %v", mode, got, err)
			}
			sends := f.sends.Load()
			if mode == "provider" && sends != 1 || mode != "provider" && sends != 4 {
				t.Fatalf("inventory %d", sends)
			}
			if len(scopes) != 1 {
				t.Fatal("wrong factory count")
			}
			if qualification.ExecutionScopeForRecord(got) != scopes[0] {
				t.Fatal("cannot recover original root from final record")
			}
			root := filepath.Join(parent, strings.TrimPrefix(scopes[0].RunID, "sha256:"))
			manifest, err := os.ReadFile(filepath.Join(root, "scope.json"))
			if err != nil || !strings.Contains(string(manifest), scopes[0].RunID) {
				t.Fatal("missing scope manifest")
			}
			if mode != "provider" {
				if len(got.Observations) != 4 {
					t.Fatal("partial evidence")
				}
				_, verify := store.VerifyForActivation(context.Background(), r.ID, prepared.Plan, got.CompletedAt)
				if (mode != "failed") != (verify == nil) {
					t.Fatalf("eligibility: %v", verify)
				}
			}
			lineage := store.Lineage()
			if err = store.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := qualification.Open(filepath.Join(parent, "qualification"), lineage)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			same, err := reopened.Run(context.Background(), r.ID, factory)
			if err != nil || same.Digest != got.Digest || f.sends.Load() != sends || len(scopes) != 1 {
				t.Fatalf("restart redispatch: %v", err)
			}
		})
	}
}
