package agentcontroller

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/aks-durable-agents/internal/agentpackage"
	"github.com/Azure/aks-durable-agents/internal/qualification"
	"github.com/Azure/aks-durable-agents/modeltransport"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	azpolicy "github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/agent-primitives/sessions/api"
	"github.com/agent-primitives/sessions/eventlog"
	"github.com/agent-primitives/sessions/sqlitelog"
	"github.com/agent-primitives/suite/core"
)

type executionCredential struct{ calls atomic.Int64 }

func (c *executionCredential) GetToken(context.Context, azpolicy.TokenRequestOptions) (azcore.AccessToken, error) {
	c.calls.Add(1)
	return azcore.AccessToken{Token: "fixture-token", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

type executionFixture struct {
	pkg        *agentpackage.Package
	expected   CandidateExpectations
	budget     qualification.PreparedBudget
	config     ExecutionConfig
	credential *executionCredential
	sends      atomic.Int64
	journals   atomic.Int64
	mu         sync.Mutex
	bodies     [][]byte
	logs       map[string]eventlog.Store
}

func newExecutionFixture(t *testing.T, handler http.HandlerFunc) *executionFixture {
	t.Helper()
	f := &executionFixture{credential: &executionCredential{}, logs: map[string]eventlog.Store{}}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.sends.Add(1)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		f.mu.Lock()
		f.bodies = append(f.bodies, body)
		f.mu.Unlock()
		if handler != nil {
			handler(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hello yes\"},\"finish_reason\":null}]}\n\ndata: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: {\"choices\":[],\"usage\":{\"prompt_tokens\":12,\"completion_tokens\":4,\"completion_tokens_details\":{\"reasoning_tokens\":1}}}\n\ndata: [DONE]\n\n")
	}))
	t.Cleanup(server.Close)
	f.pkg = preparationFixture(t, preparationCases(), nil)
	f.expected = preparationExpected(t, f.pkg)
	f.expected.Binding.Endpoint = server.URL + "/openai/v1/"
	p, err := PrepareCandidate(f.pkg, f.expected)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	zero := int64(0)
	f.budget, err = PrepareRunBudget(p, f.expected.Binding, qualification.BudgetRequest{
		RunID: "record-one", LedgerPath: filepath.Join(dir, "run.sqlite"),
		Candidate: modeltransport.RunBinding{ID: "candidate", Endpoint: f.expected.Binding.Endpoint, Scope: modeltransport.DefaultScope, Deployment: f.expected.Binding.Deployment,
			Pricing: modeltransport.RunPricing{Input: 100000, Output: 500000, Extra: &zero, Source: "https://example.invalid/pricing", AsOf: "2026-10-27"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := modeltransport.OpenRunPolicy(f.budget.Config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = policy.Close() })
	journalPath := filepath.Join(dir, "sessions.sqlite")
	file, err := os.OpenFile(journalPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := sqlitelog.Open((&url.URL{Scheme: "file", Path: journalPath}).String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	f.config = ExecutionConfig{RunID: "record-one", Policy: policy, Credential: f.credential, Transport: server.Client().Transport.(*http.Transport), Journal: func(uid string) (eventlog.Store, error) {
		f.journals.Add(1)
		f.mu.Lock()
		defer f.mu.Unlock()
		log := store.Session(uid)
		f.logs[uid] = log
		return log, nil
	}}
	return f
}

// A different renderer, default model, prior conversation or incompatible SDK journal must fail this gate.
func TestCandidateExecutorJournalShape(t *testing.T) {
	f := newExecutionFixture(t, nil)
	x, err := NewCandidateExecutor(f.pkg, f.expected, f.config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = x.Close() })
	got, err := x.Execute(t.Context(), f.budget.Calls[0].SlotID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Call != f.budget.Calls[0] || got.RunID != "record-one" || got.PlanDigest != f.budget.Config.PlanDigest || got.Count != 5 || len(got.Records) != 5 || got.SessionID == "" || got.ExecutionID == "" {
		t.Fatalf("incomplete journal anchors: %+v", got)
	}
	if eventlog.VerifyChain("", got.Records) != nil || got.HeadHash != got.Records[4].Hash {
		t.Fatal("original chain/terminal anchor lost")
	}
	wantKinds := []api.EventKind{api.EventExecutionStart, api.EventInput, api.EventModelCall, api.EventOutput, api.EventEnd}
	for i, rec := range got.Records {
		if rec.Seq != int64(i+1) || rec.Event.Kind != wantKinds[i] || rec.Event.ExecutionID != got.ExecutionID || rec.Event.SchemaVersion != 0 {
			t.Fatalf("wrong original journal record %d: %+v", i, rec)
		}
	}
	start := got.Records[0].Event.ExecutionStart
	if start.InputCount == nil || *start.InputCount != 1 || start.ResumeFromSeq != 0 || start.Harness != "candidate-"+strings.TrimPrefix(x.Plan().Subject.ProfileDigest, "sha256:") || start.HarnessVersion != RunnerABI {
		t.Fatalf("wrong frozen runner: %+v", start)
	}
	input := got.Records[1].Event.Message.Parts[0].Text.Text
	if fixtureDigest([]byte(input)) != x.Plan().Cases[0].InputDigest || input != "Kia ora 世界\n\r\n\u2028" || got.Records[2].Event.ModelCall.Model != "operator-model" || got.Records[3].Event.Message.Parts[0].Text.Text != "hello yes" || got.Records[4].Event.End.State != "COMPLETED" {
		t.Fatal("input/model/output/end mismatch")
	}
	var body struct {
		Model    string
		Stream   bool
		Messages []struct{ Role, Content string }
	}
	if err := json.Unmarshal(f.bodies[0], &body); err != nil {
		t.Fatal(err)
	}
	if body.Model != "operator-model" || !body.Stream || len(body.Messages) != 2 || body.Messages[0].Role != "system" || body.Messages[0].Content != "System <&> 世界\r\n\u2028\u2029\n" || body.Messages[1].Role != "user" || body.Messages[1].Content != input || f.sends.Load() != 1 || f.journals.Load() != 1 {
		t.Fatalf("candidate did not use exact native context/model: %+v", body)
	}
	if x.Info().AuthoredModel != "author-model-not-host-model" || x.Info().Deployment != "operator-model" {
		t.Fatal("authored and effective models conflated")
	}
}

// Refusing only at HTTP dispatch would already have touched the wrong candidate journal.
func TestCandidateExecutorPreparationRefusals(t *testing.T) {
	for _, name := range []string{"nil policy", "nil credential", "nil journal", "nil package", "legacy", "run", "plan", "endpoint", "scope", "deployment", "extra", "missing", "order", "expiry", "profile", "policy", "judged", "advisory"} {
		t.Run(name, func(t *testing.T) {
			f := newExecutionFixture(t, nil)
			c, e, pkg, run := f.config, f.expected, f.pkg, f.budget.Config
			switch name {
			case "nil policy":
				c.Policy = nil
			case "nil credential":
				c.Credential = nil
			case "nil journal":
				c.Journal = nil
			case "nil package":
				pkg = nil
			case "legacy":
				c.Policy = &modeltransport.Policy{}
			case "run":
				c.RunID = "another-run"
			case "plan":
				run.PlanDigest = "sha256:" + strings.Repeat("a", 64)
			case "endpoint":
				run.Bindings[0].Endpoint = "https://other.invalid/openai/v1/"
			case "scope":
				run.Bindings[0].Scope = "https://other.invalid/.default"
			case "deployment":
				run.Bindings[0].Deployment = "other"
			case "extra":
				run.Slots = append(run.Slots, modeltransport.RunSlot{ID: "extra", BindingID: "candidate"})
			case "missing":
				run.Slots = run.Slots[:len(run.Slots)-1]
			case "order":
				run.Slots[0], run.Slots[1] = run.Slots[1], run.Slots[0]
			case "expiry":
				e.ExpiresAt = e.ExpiresAt.Add(time.Second)
			case "profile":
				e.ProfileDigest = "sha256:" + strings.Repeat("b", 64)
			case "policy":
				e.Binding.Policy = json.RawMessage(`{"changed":true}`)
			case "judged", "advisory":
				cases := preparationCases()
				if name == "judged" {
					score := 75
					cases[0].Assertions[0] = core.EvaluationAssertion{ID: "judge", Type: "llmJudge", Rubric: "rubric", MinScore: &score, JudgeModel: "judge", JudgeVersion: "v1"}
				} else {
					no := false
					cases[0].Assertions[0].Critical = &no
				}
				pkg = preparationFixture(t, cases, nil)
				e = preparationExpected(t, pkg)
				e.Binding = f.expected.Binding
			}
			if name == "plan" || name == "endpoint" || name == "scope" || name == "deployment" || name == "extra" || name == "missing" || name == "order" {
				dir := t.TempDir()
				if err := os.Chmod(dir, 0700); err != nil {
					t.Fatal(err)
				}
				run.LedgerPath = filepath.Join(dir, "different.sqlite")
				var err error
				c.Policy, err = modeltransport.OpenRunPolicy(run)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = c.Policy.Close() })
			}
			x, err := NewCandidateExecutor(pkg, e, c)
			if x != nil || err == nil || f.journals.Load() != 0 || f.credential.calls.Load() != 0 || f.sends.Load() != 0 {
				t.Fatalf("refusal was late or absent: %v", err)
			}
			if (name == "judged" || name == "advisory") && !errors.Is(err, ErrPreparation) {
				t.Fatalf("unsupported package reached budget stage: %v", err)
			}
		})
	}
}

func TestCandidateExecutorOwnedCopies(t *testing.T) {
	f := newExecutionFixture(t, nil)
	x, err := NewCandidateExecutor(f.pkg, f.expected, f.config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = x.Close() })
	plan, calls := x.Plan(), x.Calls()
	plan.Cases[0].Assertions[0].Value = "mutated"
	plan.Members[0].ID = "mutated"
	plan.Cases[0].InputDigest = "mutated"
	calls[0].SlotID = "mutated"
	f.expected.Binding.Policy[0] = '['
	f.expected.Binding.Deployment = "mutated"
	f.config.Journal = func(string) (eventlog.Store, error) {
		t.Error("caller changed frozen callback")
		return nil, errors.New("mutated")
	}
	got, err := x.Execute(t.Context(), f.budget.Calls[0].SlotID)
	if err != nil || got.Records[2].Event.ModelCall.Model != "operator-model" || x.Plan().Cases[0].Assertions[0].Value != "hello" || x.Plan().Members[0].ID != "writer" || x.Calls()[0] != f.budget.Calls[0] {
		t.Fatalf("mutable caller/output changed runtime: %v", err)
	}
}

func TestCandidateModelRefusesParams(t *testing.T) {
	calls := 0
	fn := candidateStream("operator-model", func(ctx context.Context, req api.ModelRequest, _ func(string)) (api.ModelResponse, error) {
		calls++
		deadline, ok := ctx.Deadline()
		if !ok || deadline.After(time.Now().Add(25*time.Second)) || req.Model != "operator-model" {
			t.Fatal("model/deadline escaped host policy")
		}
		return api.ModelResponse{}, nil
	})
	if _, err := fn(t.Context(), api.ModelRequest{Params: map[string]string{"temperature": "0.2"}}, nil); err == nil || calls != 0 {
		t.Fatal("unsupported params reached model")
	}
	req := api.ModelRequest{Model: "authored-model"}
	if _, err := fn(t.Context(), req, nil); err != nil || calls != 1 || req.Model != "authored-model" {
		t.Fatal("model copy/default failed")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Millisecond)
	defer cancel()
	if _, err := fn(ctx, req, nil); err != nil || calls != 2 {
		t.Fatal("bounded parent failed")
	}
}
