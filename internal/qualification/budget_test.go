package qualification

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Azure/aks-durable-agents/modeltransport"
)

func budgetBinding(id, model string) modeltransport.RunBinding {
	zero := int64(0)
	return modeltransport.RunBinding{ID: id, Endpoint: "https://example.invalid/openai/v1/", Scope: modeltransport.DefaultScope, Deployment: model, Pricing: modeltransport.RunPricing{Input: 100000, Output: 500000, Extra: &zero, Source: "https://example.invalid/pricing", AsOf: "2026-10-27"}}
}
func budgetRequest(t *testing.T) BudgetRequest {
	t.Helper()
	return BudgetRequest{Plan: testPlan(), RunID: "budget-run", LedgerPath: filepath.Join(privateTestDir(t), "run.sqlite"), Candidate: budgetBinding("candidate", "candidate-deployment")}
}

// Dropping repetitions/assertions or using one judge sample must change the semantic inventory.
func TestPrepareRunBudgetInventory(t *testing.T) {
	r := budgetRequest(t)
	r.Plan.Cases[0].Runs = 2
	r.Plan.Cases[0].Assertions = append(r.Plan.Cases[0].Assertions,
		Assertion{ID: "quality", Kind: "llmJudge", MinScore: 70, JudgeModel: "judge-deployment"},
		Assertion{ID: "accuracy", Kind: "llmJudge", MinScore: 80, JudgeModel: "judge-deployment"})
	second := testPlan().Cases[0]
	second.ID = "second"
	r.Plan.Cases = append(r.Plan.Cases, second)
	r.Judges = map[string]modeltransport.RunBinding{"judge-deployment": budgetBinding("judge", "judge-deployment")}
	got, err := PrepareRunBudget(r)
	if err != nil {
		t.Fatal(err)
	}
	var tuples []string
	seen := map[string]bool{}
	for _, c := range got.Calls {
		tuples = append(tuples, fmt.Sprintf("%s/%d/%s/%d/%s", c.CaseID, c.Run, c.AssertionID, c.JudgeSample, c.BindingID))
		if !validDigest(c.SlotID) || seen[c.SlotID] {
			t.Fatal("invalid or duplicate slot identity")
		}
		seen[c.SlotID] = true
	}
	want := []string{"case/1//0/candidate", "case/1/quality/1/judge", "case/1/quality/2/judge", "case/1/accuracy/1/judge", "case/1/accuracy/2/judge", "case/2//0/candidate", "case/2/quality/1/judge", "case/2/quality/2/judge", "case/2/accuracy/1/judge", "case/2/accuracy/2/judge", "second/1//0/candidate"}
	if !reflect.DeepEqual(tuples, want) {
		t.Fatalf("inventory %v", tuples)
	}
	if len(got.Config.Slots) != 11 || len(got.Config.Bindings) != 2 {
		t.Fatalf("budget shape %+v", got.Config)
	}
	for i, c := range got.Calls {
		if got.Config.Slots[i].ID != c.SlotID || got.Config.Slots[i].BindingID != c.BindingID {
			t.Fatal("budget detached from inventory")
		}
	}
	if got.Config.PlanDigest != objectDigest("qualification-plan-v1", normalize(Request{Plan: r.Plan}).Plan) {
		t.Fatal("different qualification plan identity")
	}
	original := got.Config.PlanDigest
	r.Plan.Cases[0].Assertions[1].MinScore++
	changed, err := PrepareRunBudget(r)
	if err != nil {
		t.Fatal(err)
	}
	if changed.Config.PlanDigest == original || changed.Calls[0].SlotID == got.Calls[0].SlotID {
		t.Fatal("changed plan reused budget identity")
	}
	if _, err = os.Stat(r.LedgerPath); !os.IsNotExist(err) {
		t.Fatal("pure preparation opened ledger")
	}
}

func TestPrepareRunBudgetRefusalBeforeEffects(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*BudgetRequest)
	}{
		{"missing judge", func(r *BudgetRequest) {
			r.Plan.Cases[0].Assertions = []Assertion{{ID: "j", Kind: "llmJudge", MinScore: 50, JudgeModel: "judge-deployment"}}
		}},
		{"extra judge", func(r *BudgetRequest) {
			r.Judges = map[string]modeltransport.RunBinding{"unused": budgetBinding("judge", "unused")}
		}},
		{"mismatched judge label", func(r *BudgetRequest) {
			r.Plan.Cases[0].Assertions = []Assertion{{ID: "j", Kind: "llmJudge", MinScore: 50, JudgeModel: "judge-deployment"}}
			r.Judges = map[string]modeltransport.RunBinding{"judge-deployment": budgetBinding("judge", "other")}
		}},
		{"conflicting binding identity", func(r *BudgetRequest) {
			r.Plan.Cases[0].Assertions = []Assertion{{ID: "j", Kind: "llmJudge", MinScore: 50, JudgeModel: "judge-deployment"}}
			r.Judges = map[string]modeltransport.RunBinding{"judge-deployment": budgetBinding("candidate", "judge-deployment")}
		}},
		{"over64", func(r *BudgetRequest) {
			base := r.Plan.Cases[0]
			r.Plan.Cases = nil
			for i := 0; i < 22; i++ {
				c := base
				c.ID = fmt.Sprint(i)
				c.Assertions = []Assertion{{ID: "j", Kind: "llmJudge", MinScore: 50, JudgeModel: "judge-deployment"}}
				r.Plan.Cases = append(r.Plan.Cases, c)
			}
			r.Judges = map[string]modeltransport.RunBinding{"judge-deployment": budgetBinding("judge", "judge-deployment")}
		}},
		{"combined cost", func(r *BudgetRequest) {
			r.Plan.Cases[0].Runs = 2
			r.Plan.Cases[0].Assertions = []Assertion{{ID: "j", Kind: "llmJudge", MinScore: 50, JudgeModel: "judge-deployment"}}
			r.Candidate.Pricing.Input = 50000000
			r.Candidate.Pricing.Output = 1
			j := budgetBinding("judge", "judge-deployment")
			j.Pricing.Input = 50000000
			j.Pricing.Output = 1
			r.Judges = map[string]modeltransport.RunBinding{"judge-deployment": j}
		}},
		{"metadata bound", func(r *BudgetRequest) { r.Plan.Cases[0].Assertions[0].Value = strings.Repeat("a", 4097) }},
		{"invalid candidate model", func(r *BudgetRequest) { r.Candidate.Deployment = "not a model label" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := budgetRequest(t)
			tc.change(&r)
			if _, err := PrepareRunBudget(r); err == nil {
				t.Fatal("whole inventory accepted")
			}
			if _, err := os.Stat(r.LedgerPath); !os.IsNotExist(err) {
				t.Fatal("refusal created ledger")
			}
		})
	}
}

func TestPrepareRunBudget64AndDigestDirection(t *testing.T) {
	r := budgetRequest(t)
	r.Plan.Cases[0].Runs = 64
	before := r.Plan.Subject.PolicyDigest
	got, err := PrepareRunBudget(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Calls) != 64 || got.Calls[63].Run != 64 || len(got.Config.Slots) != 64 {
		t.Fatal("64-slot bound truncated")
	}
	if r.Plan.Subject.PolicyDigest != before {
		t.Fatal("run policy fed back into serving policy digest")
	}
	p, err := modeltransport.OpenRunPolicy(got.Config)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if p.AttemptLimit() != 64 || p.InputLimit() != 8192 {
		t.Fatal("reservation envelope changed")
	}
	changed := r
	changed.Plan = testPlan()
	changed.Plan.Subject.ModelDigest = digest("9")
	other, err := PrepareRunBudget(changed)
	if err != nil {
		t.Fatal(err)
	}
	if other.Config.PlanDigest == got.Config.PlanDigest {
		t.Fatal("model subject omitted from plan digest")
	}
}
