package qualification

import (
	"bytes"
	"encoding/json"

	"github.com/Azure/aks-durable-agents/modeltransport"
)

// BudgetRequest supplies trusted host bindings, not a package or a verdict.
// Judge bindings currently have no package-derived provenance contract: this
// preflight reserves spend only and cannot authorize judge execution.
type BudgetRequest struct {
	Plan              Plan
	RunID, LedgerPath string
	MaxInputTokens    *int
	Candidate         modeltransport.RunBinding
	Judges            map[string]modeltransport.RunBinding
}

// BudgetCall maps an opaque transport slot to one required semantic call.
// Run is one-based. JudgeSample is 1/2 for judges, zero for candidates.
type BudgetCall struct {
	SlotID, BindingID, CaseID, AssertionID string
	Run, JudgeSample                       int
}

func budgetSlotID(planDigest, caseID, assertionID string, run, sample int) string {
	return objectDigest("qualification-budget-slot-v1", struct {
		PlanDigest, CaseID, AssertionID string
		Run, Sample                     int
	}{planDigest, caseID, assertionID, run, sample})
}

type PreparedBudget struct {
	Config modeltransport.RunConfig
	Calls  []BudgetCall
}

// PrepareRunBudget derives the entire bounded inventory before allocating any
// ledger or transport. It neither mutates Plan nor replaces its serving policy.
// Native callers must also anchor the candidate tuple via agentcontroller's
// preparation wrapper. Neither function establishes qualification authority.
func PrepareRunBudget(r BudgetRequest) (PreparedBudget, error) {
	if err := ValidatePlan(r.Plan); err != nil {
		return PreparedBudget{}, err
	}
	if ValidateModelLabel(r.Candidate.Deployment) != nil {
		return PreparedBudget{}, ErrInvalid
	}
	plan := normalize(Request{Plan: r.Plan}).Plan
	result := PreparedBudget{Config: modeltransport.RunConfig{RunID: r.RunID, LedgerPath: r.LedgerPath, PlanDigest: objectDigest("qualification-plan-v1", plan), MaxInputTokens: r.MaxInputTokens}}
	bindings := map[string][]byte{}
	usedJudges := map[string]bool{}
	addBinding := func(b modeltransport.RunBinding) bool {
		data, err := json.Marshal(b)
		if err != nil {
			return false
		}
		if prior, ok := bindings[b.ID]; ok {
			return bytes.Equal(prior, data)
		}
		bindings[b.ID] = data
		result.Config.Bindings = append(result.Config.Bindings, b)
		return true
	}
	if !addBinding(r.Candidate) {
		return PreparedBudget{}, ErrInvalid
	}
	appendCall := func(caseID string, run int, assertionID string, sample int, bindingID string) {
		id := budgetSlotID(result.Config.PlanDigest, caseID, assertionID, run, sample)
		result.Calls = append(result.Calls, BudgetCall{SlotID: id, BindingID: bindingID, CaseID: caseID, AssertionID: assertionID, Run: run, JudgeSample: sample})
		result.Config.Slots = append(result.Config.Slots, modeltransport.RunSlot{ID: id, BindingID: bindingID})
	}
	for _, c := range plan.Cases {
		for run := 1; run <= c.Runs; run++ {
			appendCall(c.ID, run, "", 0, r.Candidate.ID)
			for _, a := range c.Assertions {
				if a.Kind != "llmJudge" {
					continue
				}
				b, ok := r.Judges[a.JudgeModel]
				if !ok || b.Deployment != a.JudgeModel || !addBinding(b) {
					return PreparedBudget{}, ErrInvalid
				}
				usedJudges[a.JudgeModel] = true
				appendCall(c.ID, run, a.ID, 1, b.ID)
				appendCall(c.ID, run, a.ID, 2, b.ID)
			}
		}
	}
	if len(usedJudges) != len(r.Judges) {
		return PreparedBudget{}, ErrInvalid
	}
	if err := modeltransport.ValidateRunConfig(result.Config); err != nil {
		return PreparedBudget{}, err
	}
	return result, nil
}
