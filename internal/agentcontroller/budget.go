package agentcontroller

import (
	"github.com/Azure/aks-durable-agents/internal/qualification"
	"github.com/Azure/aks-durable-agents/modeltransport"
)

// PrepareRunBudget anchors the candidate budget tuple to the prepared native
// model identity. It takes inventory from candidate, not request.Plan. Neither
// this pure check nor the returned budget authorizes execution or qualification;
// package-derived judge bindings and the runner remain separate work.
func PrepareRunBudget(candidate PreparedCandidate, binding NativeBinding, request qualification.BudgetRequest) (qualification.PreparedBudget, error) {
	if binding.Scope == "" {
		binding.Scope = modeltransport.DefaultScope
	}
	b := request.Candidate
	if b.Endpoint != binding.Endpoint || b.Deployment != binding.Deployment || b.Scope != binding.Scope {
		return qualification.PreparedBudget{}, ErrPreparation
	}
	digest := preparationDigest("candidate-model-v1", struct{ Endpoint, Deployment, Scope string }{binding.Endpoint, binding.Deployment, binding.Scope})
	if digest != candidate.Plan.Subject.ModelDigest {
		return qualification.PreparedBudget{}, ErrPreparation
	}
	request.Plan = candidate.Plan
	return qualification.PrepareRunBudget(request)
}
