package qualification

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/agent-primitives/sessions/eventlog"
)

// ExecutionScope is a non-authorizing identity supplied by the durable runner.
type ExecutionScope struct{ RunID, PlanDigest string }

type ExecutorFactory func(context.Context, ExecutionScope) (Executor, error)

// CandidateSessionID binds a semantic slot to one run; it is not admission authority.
func CandidateSessionID(runID, slotID string) string {
	data, _ := json.Marshal(struct{ Domain, RunID, SlotID string }{"qualification-candidate-session-v1", runID, slotID})
	return fmt.Sprintf("candidate-%x", sha256.Sum256(data))
}

// ExecutionInfo describes a trusted host executor, not qualification or authority.
// Deployment is the selected host binding, not a provider attestation.
type ExecutionInfo struct {
	RunID, PlanDigest, AuthoredModel, Deployment string
}

// ExecutionJournal carries original producer records and separately captured
// anchors. The future orchestrator retains them before deriving any verdict.
type ExecutionJournal struct {
	RunID, PlanDigest, SessionID, ExecutionID, HeadHash string
	Call                                                BudgetCall
	Count                                               int
	Records                                             []eventlog.Record
}

// Executor is a host-owned execution seam, never a caller-supplied verdict or
// untrusted plugin. Its journal backing and run identity are host responsibilities.
// Close drains executor work; ownership of supplied storage/policy stays with its caller.
type Executor interface {
	Info() ExecutionInfo
	Plan() Plan
	Calls() []BudgetCall
	Execute(context.Context, string) (ExecutionJournal, error)
	Close() error
}
