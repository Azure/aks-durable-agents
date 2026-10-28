package qualification

import (
	"context"

	"github.com/agent-primitives/sessions/eventlog"
)

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
