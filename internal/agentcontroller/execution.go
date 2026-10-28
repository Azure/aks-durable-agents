package agentcontroller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Azure/aks-durable-agents/internal/agentpackage"
	"github.com/Azure/aks-durable-agents/internal/qualification"
	"github.com/Azure/aks-durable-agents/modeltransport"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/agent-primitives/sessions/api"
	"github.com/agent-primitives/sessions/controller"
	"github.com/agent-primitives/sessions/eventlog"
	"github.com/agent-primitives/sessions/model/openai"
)

var ErrCandidateExecution = errors.New("candidate execution refused")

// ExecutionConfig is trusted host wiring. Journal must return a fresh candidate
// log, never a log from the serving store. No RPC accepts this configuration.
// The caller owns Policy and the journal backend; credentials stay host-side.
type ExecutionConfig struct {
	RunID      string
	Policy     *modeltransport.Policy
	Credential azcore.TokenCredential
	Transport  *http.Transport
	Journal    func(sessionID string) (eventlog.Store, error)
}

type CandidateExecutor struct {
	info    qualification.ExecutionInfo
	plan    qualification.Plan
	calls   []qualification.BudgetCall
	inputs  map[string]string
	harness *frozenHarness
	binding modeltransport.RunBinding
	config  ExecutionConfig

	mu           sync.Mutex
	next         int
	failed       bool
	closed       bool
	activeCancel context.CancelFunc
	activeDone   chan struct{}
}

var _ qualification.Executor = (*CandidateExecutor)(nil)

// NewCandidateExecutor reconstructs the native plan from verified package bytes.
// It compares only the Policy's own immutable snapshot, not an operator JSON file.
// Construction performs no journal, credential or provider I/O.
func NewCandidateExecutor(p *agentpackage.Package, e CandidateExpectations, c ExecutionConfig) (*CandidateExecutor, error) {
	if c.Policy == nil || c.Credential == nil || c.Journal == nil {
		return nil, ErrCandidateExecution
	}
	prepared, err := PrepareCandidate(p, e)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCandidateExecution, err)
	}
	// Mirror the existing v4 snapshot envelope solely for exact comparison.
	var snapshot struct {
		Version int `json:"version"`
		modeltransport.RunConfig
	}
	if json.Unmarshal(c.Policy.Snapshot(), &snapshot) != nil || snapshot.Version != 4 || snapshot.RunID != c.RunID || len(snapshot.Bindings) != 1 {
		return nil, ErrCandidateExecution
	}
	budget, err := PrepareRunBudget(prepared, e.Binding, qualification.BudgetRequest{
		RunID: c.RunID, LedgerPath: snapshot.LedgerPath, MaxInputTokens: snapshot.MaxInputTokens, Candidate: snapshot.Bindings[0],
	})
	if err != nil {
		return nil, fmt.Errorf("%w: budget binding", ErrCandidateExecution)
	}
	snapshot.RunConfig = budget.Config
	encoded, err := json.Marshal(snapshot)
	if err != nil || !bytes.Equal(encoded, c.Policy.Snapshot()) {
		return nil, fmt.Errorf("%w: run inventory", ErrCandidateExecution)
	}
	h, err := packagedHarness(p, definition{Spec: Spec{Member: e.MemberID}, Model: prepared.Summary.Model,
		Harness: "candidate-" + strings.TrimPrefix(prepared.Plan.Subject.ProfileDigest, "sha256:")})
	if err != nil {
		return nil, ErrCandidateExecution
	}
	inputs := make(map[string]string, len(prepared.Plan.Cases))
	for i, call := range prepared.Plan.Cases {
		inputs[call.ID] = prepared.Summary.Cases[i].Input
	}
	if c.Transport != nil {
		c.Transport = c.Transport.Clone()
	}
	return &CandidateExecutor{info: qualification.ExecutionInfo{RunID: c.RunID, PlanDigest: budget.Config.PlanDigest,
		AuthoredModel: prepared.Summary.AuthoredModel, Deployment: prepared.Summary.Model},
		plan: prepared.Plan, calls: budget.Calls, inputs: inputs, harness: h, binding: budget.Config.Bindings[0], config: c}, nil
}

func (x *CandidateExecutor) Info() qualification.ExecutionInfo { return x.info }
func (x *CandidateExecutor) Calls() []qualification.BudgetCall { return slices.Clone(x.calls) }
func (x *CandidateExecutor) Plan() qualification.Plan {
	p := x.plan
	p.Members = slices.Clone(p.Members)
	p.Cases = slices.Clone(p.Cases)
	for i := range p.Cases {
		p.Cases[i].Assertions = slices.Clone(p.Cases[i].Assertions)
	}
	return p
}

// Execute admits the next planned call only. A mechanical failure stops this
// executor even when the provider finished but journal readback was unavailable.
func (x *CandidateExecutor) Execute(ctx context.Context, slot string) (qualification.ExecutionJournal, error) {
	x.mu.Lock()
	if x.closed || x.failed || x.activeDone != nil || x.next >= len(x.calls) || x.calls[x.next].SlotID != slot {
		x.mu.Unlock()
		return qualification.ExecutionJournal{}, ErrCandidateExecution
	}
	if err := ctx.Err(); err != nil {
		x.failed = true
		x.mu.Unlock()
		return qualification.ExecutionJournal{}, err
	}
	run, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	call := x.calls[x.next]
	x.activeCancel, x.activeDone = cancel, done
	x.mu.Unlock()

	result, err := x.execute(run, call)
	x.mu.Lock()
	if err == nil {
		err = run.Err()
	}
	if err != nil {
		x.failed = true
		result = qualification.ExecutionJournal{}
	} else {
		x.next++
	}
	x.activeCancel, x.activeDone = nil, nil
	close(done)
	x.mu.Unlock()
	cancel()
	return result, err
}

func (x *CandidateExecutor) execute(ctx context.Context, call qualification.BudgetCall) (qualification.ExecutionJournal, error) {
	slot := call.SlotID
	uid := qualification.CandidateSessionID(x.info.RunID, slot)
	log, err := x.config.Journal(uid)
	if err != nil {
		return qualification.ExecutionJournal{}, err
	}
	if log == nil {
		return qualification.ExecutionJournal{}, ErrCandidateExecution
	}
	head, err := log.Head()
	if err != nil {
		return qualification.ExecutionJournal{}, fmt.Errorf("%w: journal head: %w", ErrCandidateExecution, err)
	}
	if head != 0 {
		return qualification.ExecutionJournal{}, ErrCandidateExecution
	}
	client, err := modeltransport.NewClient(modeltransport.Config{Endpoint: x.binding.Endpoint, Deployment: x.binding.Deployment,
		Scope: x.binding.Scope, Credential: x.config.Credential, Transport: x.config.Transport, Policy: x.config.Policy, CallSlot: slot})
	if err != nil {
		return qualification.ExecutionJournal{}, err
	}
	defer client.CloseIdleConnections()
	model, err := openai.New(openai.WithBaseURL(x.binding.Endpoint), openai.WithModel(x.binding.Deployment), openai.WithHTTPClient(client))
	if err != nil {
		return qualification.ExecutionJournal{}, err
	}
	c, err := controller.New(log, nil, controller.WithSessionUID(uid), controller.WithHarness(x.harness.name),
		controller.WithModelPolicy(api.ModelPolicy{Default: x.binding.Deployment, Allowed: []string{x.binding.Deployment}}),
		controller.WithStreamingModel(candidateStream(x.binding.Deployment, model.StreamModel)))
	if err != nil {
		return qualification.ExecutionJournal{}, err
	}
	if err := c.Exec(ctx, x.harness, []api.Message{*api.TextMessage("user", x.inputs[call.CaseID])}, 0); err != nil {
		return qualification.ExecutionJournal{}, err
	}
	head, err = log.Head()
	if err != nil {
		return qualification.ExecutionJournal{}, err
	}
	records, err := log.Read(1)
	if err != nil {
		return qualification.ExecutionJournal{}, fmt.Errorf("%w: journal readback: %w", ErrCandidateExecution, err)
	}
	if len(records) == 0 || head != int64(len(records)) || eventlog.VerifyChain("", records) != nil {
		return qualification.ExecutionJournal{}, fmt.Errorf("%w: journal readback", ErrCandidateExecution)
	}
	return qualification.ExecutionJournal{RunID: x.info.RunID, PlanDigest: x.info.PlanDigest, Call: call, SessionID: uid,
		ExecutionID: records[0].Event.ExecutionID, HeadHash: records[len(records)-1].Hash, Count: len(records), Records: records}, nil
}

func candidateStream(deployment string, next controller.StreamFunc) controller.StreamFunc {
	return func(ctx context.Context, req api.ModelRequest, chunk func(string)) (api.ModelResponse, error) {
		if len(req.Params) != 0 {
			return api.ModelResponse{}, fmt.Errorf("%w: model parameters", ErrCandidateExecution)
		}
		bounded, cancel := context.WithTimeout(ctx, 25*time.Second)
		defer cancel()
		req.Model = deployment
		return next(bounded, req, chunk)
	}
}

// Close cancels and drains only this executor's work. Its caller must keep the
// supplied journal backend and shared Policy open until Close has returned.
func (x *CandidateExecutor) Close() error {
	x.mu.Lock()
	x.closed = true
	if x.activeCancel != nil {
		x.activeCancel()
	}
	done := x.activeDone
	x.mu.Unlock()
	if done != nil {
		<-done
	}
	return nil
}
