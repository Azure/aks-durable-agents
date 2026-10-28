package qualification

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

type runJob struct {
	cancel context.CancelFunc
	done   chan struct{}
}

// ExecutionScopeForRecord locates already-started run artifacts from readback.
// Interrupt fences the lease by incrementing Generation; artifacts still belong
// to the preceding generation. This identity grants no execution authority.
func ExecutionScopeForRecord(r Record) ExecutionScope {
	if r.Generation == 0 {
		return ExecutionScope{}
	}
	if r.State == Incomplete && r.Reason == "interrupted" {
		r.Generation--
	}
	return ExecutionScope{RunID: objectDigest("qualification-run-v1", struct {
		Lineage, RecordID string
		Generation        int64
	}{r.Lineage, r.ID, r.Generation}), PlanDigest: r.PlanDigest}
}

// Run is a host-only no-judge orchestration path, not admission or activation
// authority. Factory is trusted host code, never caller-uploaded executable logic.
// A record may dispatch once; repeat/recovery calls never adopt a run directory.
func (s *Store) Run(ctx context.Context, id string, create ExecutorFactory) (Record, error) {
	s.mu.Lock()
	if s.closing || s.db == nil {
		s.mu.Unlock()
		return Record{}, ErrUnavailable
	}
	r, err := s.read(ctx, id)
	if err != nil {
		s.mu.Unlock()
		return Record{}, err
	}
	if terminal(r.State) {
		s.mu.Unlock()
		return r, nil
	}
	if s.active[id] != nil {
		s.mu.Unlock()
		return r, ErrConflict
	}
	run, cancel := context.WithCancel(ctx)
	job := &runJob{cancel: cancel, done: make(chan struct{})}
	if s.active == nil {
		s.active = map[string]*runJob{}
	}
	s.active[id] = job
	s.mu.Unlock()
	defer func() { cancel(); s.mu.Lock(); delete(s.active, id); close(job.done); s.mu.Unlock() }()
	l := lease{ID: r.ID, Generation: r.Generation}
	if r.State == Running {
		return s.interrupt(context.WithoutCancel(run), l)
	}
	if r.State == Verifying {
		return s.complete(run, l, r.Observations)
	}
	if create == nil {
		return r, ErrInvalid
	}
	l, err = s.start(run, id)
	if err != nil {
		return r, err
	}
	r, err = s.Read(run, id)
	if err != nil {
		_, cleanup := s.interrupt(context.WithoutCancel(run), l)
		return Record{}, errors.Join(err, cleanup)
	}
	var x Executor
	closeExecutor := func() error {
		if x == nil {
			return nil
		}
		owned := x
		x = nil
		return owned.Close()
	}
	failure := func(cause error) (Record, error) {
		cause = errors.Join(cause, closeExecutor())
		current, e := s.Read(context.WithoutCancel(run), id)
		if e != nil {
			return Record{}, errors.Join(cause, e)
		}
		// complete may have durably retained Verifying intent before failing. Leave
		// that intent available for evidence-only completion, never blanket-interrupt.
		if current.State == Running && current.Generation == l.Generation {
			current, e = s.interrupt(context.WithoutCancel(run), l)
		}
		return current, errors.Join(cause, e)
	}
	if err = run.Err(); err != nil {
		return failure(err)
	}
	if !time.Now().Before(r.Request.Plan.ExpiresAt) {
		return failure(ErrIneligible)
	}
	for _, c := range r.Request.Plan.Cases {
		for _, a := range c.Assertions {
			if a.Kind == "llmJudge" {
				return failure(ErrInvalid)
			}
		}
	}
	scope := ExecutionScopeForRecord(r)
	x, err = create(run, scope)
	if err != nil {
		return failure(err)
	}
	if x == nil {
		return failure(ErrIntegrity)
	}
	info := x.Info()
	plan := normalize(Request{Plan: x.Plan()}).Plan
	calls := x.Calls()
	if info.RunID != scope.RunID || info.PlanDigest != r.PlanDigest || ValidateModelLabel(info.Deployment) != nil || ValidateModelLabel(info.AuthoredModel) != nil || objectDigest("qualification-plan-v1", plan) != r.PlanDigest {
		return failure(ErrIntegrity)
	}
	expected := []BudgetCall{}
	binding := ""
	if len(calls) > 0 {
		binding = calls[0].BindingID
	}
	if !validID(binding) {
		return failure(ErrIntegrity)
	}
	for _, c := range r.Request.Plan.Cases {
		for n := 1; n <= c.Runs; n++ {
			expected = append(expected, BudgetCall{SlotID: budgetSlotID(r.PlanDigest, c.ID, "", n, 0), BindingID: binding, CaseID: c.ID, Run: n})
		}
	}
	if len(calls) != len(expected) {
		return failure(ErrIntegrity)
	}
	for i := range expected {
		if calls[i] != expected[i] {
			return failure(ErrIntegrity)
		}
	}
	observations := make([]Observation, 0, len(calls))
	used := map[string]bool{}
	for _, call := range calls {
		if err = run.Err(); err != nil {
			return failure(err)
		}
		j, e := x.Execute(run, call.SlotID)
		if e != nil {
			return failure(e)
		}
		if j.RunID != scope.RunID || j.PlanDigest != r.PlanDigest || j.Call != call || j.SessionID != CandidateSessionID(scope.RunID, call.SlotID) || j.Count != len(j.Records) || j.Count < 5 || j.Count > 6 {
			return failure(ErrIntegrity)
		}
		data, e := json.Marshal(j.Records)
		if e != nil {
			return failure(e)
		}
		blob, e := s.retain(data)
		if e != nil {
			return failure(e)
		}
		anchor := Journal{SessionID: j.SessionID, ExecutionID: j.ExecutionID, HeadHash: j.HeadHash, Count: j.Count, Blob: blob}
		s.mu.Lock()
		input, _, e := s.journal(anchor, used, info.Deployment)
		s.mu.Unlock()
		if e != nil {
			return failure(e)
		}
		for _, c := range r.Request.Plan.Cases {
			if c.ID == call.CaseID && hashBytes([]byte(input)) != c.InputDigest {
				return failure(ErrIntegrity)
			}
		}
		observations = append(observations, Observation{CaseID: call.CaseID, Run: call.Run, Candidate: anchor})
	}
	if err = closeExecutor(); err != nil {
		return failure(err)
	}
	if err = run.Err(); err != nil {
		return failure(err)
	}
	result, err := s.complete(run, l, observations)
	if err != nil {
		return failure(err)
	}
	return result, nil
}
