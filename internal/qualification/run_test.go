package qualification

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Azure/aks-durable-agents/modeltransport"
)

type runExecutor struct {
	t                *testing.T
	record           Record
	scope            ExecutionScope
	calls            []BudgetCall
	executed, closed atomic.Int32
	execute          func(context.Context, BudgetCall) (ExecutionJournal, error)
	onClose          func() error
}

func (x *runExecutor) Info() ExecutionInfo {
	return ExecutionInfo{x.scope.RunID, x.scope.PlanDigest, "authored", "model"}
}
func (x *runExecutor) Plan() Plan          { return x.record.Request.Plan }
func (x *runExecutor) Calls() []BudgetCall { return x.calls }
func (x *runExecutor) Close() error {
	x.closed.Add(1)
	if x.onClose != nil {
		return x.onClose()
	}
	return nil
}
func (x *runExecutor) Execute(ctx context.Context, slot string) (ExecutionJournal, error) {
	n := int(x.executed.Add(1)) - 1
	c := x.calls[n]
	if c.SlotID != slot {
		x.t.Fatal("wrong order")
	}
	if x.execute != nil {
		return x.execute(ctx, c)
	}
	records := journalRecords(x.t, "execution-"+string(rune('a'+n)), "question", "hello", "model")
	return ExecutionJournal{RunID: x.scope.RunID, PlanDigest: x.scope.PlanDigest, Call: c, SessionID: CandidateSessionID(x.scope.RunID, c.SlotID), ExecutionID: records[0].Event.ExecutionID, HeadHash: records[len(records)-1].Hash, Count: len(records), Records: records}, nil
}
func runFactory(t *testing.T, r Record) (ExecutorFactory, **runExecutor, *atomic.Int32) {
	t.Helper()
	var x *runExecutor
	var made atomic.Int32
	factory := func(ctx context.Context, scope ExecutionScope) (Executor, error) {
		made.Add(1)
		zero := int64(0)
		b, e := PrepareRunBudget(BudgetRequest{Plan: r.Request.Plan, RunID: scope.RunID, LedgerPath: filepath.Join(privateTestDir(t), "budget"), Candidate: modeltransport.RunBinding{ID: "candidate", Endpoint: "https://example.invalid/openai/v1/", Scope: modeltransport.DefaultScope, Deployment: "model", Pricing: modeltransport.RunPricing{Input: 1, Output: 1, Extra: &zero, Source: "https://example.invalid/prices", AsOf: "2026-10-28"}}})
		if e != nil {
			t.Fatal(e)
		}
		x = &runExecutor{t: t, record: r, scope: scope, calls: b.Calls}
		return x, nil
	}
	return factory, &x, &made
}
func TestRunRetainsAndRecomputes(t *testing.T) {
	s, _ := testStore(t)
	r := admit(t, s)
	factory, x, made := runFactory(t, r)
	got, err := s.Run(context.Background(), r.ID, factory)
	if err != nil || got.State != Passed || len(got.Observations) != 1 {
		t.Fatalf("completion: %+v %v", got, err)
	}
	if made.Load() != 1 || (*x).executed.Load() != 1 || (*x).closed.Load() != 1 {
		t.Fatal("wrong lifecycle")
	}
	if _, err = s.VerifyForActivation(context.Background(), r.ID, r.Request.Plan, got.CompletedAt); err != nil {
		t.Fatal(err)
	}
	repeat, err := s.Run(context.Background(), r.ID, factory)
	if err != nil || repeat.Digest != got.Digest || made.Load() != 1 {
		t.Fatal("redispatch")
	}
}
func TestRunRejectsMismatchesBeforeExecution(t *testing.T) {
	for _, name := range []string{"scope", "plan", "calls", "factory", "nil"} {
		t.Run(name, func(t *testing.T) {
			s, _ := testStore(t)
			r := admit(t, s)
			factory, x, made := runFactory(t, r)
			altered := func(ctx context.Context, scope ExecutionScope) (Executor, error) {
				e, err := factory(ctx, scope)
				if err != nil {
					return nil, err
				}
				switch name {
				case "scope":
					(*x).scope.RunID = "other"
				case "plan":
					(*x).record.Request.Plan.Platform = "other"
				case "calls":
					(*x).calls[0].CaseID = "other"
				case "factory":
					return e, ErrInvalid
				case "nil":
					return nil, nil
				}
				return e, nil
			}
			got, err := s.Run(context.Background(), r.ID, altered)
			if err == nil || got.State != Incomplete || made.Load() != 1 || (*x).executed.Load() != 0 {
				t.Fatalf("mismatch: %+v %v", got, err)
			}
			if name != "nil" && (*x).closed.Load() != 1 {
				t.Fatal("leaked executor")
			}
			_, _ = s.Run(context.Background(), r.ID, altered)
			if made.Load() != 1 {
				t.Fatal("retried refusal")
			}
		})
	}
}
func TestRunFailureStopsAndRetainsOwner(t *testing.T) {
	for _, name := range []string{"provider", "oversize", "cross-run", "close"} {
		t.Run(name, func(t *testing.T) {
			s, _ := testStore(t)
			p := testPlan()
			p.Cases[0].Runs = 2
			r, err := s.Admit(context.Background(), Request{Key: "key", Requester: "caller", Plan: p})
			if err != nil {
				t.Fatal(err)
			}
			factory, x, made := runFactory(t, r)
			wrapped := func(ctx context.Context, scope ExecutionScope) (Executor, error) {
				e, er := factory(ctx, scope)
				if er != nil {
					return nil, er
				}
				if name == "close" {
					(*x).onClose = func() error { return ErrUnavailable }
				} else {
					(*x).execute = func(ctx context.Context, c BudgetCall) (ExecutionJournal, error) {
						if name == "provider" {
							return ExecutionJournal{}, ErrUnavailable
						}
						input := "question"
						if name == "oversize" {
							input = strings.Repeat("q", maxBlobBytes+1)
						}
						records := journalRecords(t, "execution", input, "hello", "model")
						uid := CandidateSessionID(scope.RunID, c.SlotID)
						if name == "cross-run" {
							uid = CandidateSessionID("other", c.SlotID)
						}
						return ExecutionJournal{RunID: scope.RunID, PlanDigest: scope.PlanDigest, Call: c, SessionID: uid, ExecutionID: "execution", HeadHash: records[len(records)-1].Hash, Count: len(records), Records: records}, nil
					}
				}
				return e, nil
			}
			got, err := s.Run(context.Background(), r.ID, wrapped)
			if err == nil || got.State != Incomplete || (*x).closed.Load() != 1 {
				t.Fatalf("failure: %+v %v", got, err)
			}
			want := int32(1)
			if name == "close" {
				want = 2
			}
			if (*x).executed.Load() != want {
				t.Fatal("continued after failure")
			}
			_, _ = s.Run(context.Background(), r.ID, wrapped)
			if made.Load() != 1 {
				t.Fatal("retried failure")
			}
		})
	}
}
func TestRunRestartRecovery(t *testing.T) {
	for _, state := range []State{Running, Verifying} {
		t.Run(string(state), func(t *testing.T) {
			s, dir := testStore(t)
			r := admit(t, s)
			l, err := s.start(context.Background(), r.ID)
			if err != nil {
				t.Fatal(err)
			}
			if state == Verifying {
				b, err := s.retain([]byte(mustJSON(t, journalRecords(t, "exec", "question", "hello", "model"))))
				if err != nil {
					t.Fatal(err)
				}
				records := journalRecords(t, "exec", "question", "hello", "model")
				// Reuse the exact retained chain; helper is deterministic except no fabricated timestamps.
				r.State = Verifying
				r.Generation = l.Generation
				r.Observations = []Observation{{CaseID: "case", Run: 1, Candidate: Journal{SessionID: "session", ExecutionID: "exec", HeadHash: records[len(records)-1].Hash, Count: len(records), Blob: b}}}
				s.mu.Lock()
				err = s.transaction(context.Background(), func() error { return s.save(context.Background(), r, false) })
				s.mu.Unlock()
				if err != nil {
					t.Fatal(err)
				}
			}
			lineage := s.Lineage()
			if err = s.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := Open(dir, lineage)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			var made atomic.Int32
			factory := func(context.Context, ExecutionScope) (Executor, error) { made.Add(1); return nil, ErrInvalid }
			got, err := reopened.Run(context.Background(), r.ID, factory)
			want := Incomplete
			if state == Verifying {
				want = Passed
			}
			if err != nil || got.State != want || made.Load() != 0 {
				t.Fatalf("recovery: %+v %v", got, err)
			}
		})
	}
}
func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestRunCloseCancelsAndDrains(t *testing.T) {
	s, _ := testStore(t)
	r := admit(t, s)
	factory, x, _ := runFactory(t, r)
	entered := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan error, 1)
	wrapped := func(ctx context.Context, scope ExecutionScope) (Executor, error) {
		e, er := factory(ctx, scope)
		(*x).execute = func(ctx context.Context, c BudgetCall) (ExecutionJournal, error) {
			close(entered)
			<-ctx.Done()
			<-release
			return ExecutionJournal{}, ctx.Err()
		}
		return e, er
	}
	go func() { _, err := s.Run(context.Background(), r.ID, wrapped); finished <- err }()
	<-entered
	if _, err := s.Run(context.Background(), r.ID, factory); !errors.Is(err, ErrConflict) {
		t.Fatalf("concurrent: %v", err)
	}
	closed := make(chan error, 1)
	go func() { closed <- s.Close() }()
	select {
	case <-closed:
		t.Fatal("closed before active drain")
	default:
	}
	close(release)
	if err := <-finished; !errors.Is(err, context.Canceled) {
		t.Fatalf("run: %v", err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if (*x).closed.Load() != 1 {
		t.Fatal("owner not closed")
	}
	if _, err := s.Run(context.Background(), r.ID, factory); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("closed store: %v", err)
	}
}

func TestRunPreservesVerifyingAfterAvailabilityFailure(t *testing.T) {
	s, _ := testStore(t)
	r := admit(t, s)
	factory, x, made := runFactory(t, r)
	original := blobReadAll
	defer func() { blobReadAll = original }()
	wrapped := func(ctx context.Context, scope ExecutionScope) (Executor, error) {
		e, err := factory(ctx, scope)
		(*x).onClose = func() error {
			blobReadAll = func(io.Reader) ([]byte, error) { return nil, os.ErrPermission }
			return nil
		}
		return e, err
	}
	got, err := s.Run(context.Background(), r.ID, wrapped)
	if !errors.Is(err, ErrUnavailable) || got.State != Verifying || len(got.Observations) != 1 {
		t.Fatalf("lost intent: %+v %v", got, err)
	}
	blobReadAll = original
	got, err = s.Run(context.Background(), r.ID, wrapped)
	if err != nil || got.State != Passed || made.Load() != 1 || (*x).executed.Load() != 1 {
		t.Fatalf("resend verifying: %+v %v", got, err)
	}
}

func TestRunSamePlanHasIndependentScope(t *testing.T) {
	s, _ := testStore(t)
	first := admit(t, s)
	second, err := s.Admit(context.Background(), Request{Key: "other", Requester: "caller", Plan: first.Request.Plan})
	if err != nil {
		t.Fatal(err)
	}
	var scopes []ExecutionScope
	for _, r := range []Record{first, second} {
		factory, x, _ := runFactory(t, r)
		got, err := s.Run(context.Background(), r.ID, factory)
		if err != nil || got.State != Passed {
			t.Fatal(err)
		}
		scope := ExecutionScopeForRecord(got)
		if scope != (*x).scope || !validID(scope.RunID) || !validDigest(scope.RunID) {
			t.Fatal("scope labels")
		}
		scopes = append(scopes, scope)
	}
	if scopes[0].RunID == scopes[1].RunID || CandidateSessionID(scopes[0].RunID, "same-slot") == CandidateSessionID(scopes[1].RunID, "same-slot") {
		t.Fatal("run alias")
	}
}
