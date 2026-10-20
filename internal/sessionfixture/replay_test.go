package sessionfixture

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/agent-primitives/sessions/api"
	"github.com/agent-primitives/sessions/controller"
	"github.com/agent-primitives/sessions/eventlog"
)

func completedDraft(t *testing.T) (eventlog.Store, *releaseNotesHarness, controller.ModelFunc, *executor) {
	t.Helper()
	log := eventlog.AsStore(eventlog.New())
	h := newHarness(testInstructions)
	ex, e := newExecutor(privateTempDir(t))
	if e != nil {
		t.Fatal(e)
	}
	model := func(context.Context, api.ModelRequest) (api.ModelResponse, error) {
		return api.ModelResponse{Message: *api.TextMessage("assistant", parentDraft)}, nil
	}
	c := controllerFor(t, log, "s", model, ex.execute)
	if e = c.Exec(t.Context(), h, []api.Message{*api.TextMessage("user", parentInput)}, 0); !errors.Is(e, api.ErrApprovalParked) {
		t.Fatal(e)
	}
	decide(t, c, log, true)
	c = controllerFor(t, log, "s", model, ex.execute)
	if _, e = c.Resume(t.Context(), h); e != nil {
		t.Fatal(e)
	}
	return log, h, model, ex
}

// Break caught: verifier treats an earlier completed turn as proof of the final pending decision.
func TestReplayRefusesUnfinishedFinalApproval(t *testing.T) {
	log, h, model, ex := completedDraft(t)
	c := controllerFor(t, log, "s", model, ex.execute)
	if e := c.Exec(t.Context(), h, []api.Message{*api.TextMessage("user", internalInput)}, head(t, log)); !errors.Is(e, api.ErrApprovalParked) {
		t.Fatal(e)
	}
	records := snapshot(t, log)
	proof, e := verifyReplay(t.Context(), "s", records, h)
	if e == nil || proof.Completed {
		t.Fatal("unfinished final approval passed replay")
	}
	if proof.HeadHash != records[len(records)-1].Hash || proof.HeadSeq != records[len(records)-1].Seq {
		t.Fatalf("failure evidence lost journal binding: %#v", proof)
	}
	if len(proof.ExpectedExecutionIDs) != 2 || proof.ProviderCalls != 0 || proof.ExecutorCalls != 0 {
		t.Fatalf("missing final execution or made calls: %#v", proof)
	}
}

// Break caught: replay misses a completed denied/approved decision or re-calls any effect.
func TestReplayFullTerminalCoverageZeroCalls(t *testing.T) {
	for _, approved := range []bool{false, true} {
		t.Run(map[bool]string{true: "approve", false: "deny"}[approved], func(t *testing.T) {
			log, h, model, ex := completedDraft(t)
			c := controllerFor(t, log, "s", model, ex.execute)
			if e := c.Exec(t.Context(), h, []api.Message{*api.TextMessage("user", customerInput)}, head(t, log)); !errors.Is(e, api.ErrApprovalParked) {
				t.Fatal(e)
			}
			decide(t, c, log, approved)
			c = controllerFor(t, log, "s", model, ex.execute)
			if _, e := c.Resume(t.Context(), h); e != nil {
				t.Fatal(e)
			}
			records := snapshot(t, log)
			before := snapshot(t, log)
			proof, e := verifyReplay(t.Context(), "s", records, h)
			if e != nil {
				t.Fatal(e)
			}
			want := []string{}
			for _, r := range records {
				if r.Event.Kind == api.EventExecutionStart {
					want = append(want, r.Event.ExecutionID)
				}
			}
			if !proof.Completed || !reflect.DeepEqual(proof.ExpectedExecutionIDs, want) || !reflect.DeepEqual(proof.CoveredExecutionIDs, want) {
				t.Fatalf("incomplete replay coverage: %#v", proof)
			}
			if proof.HeadHash != records[len(records)-1].Hash || proof.CheckpointSeq != records[len(records)-1].Seq || proof.ProviderCalls != 0 || proof.ExecutorCalls != 0 {
				t.Fatalf("bad replay binding/counters: %#v", proof)
			}
			if !reflect.DeepEqual(before, snapshot(t, log)) {
				t.Fatal("verification mutated real journal")
			}
			if _, e = verifyReplay(t.Context(), "s", records, newHarness(testInstructions+"changed")); e == nil {
				t.Fatal("changed instructions passed replay")
			}
		})
	}
}

// Break caught: a child re-executes inherited tools or loses the common assessment context.
func TestReplayForkBaseContinuity(t *testing.T) {
	parent, h, _, _ := completedDraft(t)
	base := snapshot(t, parent)
	baseEnd := base[len(base)-1]
	for _, choice := range []string{customerInput, internalInput} {
		t.Run(choice, func(t *testing.T) {
			child := eventlog.AsStore(eventlog.NewFrom(base))
			f, e := child.NewFence()
			if e != nil {
				t.Fatal(e)
			}
			if _, e = child.Append(baseEnd.Seq, f, api.Event{Kind: api.EventLifecycle, Lifecycle: &api.Lifecycle{Kind: api.LifecycleFork, Detail: "parent=s"}}); e != nil {
				t.Fatal(e)
			}
			model := func(_ context.Context, req api.ModelRequest) (api.ModelResponse, error) {
				assertPrompt(t, req, testInstructions, parentInput, parentDraft, choice)
				foundAssessment, foundChoice := false, false
				for i := range req.Messages {
					if req.Messages[i].Text() == parentDraft {
						foundAssessment = true
					}
					if req.Messages[i].Text() == choice {
						foundChoice = true
					}
				}
				if !foundAssessment || !foundChoice {
					t.Error("fork lost inherited conversation or new input")
				}
				return api.ModelResponse{Message: *api.TextMessage("assistant", "Child release notes for "+choice)}, nil
			}
			ex, e := newExecutor(privateTempDir(t))
			if e != nil {
				t.Fatal(e)
			}
			c := controllerFor(t, child, "child-"+choice, model, ex.execute)
			if e = c.Exec(t.Context(), h, []api.Message{*api.TextMessage("user", choice)}, head(t, child)); !errors.Is(e, api.ErrApprovalParked) {
				t.Fatal(e)
			}
			decide(t, c, child, false)
			c = controllerFor(t, child, "child-"+choice, model, ex.execute)
			if _, e = c.Resume(t.Context(), h); e != nil {
				t.Fatal(e)
			}
			if !reflect.DeepEqual(snapshot(t, child)[:len(base)], base) {
				t.Fatal("fork changed common prefix")
			}
			proof, e := verifyReplay(t.Context(), "child-"+choice, snapshot(t, child), h)
			if e != nil || len(proof.CoveredExecutionIDs) != 2 || proof.ExecutorCalls != 0 {
				t.Fatalf("fork replay failed: %#v %v", proof, e)
			}
		})
	}
}
