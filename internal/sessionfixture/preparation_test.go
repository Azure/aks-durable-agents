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

// Break caught: preparation publishes, prefixes pollute followup context, or replay differs.
func TestPreparationContextForkReplay(t *testing.T) {
	log := eventlog.AsStore(eventlog.New())
	h := newHarness(testInstructions)
	calls, tools := 0, 0
	texts := []string{testInstructions}
	model := func(_ context.Context, req api.ModelRequest) (api.ModelResponse, error) {
		calls++
		assertPrompt(t, req, texts...)
		return api.ModelResponse{Message: *api.TextMessage("assistant", "Recorded draft")}, nil
	}
	tool := func(context.Context, controller.ToolCallContext, api.ToolCall) (api.ToolResult, error) {
		tools++
		return api.ToolResult{}, errors.New("must never publish")
	}
	for _, input := range []string{"Facts and initial draft", "Review feedback"} {
		texts = append(texts, input)
		c := controllerFor(t, log, "parent", model, tool)
		if e := c.Exec(t.Context(), h, []api.Message{*api.TextMessage("user", "[prepare]\n"+input)}, head(t, log)); e != nil {
			t.Fatal(e)
		}
		texts = append(texts, "Recorded draft")
	}
	if calls != 2 || tools != 0 {
		t.Fatalf("preparation effects: %d %d", calls, tools)
	}
	base := snapshot(t, log)
	for _, r := range base {
		if r.Event.Kind == api.EventToolCall || r.Event.Kind == api.EventApprovalRequest {
			t.Fatal("preparation requested publication")
		}
	}
	proof, e := verifyReplay(t.Context(), "parent", base, h)
	if e != nil || !proof.Completed || len(proof.CoveredExecutionIDs) != 2 {
		t.Fatalf("prep replay: %#v %v", proof, e)
	}
	// A real fork copies these exact records; followup must contain both user/model turns.
	child := eventlog.AsStore(eventlog.NewFrom(base))
	texts = append(texts, "Revise directly")
	c := controllerFor(t, child, "child", model, tool)
	if e = c.Exec(t.Context(), h, []api.Message{*api.TextMessage("user", "Revise directly")}, head(t, child)); !errors.Is(e, api.ErrApprovalParked) {
		t.Fatal(e)
	}
	if calls != 3 || tools != 0 || !reflect.DeepEqual(snapshot(t, child)[:len(base)], base) {
		t.Fatal("fork context or gate changed")
	}
	decide(t, c, child, false)
	c = controllerFor(t, child, "child", model, tool)
	if _, e = c.Resume(t.Context(), h); e != nil {
		t.Fatal(e)
	}
	before := snapshot(t, child)
	proof, e = verifyReplay(t.Context(), "child", before, h)
	if e != nil || len(proof.CoveredExecutionIDs) != 3 || calls != 3 || tools != 0 || !reflect.DeepEqual(before, snapshot(t, child)) {
		t.Fatalf("fork replay: %#v %v", proof, e)
	}
}

func TestEmptyPreparationRefusedBeforeProvider(t *testing.T) {
	log := eventlog.AsStore(eventlog.New())
	calls := 0
	c := controllerFor(t, log, "s", func(context.Context, api.ModelRequest) (api.ModelResponse, error) {
		calls++
		return api.ModelResponse{}, nil
	}, nil)
	if e := c.Exec(t.Context(), newHarness(testInstructions), []api.Message{*api.TextMessage("user", "[prepare]\n  ")}, 0); e == nil || calls != 0 {
		t.Fatalf("empty preparation reached provider: %v calls=%d", e, calls)
	}
}
