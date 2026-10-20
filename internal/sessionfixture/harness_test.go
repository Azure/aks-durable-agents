package sessionfixture

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/agent-primitives/sessions/api"
	"github.com/agent-primitives/sessions/controller"
	"github.com/agent-primitives/sessions/eventlog"
)

const testInstructions = "Write fictional release notes.\nPreserve the supplied facts.\n"
const parentInput = "Orka 2.4: faster startup, clearer error messages; known issue: offline sync delayed."

const parentDraft = draftA
const customerInput = "Make these release notes customer-facing."
const internalInput = "Make these release notes for the internal team."

func snapshot(t *testing.T, log eventlog.Store) []eventlog.Record {
	t.Helper()
	r, e := log.Read(1)
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func head(t *testing.T, log eventlog.Store) int64 {
	t.Helper()
	n, e := log.Head()
	if e != nil {
		t.Fatal(e)
	}
	return n
}
func controllerFor(t *testing.T, log eventlog.Store, uid string, model controller.ModelFunc, tool controller.ToolFunc) *controller.Controller {
	t.Helper()
	c, e := controller.New(log, model, controller.WithSessionUID(uid), controller.WithToolExecutor(tool))
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func pending(t *testing.T, log eventlog.Store) api.ApprovalDecision {
	t.Helper()
	r := snapshot(t, log)
	for i := len(r) - 1; i >= 0; i-- {
		if r[i].Event.Kind == api.EventApprovalRequest {
			return api.ApprovalDecision{ExecutionID: r[i].Event.ExecutionID, ToolCallID: r[i].Event.Approval.ToolCallID, RequestSeq: r[i].Seq, Reason: "offline test"}
		}
	}
	t.Fatal("missing approval request")
	return api.ApprovalDecision{}
}
func decide(t *testing.T, _ *controller.Controller, log eventlog.Store, approved bool) {
	t.Helper()
	d := pending(t, log)
	d.Approved = approved
	if _, e := controller.Approve(log, d); e != nil {
		t.Fatal(e)
	}
}
func lastOutput(t *testing.T, log eventlog.Store) string {
	t.Helper()
	r := snapshot(t, log)
	for i := len(r) - 1; i >= 0; i-- {
		if r[i].Event.Kind == api.EventOutput {
			return r[i].Event.Message.Text()
		}
	}
	return ""
}
func receipts(t *testing.T, dir string) []string {
	t.Helper()
	ex, e := newExecutor(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer ex.close()
	rows, e := ex.inventory()
	if e != nil {
		t.Fatal(e)
	}
	out := []string{}
	for _, row := range rows {
		out = append(out, string(row.Raw))
	}
	return out
}
func assertPrompt(t *testing.T, req api.ModelRequest, texts ...string) {
	t.Helper()
	if req.Model != "gpt-6-luna-2026-09-22" || len(req.Messages) != len(texts) || len(req.Tools) != 0 {
		t.Fatalf("unexpected request: %#v", req)
	}
	for i, text := range texts {
		wantRole := "user"
		if i == 0 {
			wantRole = "system"
		} else if i%2 == 0 {
			wantRole = "assistant"
		}
		if req.Messages[i].Text() != text || req.Messages[i].Role != wantRole {
			t.Fatalf("message %d: %#v want %s %q", i, req.Messages[i], wantRole, text)
		}
	}
}

// Break caught: drafting after consent, rewritten tool draft, new call on restart, denial publishing.
func TestHarnessDraftBeforeParkRestartApproveDeny(t *testing.T) {
	for _, approved := range []bool{true, false} {
		t.Run(map[bool]string{true: "approve", false: "deny"}[approved], func(t *testing.T) {
			log := eventlog.AsStore(eventlog.New())
			dir := privateTempDir(t)
			ex, e := newExecutor(dir)
			if e != nil {
				t.Fatal(e)
			}
			modelCalls, toolCalls := 0, 0
			model := func(_ context.Context, req api.ModelRequest) (api.ModelResponse, error) {
				modelCalls++
				assertPrompt(t, req, testInstructions, parentInput)
				return api.ModelResponse{Message: *api.TextMessage("assistant", parentDraft)}, nil
			}
			execute := func(ctx context.Context, s controller.ToolCallContext, c api.ToolCall) (api.ToolResult, error) {
				toolCalls++
				return ex.execute(ctx, s, c)
			}
			h := newHarness(testInstructions)
			c := controllerFor(t, log, "parent", model, execute)
			e = c.Exec(t.Context(), h, []api.Message{*api.TextMessage("user", parentInput)}, 0)
			var park *api.ApprovalParkedError
			if !errors.As(e, &park) {
				t.Fatalf("want typed park: %v", e)
			}
			if modelCalls != 1 || toolCalls != 0 || len(receipts(t, dir)) != 0 {
				t.Fatalf("before consent model=%d tools=%d", modelCalls, toolCalls)
			}
			var call *api.ToolCall
			var executionID string
			outputs := 0
			for _, r := range snapshot(t, log) {
				if r.Event.Kind == api.EventEnd || r.Event.Kind == api.EventError {
					t.Fatal("park fabricated terminal event")
				}
				if r.Event.Kind == api.EventOutput {
					outputs++
					if r.Event.Message.Text() != parentDraft {
						t.Fatal("draft not recorded")
					}
				}
				if r.Event.Kind == api.EventToolCall {
					call = r.Event.ToolCall
					executionID = r.Event.ExecutionID
				}
			}
			if outputs != 1 || call == nil || call.Tool != "publish_release_notes" || call.Args["draft"] != parentDraft || call.Args["destination"] != "release-notes-demo" || len(call.Args) != 2 || call.Mediation != api.MediationRequiresApproval || call.ID != executionID+"/publish_release_notes" || call.IdempotencyKey != call.ID {
				t.Fatalf("invalid exact publication gate: %#v", call)
			}
			// Recreate both components before deciding; parked Resume must retain pending identity.
			before := pending(t, log)
			ex, e = newExecutor(dir)
			if e != nil {
				t.Fatal(e)
			}
			c = controllerFor(t, log, "parent", model, execute)
			if _, e = c.Resume(t.Context(), h); !errors.Is(e, api.ErrApprovalParked) {
				t.Fatalf("restarted park: %v", e)
			}
			if !reflect.DeepEqual(before, pending(t, log)) || modelCalls != 1 || toolCalls != 0 {
				t.Fatal("restart changed pending/calls")
			}
			decide(t, c, log, approved)
			c = controllerFor(t, log, "parent", model, execute)
			if _, e = c.Resume(t.Context(), h); e != nil {
				t.Fatal(e)
			}
			wantTools := 0
			wantStatus := "Publication denied; nothing published."
			if approved {
				wantTools = 1
				wantStatus = "Published locally: release-notes-demo."
			}
			if modelCalls != 1 || toolCalls != wantTools || len(receipts(t, dir)) != wantTools || lastOutput(t, log) != wantStatus {
				t.Fatalf("decision calls=%d tools=%d status=%s", modelCalls, toolCalls, lastOutput(t, log))
			}
			records := snapshot(t, log)
			if _, e = c.Resume(t.Context(), h); e != nil {
				t.Fatal(e)
			}
			if !reflect.DeepEqual(records, snapshot(t, log)) {
				t.Fatal("completed resume mutated journal")
			}
		})
	}
}

// Break caught: modified instructions after parking silently resume with an effect or new provider call.
func TestModifiedPromptResumeFailsClosed(t *testing.T) {
	log := eventlog.AsStore(eventlog.New())
	ex, e := newExecutor(privateTempDir(t))
	if e != nil {
		t.Fatal(e)
	}
	calls, tools := 0, 0
	model := func(context.Context, api.ModelRequest) (api.ModelResponse, error) {
		calls++
		return api.ModelResponse{Message: *api.TextMessage("assistant", parentDraft)}, nil
	}
	execute := func(ctx context.Context, s controller.ToolCallContext, c api.ToolCall) (api.ToolResult, error) {
		tools++
		return ex.execute(ctx, s, c)
	}
	c := controllerFor(t, log, "s", model, execute)
	if e = c.Exec(t.Context(), newHarness(testInstructions), []api.Message{*api.TextMessage("user", parentInput)}, 0); !errors.Is(e, api.ErrApprovalParked) {
		t.Fatal(e)
	}
	decide(t, c, log, true)
	c = controllerFor(t, log, "s", model, execute)
	_, e = c.Resume(t.Context(), newHarness(testInstructions+"changed"))
	if !errors.Is(e, controller.ErrHarnessVersionMismatch) {
		t.Fatalf("changed prompt not rejected: %v", e)
	}
	if calls != 1 || tools != 0 || len(receipts(t, ex.dir)) != 0 {
		t.Fatal("changed resume performed an effect")
	}
}

// Fail after an approved durable effect but before journal result: recovery must reuse its receipt.
type dropReceiptLog struct {
	eventlog.Store
	drop bool
}

func (l *dropReceiptLog) Append(h, f int64, e api.Event) (eventlog.Record, error) {
	if l.drop && e.Kind == api.EventToolResult {
		l.drop = false
		return eventlog.Record{}, errors.New("injected receipt append crash")
	}
	return l.Store.Append(h, f, e)
}
func TestHarnessRecoveryAfterEffectBeforeReceipt(t *testing.T) {
	log := &dropReceiptLog{Store: eventlog.AsStore(eventlog.New())}
	dir := privateTempDir(t)
	ex, e := newExecutor(dir)
	if e != nil {
		t.Fatal(e)
	}
	calls := 0
	model := func(context.Context, api.ModelRequest) (api.ModelResponse, error) {
		calls++
		return api.ModelResponse{Message: *api.TextMessage("assistant", parentDraft)}, nil
	}
	c := controllerFor(t, log, "s", model, ex.execute)
	h := newHarness(testInstructions)
	if e = c.Exec(t.Context(), h, []api.Message{*api.TextMessage("user", parentInput)}, 0); !errors.Is(e, api.ErrApprovalParked) {
		t.Fatal(e)
	}
	decide(t, c, log, true)
	c = controllerFor(t, log, "s", model, ex.execute)
	log.drop = true
	if _, e = c.Resume(t.Context(), h); e == nil || !strings.Contains(e.Error(), "injected") {
		t.Fatalf("crash injection: %v", e)
	}
	paths := receipts(t, dir)
	if len(paths) != 1 {
		t.Fatal(paths)
	}
	before := paths[0]
	ex, e = newExecutor(dir)
	if e != nil {
		t.Fatal(e)
	}
	c = controllerFor(t, log, "s", model, ex.execute)
	if _, e = c.Resume(t.Context(), h); e != nil {
		t.Fatal(e)
	}
	after := receipts(t, dir)[0]
	if calls != 1 || len(receipts(t, dir)) != 1 || string(after) != string(before) {
		t.Fatal("duplicate effect/provider after crash")
	}
}
