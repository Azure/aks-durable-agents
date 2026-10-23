//go:build squadproof

package squadproof

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/agent-primitives/sessions/api"
)

// This sink isolates the harness's mediated boundary, without a provider or executor.
// The parent integration tests exercise the controller and SDK transport separately.
type proofHarnessSink struct {
	responses []string
	requests  []api.ModelRequest
	calls     []api.ToolCall
	outputs   []string
	results   []api.ToolResult
	modelErr  error
	toolErr   error
	outputErr error
	order     []string
}

func (s *proofHarnessSink) Model(_ context.Context, req api.ModelRequest) (api.ModelResponse, error) {
	s.requests = append(s.requests, req)
	s.order = append(s.order, "model")
	if s.modelErr != nil {
		return api.ModelResponse{}, s.modelErr
	}
	i := len(s.requests) - 1
	if i >= len(s.responses) {
		return api.ModelResponse{}, errors.New("unexpected model request")
	}
	return api.ModelResponse{Message: *api.TextMessage("assistant", s.responses[i])}, nil
}
func (s *proofHarnessSink) ToolCall(_ context.Context, call api.ToolCall) (api.ToolResult, error) {
	s.calls = append(s.calls, call)
	s.order = append(s.order, "tool")
	if s.toolErr != nil {
		return api.ToolResult{}, s.toolErr
	}
	if len(s.calls) <= len(s.results) {
		return s.results[len(s.calls)-1], nil
	}
	return api.ToolResult{ID: call.ID, Output: map[string]any{"ok": true}}, nil
}
func (s *proofHarnessSink) Output(_ context.Context, text string) error {
	s.outputs = append(s.outputs, text)
	s.order = append(s.order, "output")
	return s.outputErr
}
func (*proofHarnessSink) Report(context.Context, api.ToolResult) error {
	return errors.New("harness must not report local effects")
}
func (*proofHarnessSink) Usage(context.Context, api.Usage) error {
	return errors.New("unexpected usage emission")
}
func proofHarnessStart() *api.Start {
	return &api.Start{ExecutionID: "exec-1", SessionUID: "session-1", Inputs: []api.Message{*api.TextMessage("user", " original input\n")}}
}

// Removing the role/package version pin or weakening mediation breaks replay identity.
func TestHarnessDescriptor(t *testing.T) {
	for _, tc := range []struct {
		role  string
		tools []api.ToolSpec
	}{
		{"lead", []api.ToolSpec{{Name: "dispatch_member", Mediation: api.MediationControllerMediated}, {Name: "read_context", Mediation: api.MediationControllerMediated}, {Name: "checkpoint", Mediation: api.MediationRequiresApproval}}},
		{"member", []api.ToolSpec{{Name: "read_context", Mediation: api.MediationControllerMediated}, {Name: "publish", Mediation: api.MediationRequiresApproval}}},
	} {
		t.Run(tc.role, func(t *testing.T) {
			d, err := NewHarness(tc.role, packageDigest).Describe(t.Context())
			if err != nil || d.ID != "proof-"+tc.role || d.Version == "" || !reflect.DeepEqual(d.Models, []string{"proof-model"}) || !reflect.DeepEqual(d.Tools, tc.tools) || d.Capabilities.Resumability != api.ResumabilityStatelessReplay {
				t.Fatalf("descriptor: %+v, %v", d, err)
			}
			again, _ := NewHarness(tc.role, packageDigest).Describe(t.Context())
			otherPackage, _ := NewHarness(tc.role, strings.Repeat("b", 64)).Describe(t.Context())
			otherRole := "lead"
			if tc.role == "lead" {
				otherRole = "member"
			}
			other, _ := NewHarness(otherRole, packageDigest).Describe(t.Context())
			if again.Version != d.Version || otherPackage.Version == d.Version || other.Version == d.Version {
				t.Fatal("version must stably pin both role and package")
			}
		})
	}
}

// Wrong messages, tool order, mediation or keys would change replay or authority.
func TestHarnessTwoModelPhasesAndRoleMediation(t *testing.T) {
	for _, tc := range []struct {
		role, plan string
		names      []string
		mediation  []api.Mediation
	}{
		{"lead", `{"tools":[{"name":"dispatch_member","arguments":{"task":"work"}},{"name":"read_context","arguments":{}},{"name":"checkpoint","arguments":{}}],"reply":"not final"}`, []string{"dispatch_member", "read_context", "checkpoint"}, []api.Mediation{api.MediationControllerMediated, api.MediationControllerMediated, api.MediationRequiresApproval}},
		{"member", `{"tools":[{"name":"read_context","arguments":{}},{"name":"publish","arguments":{"text":"work"}}]}`, []string{"read_context", "publish"}, []api.Mediation{api.MediationControllerMediated, api.MediationRequiresApproval}},
	} {
		t.Run(tc.role, func(t *testing.T) {
			sink := &proofHarnessSink{responses: []string{tc.plan, `{"reply":"finished"}`}}
			start := proofHarnessStart()
			start.History = []api.Event{{Kind: api.EventInput, Message: api.TextMessage("user", "must not enter this complete input")}}
			if err := NewHarness(tc.role, packageDigest).Run(t.Context(), start, sink); err != nil {
				t.Fatal(err)
			}
			if len(sink.requests) != 2 || len(sink.calls) != len(tc.names) || !reflect.DeepEqual(sink.outputs, []string{"finished"}) {
				t.Fatalf("unexpected phases/calls/outputs: %+v", sink)
			}
			for i, req := range sink.requests {
				phase := []string{"plan", "finish"}[i]
				if req.Model != "proof-model" || len(req.Messages) != 2 || req.Messages[0].Role != "system" || req.Messages[0].Text() != fmt.Sprintf("squad-proof-v1 role=%s package=%s phase=%s", tc.role, packageDigest, phase) || req.Messages[1].Role != "user" || len(req.Messages[0].Parts) != 1 || len(req.Messages[1].Parts) != 1 || req.Params != nil || req.Tools != nil || req.ToolChoice != nil {
					t.Fatalf("request %d: %+v", i, req)
				}
			}
			if sink.requests[0].Messages[1].Text() != " original input\n" {
				t.Fatal("plan input was changed")
			}
			var finish struct {
				Input   string           `json:"input"`
				Results []api.ToolResult `json:"results"`
			}
			if err := json.Unmarshal([]byte(sink.requests[1].Messages[1].Text()), &finish); err != nil || finish.Input != " original input\n" || len(finish.Results) != len(tc.names) {
				t.Fatalf("finish context: %+v, %v", finish, err)
			}
			for i, call := range sink.calls {
				key := fmt.Sprintf("exec-1/%d/%s", i, tc.names[i])
				if call.ID != key || call.IdempotencyKey != key || call.Tool != tc.names[i] || call.Mediation != tc.mediation[i] || finish.Results[i].ID != key {
					t.Fatalf("tool %d: %+v, finish %+v", i, call, finish)
				}
			}
			if sink.calls[0].Args == nil || sink.order[0] != "model" || sink.order[len(sink.order)-2] != "model" {
				t.Fatalf("arguments/order: %+v", sink)
			}
			for _, step := range sink.order[1 : len(sink.order)-2] {
				if step != "tool" {
					t.Fatalf("finish ran before all tools: %v", sink.order)
				}
			}
		})
	}
}

// Invalid starts/configurations must fail before a model or tool can run.
func TestHarnessInvalidConfigurationAndStart(t *testing.T) {
	for _, cfg := range [][2]string{{"", packageDigest}, {"owner", packageDigest}, {"lead", "bad"}, {"lead", strings.Repeat("A", 64)}} {
		h := NewHarness(cfg[0], cfg[1])
		if _, err := h.Describe(t.Context()); !errors.Is(err, ErrInvalid) {
			t.Fatalf("Describe(%v): %v", cfg, err)
		}
		if err := h.Run(t.Context(), proofHarnessStart(), &proofHarnessSink{}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("Run(%v): %v", cfg, err)
		}
	}
	starts := []*api.Start{nil, {}, {ExecutionID: "exec-1"}, {ExecutionID: "exec-1", Inputs: proofHarnessStart().Inputs}, {ExecutionID: " exec-1", SessionUID: "session-1", Inputs: proofHarnessStart().Inputs}, {ExecutionID: "exec-1", SessionUID: "session-1"}, {ExecutionID: "exec-1", SessionUID: "session-1", Inputs: []api.Message{*api.TextMessage("assistant", "bad")}}, {ExecutionID: "exec-1", SessionUID: "session-1", Inputs: []api.Message{*api.TextMessage("user", " ")}}, {SessionUID: "session-1", Inputs: proofHarnessStart().Inputs}, {ExecutionID: "exec-1", SessionUID: "session-1", Inputs: append(proofHarnessStart().Inputs, *api.TextMessage("user", "extra"))}}
	for i, start := range starts {
		sink := &proofHarnessSink{}
		if err := NewHarness("lead", packageDigest).Run(t.Context(), start, sink); !errors.Is(err, ErrInvalid) || len(sink.requests) != 0 || len(sink.calls) != 0 {
			t.Fatalf("start %d: %v %+v", i, err, sink)
		}
	}
}

// Reject every malformed plan before any proposed effect, including later unknown tools.
func TestHarnessStrictPlan(t *testing.T) {
	for _, plan := range []string{
		`null`, `[]`, `{}`, `{"reply":"ok","extra":true}`, `{"reply":"ok"} {}`,
		`{"tools":[{"name":"read_context","arguments":{},"mediation":"IN_HARNESS_REPORTED"}]}`,
		`{"tools":[{"name":"read_context","arguments":{}},{"name":"publish","arguments":{}}]}`,
		`{"tools":[{"name":"read_context"},{"name":"read_context"},{"name":"read_context"},{"name":"read_context"},{"name":"read_context"}]}`,
		`{"tools":[],"tools":[{"name":"checkpoint"}]}`,
		`{"reply":"` + strings.Repeat("x", 16<<10) + `"}`,
	} {
		// An empty plan object is valid; use it as an invalid finish instead.
		responses := []string{plan, `{"reply":"ok"}`}
		if plan == `{}` {
			responses = []string{`{}`, `{}`}
		}
		sink := &proofHarnessSink{responses: responses}
		if err := NewHarness("lead", packageDigest).Run(t.Context(), proofHarnessStart(), sink); !errors.Is(err, ErrInvalid) || len(sink.calls) != 0 || len(sink.outputs) != 0 {
			t.Fatalf("plan %.80s: %v %+v", plan, err, sink)
		}
	}
	for _, finish := range []string{`{"reply":" "}`, `{"tools":[{"name":"read_context"}],"reply":"no"}`, `{"reply":"ok","extra":1}`} {
		sink := &proofHarnessSink{responses: []string{`{}`, finish}}
		if err := NewHarness("lead", packageDigest).Run(t.Context(), proofHarnessStart(), sink); !errors.Is(err, ErrInvalid) || len(sink.outputs) != 0 {
			t.Fatalf("finish %s: %v", finish, err)
		}
	}
}

// A denial is data for the finish explanation, not permission to claim tool success.
func TestHarnessDeniedToolCanFinishExplanation(t *testing.T) {
	denied := api.ToolResult{ID: "exec-1/0/checkpoint", IsError: true, Code: api.ToolResultCodeApprovalDenied, Error: "not approved", ApprovalRequestSeq: 4, ApprovalDecisionSeq: 5}
	sink := &proofHarnessSink{responses: []string{`{"tools":[{"name":"checkpoint","arguments":{}},{"name":"read_context","arguments":{}}]}`, `{"reply":"Checkpoint denied; nothing checkpointed."}`}, results: []api.ToolResult{denied}}
	if err := NewHarness("lead", packageDigest).Run(t.Context(), proofHarnessStart(), sink); err != nil {
		t.Fatal(err)
	}
	var finish struct {
		Results []api.ToolResult `json:"results"`
	}
	if err := json.Unmarshal([]byte(sink.requests[1].Messages[1].Text()), &finish); err != nil || len(finish.Results) != 2 || !reflect.DeepEqual(finish.Results[0], denied) || !reflect.DeepEqual(sink.outputs, []string{"Checkpoint denied; nothing checkpointed."}) {
		t.Fatalf("denial lost: %+v %+v, %v", finish, sink, err)
	}
}

// Never swallow a typed park, a replay mismatch, or an ordinary executor failure.
func TestHarnessPropagatesBoundaryErrors(t *testing.T) {
	park := &api.ApprovalParkedError{Ref: api.ApprovalRef{ExecutionID: "exec-1", ToolCallID: "exec-1/0/checkpoint", RequestSeq: 4}}
	divergence := errors.New("replay input hash mismatch")
	for _, boundary := range []string{"model", "tool", "output"} {
		for _, want := range []error{park, divergence} {
			sink := &proofHarnessSink{responses: []string{`{"tools":[{"name":"checkpoint","arguments":{}}]}`, `{"reply":"done"}`}}
			switch boundary {
			case "model":
				sink.modelErr = want
			case "tool":
				sink.toolErr = want
			case "output":
				sink.outputErr = want
			}
			if got := NewHarness("lead", packageDigest).Run(t.Context(), proofHarnessStart(), sink); got != want {
				t.Fatalf("%s: got %v, want unchanged %v", boundary, got, want)
			}
			if boundary != "output" && len(sink.outputs) != 0 {
				t.Fatal("failure emitted success output")
			}
		}
	}
	sink := &proofHarnessSink{responses: []string{`{"tools":[{"name":"checkpoint"}]}`, `{"reply":"succeeded"}`}, results: []api.ToolResult{{IsError: true, Code: api.ToolResultCodeExecutorError, Error: "disk unavailable"}}}
	if err := NewHarness("lead", packageDigest).Run(t.Context(), proofHarnessStart(), sink); err == nil || !strings.Contains(err.Error(), "disk unavailable") || len(sink.requests) != 1 || len(sink.outputs) != 0 {
		t.Fatalf("ordinary tool error claimed success: %v %+v", err, sink)
	}
}
