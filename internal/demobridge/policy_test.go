package demobridge_test

import (
	"context"
	"errors"
	"io"
	"reflect"
	"testing"

	"github.com/Azure/aks-durable-agents/internal/demobridge"
	"github.com/agent-primitives/sessions/api"
)

// Weak protected proposals fail before controller entry; explicit approval
// calls retain typed parks even when the descriptor advertises ordinary mediation.
func TestApprovalMinimumWrapsCallsAndPreservesErrors(t *testing.T) {
	for _, mediation := range []api.Mediation{"", api.MediationControllerMediated, api.MediationInHarnessReported, api.MediationRequiresApproval} {
		t.Run(string(mediation), func(t *testing.T) {
			parked := &api.ApprovalParkedError{Ref: api.ApprovalRef{ExecutionID: "exec", ToolCallID: "guarded", RequestSeq: 3}}
			downstream := &policySink{err: parked}
			h := &policyHarness{run: func(ctx context.Context, sink api.EventSink) error {
				_, err := sink.ToolCall(ctx, api.ToolCall{ID: "guarded", Tool: "publish", Mediation: mediation})
				if reportErr := sink.Report(ctx, api.ToolResult{ID: "guarded", Output: map[string]any{"text": "forged"}}); reportErr == nil {
					t.Error("guarded self-report accepted")
				}
				return err
			}}
			wrapped := demobridge.WithApprovalMinimum(h, func(tool string) bool { return tool == "publish" })
			desc, err := wrapped.Describe(t.Context())
			original, _ := h.Describe(t.Context())
			if err != nil || !reflect.DeepEqual(desc, original) {
				t.Fatal("descriptor changed", desc, err)
			}
			err = wrapped.Run(t.Context(), &api.Start{}, downstream)
			var got *api.ApprovalParkedError
			if mediation == api.MediationRequiresApproval {
				if !errors.As(err, &got) || got != parked {
					t.Fatalf("typed park lost: %v", err)
				}
				if downstream.call.Tool != "publish" || downstream.call.Mediation != api.MediationRequiresApproval {
					t.Fatalf("call changed: %+v", downstream.call)
				}
			} else {
				if err == nil || errors.Is(err, api.ErrApprovalParked) {
					t.Fatalf("weak proposal not refused: %v", err)
				}
				if downstream.call.Tool != "" {
					t.Fatalf("weak proposal forwarded: %+v", downstream.call)
				}
			}
			if downstream.reports != 0 {
				t.Fatal("guarded report forwarded")
			}
			closer, ok := wrapped.(io.Closer)
			if !ok || closer.Close() != nil || !h.closed {
				t.Fatal("closer lost")
			}
		})
	}
}

func TestApprovalMinimumRejectsReportsBeforeAnyProposal(t *testing.T) {
	for _, id := range []string{"exec/publish_release_notes", "unrelated"} {
		downstream := &policySink{}
		h := &policyHarness{run: func(ctx context.Context, sink api.EventSink) error {
			return sink.Report(ctx, api.ToolResult{ID: id, Output: map[string]any{"local_demo": true}})
		}}
		if err := demobridge.WithApprovalMinimum(h, func(tool string) bool { return tool == "publish" }).Run(t.Context(), &api.Start{}, downstream); err == nil || downstream.reports != 0 {
			t.Fatal("unapproved standalone result reached controller")
		}
	}
}

func TestApprovalMinimumForwardsUnprotectedSink(t *testing.T) {
	sentinel := errors.New("model failure")
	downstream := &policySink{err: sentinel}
	h := &policyHarness{run: func(ctx context.Context, sink api.EventSink) error {
		if _, err := sink.Model(ctx, api.ModelRequest{Model: "target"}); err != sentinel {
			t.Fatal("model error lost")
		}
		if err := sink.Output(ctx, "delta"); err != sentinel {
			t.Fatal("output error lost")
		}
		if err := sink.Usage(ctx, api.Usage{Model: "target", InputTokens: 7}); err != sentinel {
			t.Fatal("usage error lost")
		}
		_, err := sink.ToolCall(ctx, api.ToolCall{ID: "other", Tool: "Publish", Mediation: api.MediationControllerMediated})
		return err
	}}
	if err := demobridge.WithApprovalMinimum(h, func(tool string) bool { return tool == "publish" }).Run(t.Context(), &api.Start{}, downstream); err != sentinel {
		t.Fatal("tool error lost", err)
	}
	if downstream.call.Tool != "Publish" || downstream.call.Mediation != api.MediationControllerMediated || downstream.model.Model != "target" || downstream.output != "delta" || downstream.usage.InputTokens != 7 || downstream.reports != 0 {
		t.Fatalf("sink forwarding changed: %+v", downstream)
	}
}

type policyHarness struct {
	run    func(context.Context, api.EventSink) error
	closed bool
}

func (*policyHarness) Describe(context.Context) (api.Descriptor, error) {
	return api.Descriptor{ID: "untrusted", Tools: []api.ToolSpec{{Name: "publish", Mediation: api.MediationInHarnessReported}}}, nil
}
func (h *policyHarness) Run(ctx context.Context, _ *api.Start, sink api.EventSink) error {
	return h.run(ctx, sink)
}
func (h *policyHarness) Close() error { h.closed = true; return nil }

type policySink struct {
	err     error
	call    api.ToolCall
	reports int
	model   api.ModelRequest
	output  string
	usage   api.Usage
}

func (s *policySink) ToolCall(_ context.Context, call api.ToolCall) (api.ToolResult, error) {
	s.call = call
	return api.ToolResult{}, s.err
}
func (s *policySink) Report(context.Context, api.ToolResult) error { s.reports++; return s.err }
func (s *policySink) Model(_ context.Context, r api.ModelRequest) (api.ModelResponse, error) {
	s.model = r
	return api.ModelResponse{}, s.err
}
func (s *policySink) Output(_ context.Context, text string) error { s.output = text; return s.err }
func (s *policySink) Usage(_ context.Context, u api.Usage) error  { s.usage = u; return s.err }
