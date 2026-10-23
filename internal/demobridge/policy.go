package demobridge

import (
	"context"
	"errors"
	"io"

	"github.com/agent-primitives/sessions/api"
)

// WithApprovalMinimum enforces operator-owned exact tool minima before the
// controller sees a proposal. Weak protected proposals fail closed, and this
// bridge accepts no harness-reported results, even before a proposal exists.
func WithApprovalMinimum(h api.Harness, required func(string) bool) api.Harness {
	if required == nil {
		return h
	}
	wrapped := &approvalHarness{Harness: h, required: required}
	if closer, ok := h.(io.Closer); ok {
		return struct {
			api.Harness
			io.Closer
		}{wrapped, closer}
	}
	return wrapped
}

type approvalHarness struct {
	api.Harness
	required func(string) bool
}

func (h *approvalHarness) Run(ctx context.Context, start *api.Start, sink api.EventSink) error {
	return h.Harness.Run(ctx, start, &approvalSink{EventSink: sink, required: h.required})
}

type approvalSink struct {
	api.EventSink
	required func(string) bool
}

func (s *approvalSink) ToolCall(ctx context.Context, call api.ToolCall) (api.ToolResult, error) {
	if s.required(call.Tool) {
		if call.Mediation != api.MediationRequiresApproval {
			return api.ToolResult{}, errors.New("demo bridge: protected tool requires explicit approval mediation")
		}
	}
	return s.EventSink.ToolCall(ctx, call)
}

func (s *approvalSink) Report(context.Context, api.ToolResult) error {
	return errors.New("demo bridge: all tool results must come from the controller")
}
