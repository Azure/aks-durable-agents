package host

import (
	"context"
	"errors"

	"github.com/Azure/aks-durable-agents/internal/socketexec"
	"github.com/agent-primitives/sessions/api"
	"github.com/agent-primitives/sessions/controller"
	"github.com/agent-primitives/sessions/placement"
)

// This isolated static slot is a labelled demo bridge, not package admission.
const demoBridgeHarness = "demo-release-notes"

func validateDemoBridge(harnesses map[string]string, tools map[string]socketexec.Binding) error {
	if _, enabled := harnesses[demoBridgeHarness]; !enabled {
		return nil
	}
	binding := tools[demoBridgeHarness]
	if binding.Execute == nil || binding.DurableDedup == nil || !binding.DurableDedup("publish_release_notes") {
		return errors.New("demo bridge requires its durable local publication executor")
	}
	return nil
}

// Only the removable static demo slot is changed. Registration/package loading
// and legacy placement/model behavior remain outside this adapter.
func demoBridgeOptions(name, target string, model controller.ModelFunc, stream controller.StreamFunc, opts []placement.Option) (controller.ModelFunc, []placement.Option) {
	if name != demoBridgeHarness {
		return model, opts
	}
	return checkedBridgeModel(target, model), append(opts,
		placement.WithDescriptorID(name),
		placement.WithModelPolicy(api.ModelPolicy{Default: target, Allowed: []string{target}}),
		placement.WithStreamingModel(checkedBridgeStreamingModel(target, stream)),
		placement.WithDialer(func(inc api.Incarnation) (api.Harness, func() error, error) {
			harness, close, err := placement.DefaultDial(inc)
			if err != nil {
				return nil, close, err
			}
			return approvalHarness{harness}, close, nil
		}))
}

type approvalHarness struct{ api.Harness }

func (h approvalHarness) Run(ctx context.Context, start *api.Start, sink api.EventSink) error {
	return h.Harness.Run(ctx, start, approvalSink{sink})
}

type approvalSink struct{ api.EventSink }

// Refuse weak proposals before controller entry; never accept harness receipts,
// even before a proposal. Controller-produced receipts and typed parks stay intact.
func (s approvalSink) ToolCall(ctx context.Context, call api.ToolCall) (api.ToolResult, error) {
	if call.Tool == "publish_release_notes" && call.Mediation != api.MediationRequiresApproval {
		return api.ToolResult{}, errors.New("demo bridge: protected tool requires explicit approval mediation")
	}
	return s.EventSink.ToolCall(ctx, call)
}

func (s approvalSink) Report(context.Context, api.ToolResult) error {
	return errors.New("demo bridge: all tool results must come from the controller")
}

func checkedBridgeModel(target string, next controller.ModelFunc) controller.ModelFunc {
	return func(ctx context.Context, req api.ModelRequest) (api.ModelResponse, error) {
		if req.Model != target {
			return api.ModelResponse{}, errors.New("demo bridge model does not match host deployment")
		}
		return next(ctx, req)
	}
}

func checkedBridgeStreamingModel(target string, next controller.StreamFunc) controller.StreamFunc {
	return func(ctx context.Context, req api.ModelRequest, chunk func(string)) (api.ModelResponse, error) {
		if req.Model != target {
			return api.ModelResponse{}, errors.New("demo bridge model does not match host deployment")
		}
		return next(ctx, req, chunk)
	}
}
