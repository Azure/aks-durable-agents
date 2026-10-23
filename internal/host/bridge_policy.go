package host

import (
	"context"
	"errors"

	"github.com/Azure/aks-durable-agents/internal/demobridge"
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
		placement.WithDialer(approvalMinimumDialer(func(tool string) bool { return tool == "publish_release_notes" })))
}

func approvalMinimumDialer(required func(string) bool) placement.Dialer {
	return func(inc api.Incarnation) (api.Harness, func() error, error) {
		harness, close, err := placement.DefaultDial(inc)
		if err != nil {
			return nil, close, err
		}
		return demobridge.WithApprovalMinimum(harness, required), close, nil
	}
}

func checkedBridgeModel(target string, next func(context.Context, api.ModelRequest) (api.ModelResponse, error)) func(context.Context, api.ModelRequest) (api.ModelResponse, error) {
	return func(ctx context.Context, req api.ModelRequest) (api.ModelResponse, error) {
		if req.Model != target {
			return api.ModelResponse{}, errors.New("demo bridge model does not match host deployment")
		}
		return next(ctx, req)
	}
}

func checkedBridgeStreamingModel(target string, next func(context.Context, api.ModelRequest, func(string)) (api.ModelResponse, error)) func(context.Context, api.ModelRequest, func(string)) (api.ModelResponse, error) {
	return func(ctx context.Context, req api.ModelRequest, chunk func(string)) (api.ModelResponse, error) {
		if req.Model != target {
			return api.ModelResponse{}, errors.New("demo bridge model does not match host deployment")
		}
		return next(ctx, req, chunk)
	}
}
