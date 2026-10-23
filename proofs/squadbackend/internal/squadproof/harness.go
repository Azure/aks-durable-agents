//go:build squadproof

package squadproof

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/agent-primitives/sessions/api"
)

type scriptedPlan struct {
	Tools []scriptedTool `json:"tools"`
	Reply string         `json:"reply"`
}

type scriptedTool struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

type proofHarness struct{ role, packageDigest string }

// NewHarness builds a synthetic, stateless team proof harness. Each input is its
// complete immutable context, not a general conversation: earlier History is not
// needed. Replay consumes the recorded Start input and mediated completions,
// never current model-script defaults. No effects execute inside this harness.
// Invalid configuration is reported by Describe and Run, not by a panic here.
func NewHarness(role, packageDigest string) api.Harness {
	return &proofHarness{role: role, packageDigest: packageDigest}
}

func (h *proofHarness) Describe(context.Context) (api.Descriptor, error) {
	if (h.role != "lead" && h.role != "member") || !digest(h.packageDigest) {
		return api.Descriptor{}, ErrInvalid
	}
	tools := []api.ToolSpec{
		{Name: "read_context", Mediation: api.MediationControllerMediated},
		{Name: "publish", Mediation: api.MediationRequiresApproval},
	}
	if h.role == "lead" {
		tools = []api.ToolSpec{
			{Name: "dispatch_member", Mediation: api.MediationControllerMediated},
			{Name: "read_context", Mediation: api.MediationControllerMediated},
			{Name: "checkpoint", Mediation: api.MediationRequiresApproval},
		}
	}
	return api.Descriptor{
		ID:      "proof-" + h.role,
		Version: "squad-proof-v1-" + h.role + "-" + h.packageDigest,
		Models:  []string{"proof-model"},
		Tools:   tools,
		Capabilities: api.Capabilities{
			Resumability: api.ResumabilityStatelessReplay,
			ForkSafe:     true,
		},
	}, nil
}

func (h *proofHarness) Run(ctx context.Context, start *api.Start, sink api.EventSink) error {
	descriptor, err := h.Describe(ctx)
	if err != nil {
		return err
	}
	if start == nil || !identity(start.ExecutionID) || !identity(start.SessionUID) || len(start.Inputs) != 1 || start.Inputs[0].Role != "user" || strings.TrimSpace(start.Inputs[0].Text()) == "" {
		return ErrInvalid
	}
	input := start.Inputs[0].Text()
	plan, err := h.modelPlan(ctx, sink, "plan", input)
	if err != nil {
		return err
	}
	mediation := make(map[string]api.Mediation, len(descriptor.Tools))
	for _, tool := range descriptor.Tools {
		mediation[tool.Name] = tool.Mediation
	}
	// Validate the entire proposal before dispatching even its first tool. The
	// role contract, never model-provided metadata, sets tool authority.
	for _, tool := range plan.Tools {
		if _, ok := mediation[tool.Name]; !ok {
			return ErrInvalid
		}
	}
	results := make([]api.ToolResult, 0, len(plan.Tools))
	for i, tool := range plan.Tools {
		key := fmt.Sprintf("%s/%d/%s", start.ExecutionID, i, tool.Name)
		result, err := sink.ToolCall(ctx, api.ToolCall{
			ID: key, Tool: tool.Name, Args: tool.Arguments,
			Mediation: mediation[tool.Name], IdempotencyKey: key,
		})
		if err != nil {
			return err // Preserve typed park and replay-divergence errors verbatim.
		}
		if result.IsError && result.Code != api.ToolResultCodeApprovalDenied {
			return fmt.Errorf("proof: tool %s failed: %s", tool.Name, result.Error)
		}
		results = append(results, result)
	}
	// Finish is a separate mediated call after all receipts, giving the host a
	// receipt-before-END cut. A denial remains data for the model to explain.
	finishInput, err := json.Marshal(struct {
		Input   string           `json:"input"`
		Results []api.ToolResult `json:"results"`
	}{Input: input, Results: results})
	if err != nil {
		return err
	}
	finish, err := h.modelPlan(ctx, sink, "finish", string(finishInput))
	if err != nil {
		return err
	}
	if len(finish.Tools) != 0 || strings.TrimSpace(finish.Reply) == "" {
		return ErrInvalid
	}
	// Model JSON completions are already journaled. Emit only the final reply,
	// not a duplicate of either completion or the provisional plan reply.
	return sink.Output(ctx, finish.Reply)
}

func (h *proofHarness) modelPlan(ctx context.Context, sink api.EventSink, phase, input string) (scriptedPlan, error) {
	response, err := sink.Model(ctx, api.ModelRequest{
		Model: "proof-model",
		Messages: []api.Message{
			*api.TextMessage("system", fmt.Sprintf("squad-proof-v1 role=%s package=%s phase=%s", h.role, h.packageDigest, phase)),
			*api.TextMessage("user", input),
		},
	})
	if err != nil {
		return scriptedPlan{}, err
	}
	text := response.Message.Text()
	// The shared canonical boundary rejects nonobjects, duplicate keys, trailing
	// JSON and payloads over 16 KiB. Decode separately to reject unknown fields,
	// without changing the cached model response or argument number semantics.
	if _, _, err := canonical([]byte(text)); err != nil {
		return scriptedPlan{}, err
	}
	var plan scriptedPlan
	decoder := json.NewDecoder(strings.NewReader(text))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&plan); err != nil || len(plan.Tools) > 4 {
		return scriptedPlan{}, ErrInvalid
	}
	return plan, nil
}
