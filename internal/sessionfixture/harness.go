package sessionfixture

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"github.com/agent-primitives/sessions/api"
)

const modelID = "gpt-6-luna-2026-09-22"
const preparePrefix = "[prepare]\n"
const hostVersion = "reference-v1-frozen"

type releaseNotesHarness struct{ instructions, scenario string }

func newHarness(instructions string) *releaseNotesHarness {
	return &releaseNotesHarness{instructions: instructions}
}
func (h *releaseNotesHarness) Describe(context.Context) (api.Descriptor, error) {
	version := hostVersion
	if h.scenario == "v2" {
		version = v2HostVersion
	}
	return api.Descriptor{ID: "release-notes", Version: fmt.Sprintf(version+"-%x", sha256.Sum256([]byte(h.instructions))), Models: []string{modelID}, Tools: []api.ToolSpec{{Name: "publish_release_notes", Mediation: api.MediationRequiresApproval}}, Capabilities: api.Capabilities{Resumability: api.ResumabilityStatelessReplay, ForkSafe: true, ReasoningReplay: true}}, nil
}

func (h *releaseNotesHarness) Run(ctx context.Context, s *api.Start, sink api.EventSink) error {
	if s.ExecutionID == "" || len(s.Inputs) != 1 || s.Inputs[0].Role != "user" || strings.TrimSpace(s.Inputs[0].Text()) == "" {
		return errors.New("scenario requires one nonempty user input and a recorded execution ID")
	}
	history, err := conversationHistory(s.History)
	if err != nil {
		return err
	}
	messages := []api.Message{*api.TextMessage("system", h.instructions)}
	messages = append(messages, history...)
	input, preparation, err := modelInput(s.Inputs[0])
	if err != nil {
		return err
	}
	messages = append(messages, input)
	response, err := sink.Model(ctx, api.ModelRequest{Model: modelID, Messages: messages})
	if err != nil {
		return err
	}
	draft := response.Message.Text()
	if strings.TrimSpace(draft) == "" || len(draft) > maxDraftBytes {
		return errors.New("model returned empty or oversized draft")
	}
	if h.scenario == "v2" {
		if err := validateV2Draft(draft); err != nil {
			return err
		}
	}
	// Preparation is an explicit host mode; the model completion is already journaled.
	// No tool request or extra host OUTPUT is needed. Replay makes the same choice.
	if preparation {
		return nil
	}
	// Publishing is a deterministic host step, not a model-selected function call.
	// Model already records the draft OUTPUT; never emit a duplicate draft here.
	result, err := sink.ToolCall(ctx, scenarioCall(s.ExecutionID, "publish_release_notes", map[string]any{"draft": draft, "destination": "release-notes-demo"}))
	if err != nil {
		return err
	} // propagate typed approval park immediately
	if result.IsError {
		if result.Code == api.ToolResultCodeApprovalDenied {
			return sink.Output(ctx, "Publication denied; nothing published.")
		}
		return errors.New("publication executor failed; no publication success claimed")
	}
	return sink.Output(ctx, "Published locally: release-notes-demo.")
}

// The pinned controller correlates MODEL_CALL with its next effect, OUTPUT (no
// call ID exists on OUTPUT). Only that completion is conversation history:
// additional host OUTPUT and tool receipts must never become model messages.
func conversationHistory(history []api.Event) ([]api.Message, error) {
	var messages []api.Message
	pending := ""
	for _, e := range history {
		switch e.Kind {
		case api.EventModelCall:
			if pending != "" || e.ModelCall == nil || e.ExecutionID == "" {
				return nil, errors.New("invalid historical model call sequence")
			}
			pending = e.ExecutionID
		case api.EventOutput:
			if pending != "" {
				if e.ExecutionID != pending || e.Message == nil {
					return nil, errors.New("invalid historical model completion")
				}
				messages = append(messages, *e.Message)
				pending = ""
			}
		case api.EventInput:
			if pending != "" || e.Message == nil {
				return nil, errors.New("invalid historical input sequence")
			}
			input, _, err := modelInput(*e.Message)
			if err != nil {
				return nil, err
			}
			messages = append(messages, input)
		case api.EventLifecycle, api.EventUsage:
		// These are not effects or conversation messages.
		default:
			if pending != "" {
				return nil, errors.New("historical model call lacks completion")
			}
		}
	}
	if pending != "" {
		return nil, errors.New("historical model call lacks completion")
	}
	return messages, nil
}

// Keep the original input in the journal, but interpret this exact prefix for
// current and historical model messages. Never trim ordinary publication input.
func modelInput(input api.Message) (api.Message, bool, error) {
	text, preparation := strings.CutPrefix(input.Text(), preparePrefix)
	if !preparation {
		return input, false, nil
	}
	if strings.TrimSpace(text) == "" {
		return api.Message{}, true, errors.New("preparation requires nonempty content")
	}
	return *api.TextMessage(input.Role, text), true, nil
}

func scenarioCall(executionID, tool string, args map[string]any) api.ToolCall {
	key := executionID + "/" + tool
	return api.ToolCall{ID: key, Tool: tool, Args: args, Mediation: api.MediationRequiresApproval, IdempotencyKey: key}
}
