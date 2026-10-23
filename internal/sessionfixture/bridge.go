package sessionfixture

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/agent-primitives/sessions/api"
	"github.com/agent-primitives/sessions/controller"
)

const bridgeHarnessID = "demo-release-notes"
const bridgeScenario = "source-demo-v1"
const bridgeMarker = "{\"scenario\":\"source-demo-v1\"}\n"
const bridgeTool = "publish_release_notes"

type bridgeConfig struct {
	SystemPrompt string `json:"system_prompt"`
	Reference    string `json:"reference"`
}

func bridgeDigest(raw []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(raw)) }
func validBridgeDigest(s string) bool {
	if len(s) != 71 || !strings.HasPrefix(s, "sha256:") || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s[7:])
	return err == nil
}
func bridgeText(s string, limit int) bool {
	if !utf8.ValidString(s) || strings.TrimSpace(s) == "" || len(s) > limit {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return false
		}
	}
	return true
}
func decodeBridgeConfig(raw []byte) (bridgeConfig, error) {
	var c bridgeConfig
	if len(raw) > 2<<20 || strictJSON(raw, []string{"system_prompt", "reference"}, &c) != nil || !bridgeText(c.SystemPrompt, 256<<10) || !validBridgeDigest(c.Reference) {
		return bridgeConfig{}, errors.New("demo bridge requires bounded system_prompt and opaque digest reference")
	}
	return c, nil
}
func bridgeArtifact(uid, key string) string {
	tuple, _ := json.Marshal([]string{uid, key})
	return fmt.Sprintf("%x.json", sha256.Sum256(tuple))
}
func bridgeReceipt(uid string, c api.ToolCall, out map[string]any) bool {
	return len(out) == 5 && out["local_demo"] == true && out["artifact"] == bridgeArtifact(uid, c.IdempotencyKey) && out["draft"] == c.Args["draft"] && out["destination"] == "release-notes-demo" && out["config_sha256"] == c.Args["config_sha256"]
}

type bridgeHarness struct{ model string }

func newBridgeHarness(model string) *bridgeHarness { return &bridgeHarness{model: model} }
func (h *bridgeHarness) Describe(context.Context) (api.Descriptor, error) {
	if !identity(h.model, 256) {
		return api.Descriptor{}, errors.New("demo bridge requires an explicit target model")
	}
	return api.Descriptor{ID: bridgeHarnessID, Version: fmt.Sprintf("source-demo-v1-%x", sha256.Sum256([]byte(h.model))), Models: []string{h.model}, Tools: []api.ToolSpec{{Name: bridgeTool, Mediation: api.MediationRequiresApproval}}, Capabilities: api.Capabilities{Resumability: api.ResumabilityStatelessReplay, ReasoningReplay: true}}, nil
}
func (h *bridgeHarness) Run(ctx context.Context, s *api.Start, sink api.EventSink) error {
	if _, err := h.Describe(ctx); err != nil {
		return err
	}
	if s == nil || !identity(s.SessionUID, 256) || !identity(s.ExecutionID, 256) || s.Model != h.model || len(s.Inputs) != 1 || s.Inputs[0].Role != "user" || len(s.Inputs[0].Parts) != 1 {
		return errors.New("demo bridge requires one text input and original session, execution and target model")
	}
	part := s.Inputs[0].Parts[0]
	if part.Text == nil || part.File != nil || part.Data != nil || part.Reasoning != nil || part.ToolCall != nil || part.ToolResult != nil || !bridgeText(part.Text.Text, 16<<10) {
		return errors.New("demo bridge requires bounded plain text input")
	}
	for _, e := range s.History {
		if e.Kind != api.EventLifecycle {
			return errors.New("demo bridge is a single-turn source-file proof")
		}
	}
	config, err := decodeBridgeConfig(s.Config)
	if err != nil {
		return err
	}
	response, err := sink.Model(ctx, api.ModelRequest{Model: s.Model, Messages: []api.Message{*api.TextMessage("system", config.SystemPrompt), s.Inputs[0]}})
	if err != nil {
		return err
	}
	if response.Message.Role != "assistant" {
		return errors.New("demo bridge requires an assistant draft")
	}
	for _, p := range response.Message.Parts {
		if p.File != nil || p.Data != nil || p.ToolCall != nil || p.ToolResult != nil {
			return errors.New("demo bridge model may return only draft text and reasoning")
		}
	}
	draft := response.Message.Text()
	if !bridgeText(draft, maxDraftBytes) {
		return errors.New("demo bridge model returned an invalid bounded draft")
	}
	// This is a deterministic local proposal, not a model-selected tool. Its host
	// route imposes the approval minimum independently of this requested mediation.
	call := scenarioCall(s.ExecutionID, bridgeTool, map[string]any{"draft": draft, "destination": "release-notes-demo", "config_sha256": bridgeDigest(s.Config)})
	result, err := sink.ToolCall(ctx, call)
	if err != nil {
		return err
	}
	if result.IsError {
		if result.Code == api.ToolResultCodeApprovalDenied {
			return sink.Output(ctx, "Local publication denied; nothing published.")
		}
		return errors.New("demo bridge publication failed; no success claimed")
	}
	if result.ID != call.ID || result.Code != api.ToolResultCodeUnspecified || !bridgeReceipt(s.SessionUID, call, result.Output) {
		return errors.New("demo bridge publication receipt mismatch")
	}
	return sink.Output(ctx, "Published locally: "+result.Output["artifact"].(string))
}

func validateBridgeTool(scope controller.ToolCallContext, c api.ToolCall) error {
	draft, ok := c.Args["draft"].(string)
	digest, digestOK := c.Args["config_sha256"].(string)
	if !identity(scope.SessionUID, 256) || !identity(c.ID, 256) || !identity(c.IdempotencyKey, 512) || c.Mediation != api.MediationRequiresApproval || c.Tool != bridgeTool || len(c.Args) != 3 || c.Args["destination"] != "release-notes-demo" || !ok || !bridgeText(draft, maxDraftBytes) || !digestOK || !validBridgeDigest(digest) {
		return errors.New("demo bridge requires a bounded local publication bound to execution config")
	}
	return nil
}
