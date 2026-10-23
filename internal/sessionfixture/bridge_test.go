package sessionfixture

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/agent-primitives/sessions/api"
)

const bridgeTestModel = "target-model"
const bridgeTestDraft = "## Fictional release notes\n- Faster search (#218).\nPlease approve before posting.\n"

func bridgeTestConfig() []byte {
	return []byte(`{"system_prompt":"Write release notes exactly as authored.","reference":"sha256:` + strings.Repeat("a", 64) + `"}`)
}
func bridgeTestStart() *api.Start {
	return &api.Start{SessionUID: "bridge-session", ExecutionID: "execution-1", Model: bridgeTestModel, Config: bridgeTestConfig(), Inputs: []api.Message{*api.TextMessage("user", "Draft fictional release facts.")}}
}

type bridgeTestSink struct {
	api.EventSink
	requests       []api.ModelRequest
	calls          []api.ToolCall
	outputs        []string
	response       api.Message
	toolError      error
	deny           bool
	corruptReceipt bool
}

func (s *bridgeTestSink) Model(_ context.Context, r api.ModelRequest) (api.ModelResponse, error) {
	s.requests = append(s.requests, r)
	msg := s.response
	if msg.Role == "" {
		msg = *api.TextMessage("assistant", bridgeTestDraft)
	}
	return api.ModelResponse{Message: msg}, nil
}
func (s *bridgeTestSink) ToolCall(_ context.Context, c api.ToolCall) (api.ToolResult, error) {
	s.calls = append(s.calls, c)
	if s.toolError != nil {
		return api.ToolResult{}, s.toolError
	}
	if s.deny {
		return api.ToolResult{ID: c.ID, IsError: true, Code: api.ToolResultCodeApprovalDenied}, nil
	}
	tuple := []byte(`["bridge-session","execution-1/publish_release_notes"]`)
	artifact := fmt.Sprintf("%x.json", sha256.Sum256(tuple))
	if s.corruptReceipt {
		artifact = "wrong"
	}
	return api.ToolResult{ID: c.ID, Output: map[string]any{"local_demo": true, "artifact": artifact, "draft": c.Args["draft"], "destination": "release-notes-demo", "config_sha256": c.Args["config_sha256"]}}, nil
}
func (s *bridgeTestSink) Output(_ context.Context, v string) error {
	s.outputs = append(s.outputs, v)
	return nil
}

func TestBridgeHarnessBindsConfigModelAndVerbatimPublication(t *testing.T) {
	h := newBridgeHarness(bridgeTestModel)
	start := bridgeTestStart()
	sink := &bridgeTestSink{}
	if err := h.Run(t.Context(), start, sink); err != nil {
		t.Fatal(err)
	}
	if len(sink.requests) != 1 || len(sink.calls) != 1 || len(sink.outputs) != 1 {
		t.Fatal("not one deterministic draft/publication")
	}
	req := sink.requests[0]
	if req.Model != bridgeTestModel || len(req.Messages) != 2 || req.Messages[0].Role != "system" || req.Messages[0].Text() != "Write release notes exactly as authored." || req.Messages[1].Text() != "Draft fictional release facts." {
		t.Fatal("model input projection/model changed")
	}
	c := sink.calls[0]
	wantSHA := fmt.Sprintf("sha256:%x", sha256.Sum256(start.Config))
	if c.Tool != "publish_release_notes" || c.ID != "execution-1/publish_release_notes" || c.IdempotencyKey != c.ID || c.Mediation != api.MediationRequiresApproval || len(c.Args) != 3 || c.Args["draft"] != bridgeTestDraft || c.Args["config_sha256"] != wantSHA || c.Args["destination"] != "release-notes-demo" {
		t.Fatal("verbatim approval-gated binding lost")
	}
	if !strings.Contains(sink.outputs[0], "Published locally:") || strings.Contains(sink.outputs[0], "Please approve") {
		t.Fatal("draft duplicated or external publication claimed")
	}
	desc, err := h.Describe(t.Context())
	if err != nil || desc.ID != "demo-release-notes" || len(desc.Models) != 1 || desc.Models[0] != bridgeTestModel {
		t.Fatal("descriptor model/route not bound")
	}
}
func TestBridgeHarnessRefusesBeforeModel(t *testing.T) {
	for _, kind := range []string{"empty-model", "different-model", "missing-session", "missing-execution", "second-turn", "empty-input", "nontext-input", "bad-config", "duplicate-config", "unknown-config", "trailing-config", "null-prompt", "oversize-prompt", "bad-reference"} {
		t.Run(kind, func(t *testing.T) {
			start := bridgeTestStart()
			switch kind {
			case "empty-model":
				start.Model = ""
			case "different-model":
				start.Model = "another-model"
			case "missing-session":
				start.SessionUID = ""
			case "missing-execution":
				start.ExecutionID = ""
			case "second-turn":
				start.History = []api.Event{{Kind: api.EventInput, Message: api.TextMessage("user", "previous")}}
			case "empty-input":
				start.Inputs[0] = *api.TextMessage("user", "")
			case "nontext-input":
				start.Inputs[0].Parts = append(start.Inputs[0].Parts, api.Part{File: &api.FilePart{URI: "https://example.invalid/input"}})
			case "bad-config":
				start.Config = []byte("PRIVATE malformed")
			case "duplicate-config":
				start.Config = append([]byte(`{"system_prompt":"PRIVATE",`), start.Config[1:]...)
			case "unknown-config":
				start.Config = append([]byte(`{"model":"PRIVATE",`), start.Config[1:]...)
			case "trailing-config":
				start.Config = append(start.Config, []byte(" {}")...)
			case "null-prompt":
				start.Config = []byte(`{"system_prompt":null,"reference":"sha256:` + strings.Repeat("a", 64) + `"}`)
			case "oversize-prompt":
				start.Config = []byte(`{"system_prompt":"` + strings.Repeat("x", 256*1024+1) + `","reference":"sha256:` + strings.Repeat("a", 64) + `"}`)
			case "bad-reference":
				start.Config = []byte(`{"system_prompt":"PRIVATE","reference":"not-a-digest"}`)
			}
			sink := &bridgeTestSink{}
			err := newBridgeHarness(bridgeTestModel).Run(t.Context(), start, sink)
			if err == nil || strings.Contains(err.Error(), "PRIVATE") || len(sink.requests) != 0 || len(sink.calls) != 0 {
				t.Fatalf("unsafe admission: %v", err)
			}
		})
	}
}
func TestBridgeHarnessParkDenialAndReceiptFailure(t *testing.T) {
	parked := errors.New("parked")
	for _, kind := range []string{"park", "deny", "receipt"} {
		t.Run(kind, func(t *testing.T) {
			s := &bridgeTestSink{}
			if kind == "park" {
				s.toolError = parked
			}
			if kind == "deny" {
				s.deny = true
			}
			if kind == "receipt" {
				s.corruptReceipt = true
			}
			err := newBridgeHarness(bridgeTestModel).Run(t.Context(), bridgeTestStart(), s)
			if len(s.requests) != 1 || len(s.calls) != 1 {
				t.Fatal("draft or proposal count changed")
			}
			if kind == "park" {
				if !errors.Is(err, parked) || len(s.outputs) != 0 {
					t.Fatal("park was swallowed")
				}
			} else if kind == "deny" {
				if err != nil || len(s.outputs) != 1 || !strings.Contains(s.outputs[0], "denied") {
					t.Fatal("denial not preserved")
				}
			} else if err == nil || len(s.outputs) != 0 {
				t.Fatal("forged receipt reported published")
			}
		})
	}
	for _, draft := range []string{"", strings.Repeat("x", 32769), "bad\x00draft"} {
		s := &bridgeTestSink{response: *api.TextMessage("assistant", draft)}
		if err := newBridgeHarness(bridgeTestModel).Run(t.Context(), bridgeTestStart(), s); err == nil || len(s.calls) != 0 {
			t.Fatal("invalid draft reached publication")
		}
	}
}
func TestBridgeConfigHashesExactBytes(t *testing.T) {
	a := bridgeTestConfig()
	var object map[string]any
	if err := json.Unmarshal(a, &object); err != nil {
		t.Fatal(err)
	}
	b, err := json.MarshalIndent(object, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	var hashes []any
	for _, raw := range [][]byte{a, b} {
		start := bridgeTestStart()
		start.Config = raw
		s := &bridgeTestSink{}
		if err := newBridgeHarness(bridgeTestModel).Run(t.Context(), start, s); err != nil {
			t.Fatal(err)
		}
		hashes = append(hashes, s.calls[0].Args["config_sha256"])
	}
	if hashes[0] == hashes[1] {
		t.Fatal("raw Config identity was normalized away")
	}
}
