package sessionfixture

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"

	"github.com/Azure/aks-durable-agents/internal/demobridge"
	"github.com/agent-primitives/sessions/api"
	"github.com/agent-primitives/sessions/eventlog"
)

type bridgeExpectation struct{ ConfigSHA256, Model, Reference string }
type bridgeReplayProof struct {
	replayProof
	BridgeOnly     bool   `json:"bridge_only"`
	Reference      string `json:"reference"`
	ConfigSHA256   string `json:"config_sha256"`
	TargetModel    string `json:"target_model"`
	Artifact       string `json:"artifact,omitempty"`
	TargetExamples string `json:"target_examples"`
}

// Expectations must be retained when establishing the run, not reconstructed
// from whichever producer profile/config exists when verification is requested.
func bridgePublishedBinding(uid string, records []eventlog.Record, want bridgeExpectation) (string, string, error) {
	if !identity(uid, 256) || !identity(want.Model, 256) || !validBridgeDigest(want.ConfigSHA256) || !validBridgeDigest(want.Reference) {
		return "", "", errors.New("original demo session/config/model/reference binding is required")
	}
	descriptor, err := newBridgeHarness(want.Model).Describe(context.Background())
	if err != nil {
		return "", "", err
	}
	var call *api.ToolCall
	var result *api.ToolResult
	var requestSeq, decisionSeq int64
	starts, models, requests, decisions, calls, results := 0, 0, 0, 0, 0, 0
	execution := ""
	for _, r := range records {
		e := r.Event
		switch e.Kind {
		case api.EventExecutionStart:
			starts++
			s := e.ExecutionStart
			if s == nil || e.ExecutionID == "" || s.Model != want.Model || s.Harness != bridgeHarnessID || s.HarnessVersion != descriptor.Version || bridgeDigest(s.Config) != want.ConfigSHA256 {
				return "", "", errors.New("original demo invocation binding mismatch")
			}
			c, err := decodeBridgeConfig(s.Config)
			if err != nil || c.Reference != want.Reference {
				return "", "", errors.New("original demo producer reference mismatch")
			}
			execution = e.ExecutionID
		case api.EventModelCall:
			models++
			if e.ModelCall == nil || e.ModelCall.Model != want.Model {
				return "", "", errors.New("demo model-call identity mismatch")
			}
		case api.EventToolCall:
			calls++
			call = e.ToolCall
			if call == nil || validateBridgeTool(toolScope(uid), *call) != nil || call.Args["config_sha256"] != want.ConfigSHA256 || call.ID != execution+"/"+bridgeTool || call.IdempotencyKey != call.ID {
				return "", "", errors.New("demo publication intent mismatch")
			}
		case api.EventApprovalRequest:
			requests++
			requestSeq = r.Seq
			if call == nil || e.Approval == nil || e.Approval.ToolCallID != call.ID {
				return "", "", errors.New("demo approval request mismatch")
			}
		case api.EventApprovalResult:
			decisions++
			decisionSeq = r.Seq
			if call == nil || e.ApprovalResult == nil || !e.ApprovalResult.Approved || e.ApprovalResult.ToolCallID != call.ID || e.ApprovalResult.RequestSeq != requestSeq || requestSeq == 0 {
				return "", "", errors.New("demo publication lacks matching positive approval")
			}
		case api.EventToolResult:
			results++
			result = e.Result
			if call == nil || result == nil || result.IsError || result.Code != api.ToolResultCodeUnspecified || result.ID != call.ID || result.ApprovalRequestSeq != requestSeq || result.ApprovalDecisionSeq != decisionSeq || decisionSeq == 0 || !bridgeReceipt(uid, *call, result.Output) {
				return "", "", errors.New("demo publication receipt/approval mismatch")
			}
		}
	}
	if starts != 1 || models != 1 || calls != 1 || requests != 1 || decisions != 1 || results != 1 {
		return "", "", errors.New("demo proof requires one complete approved publication")
	}
	body, err := json.Marshal(struct {
		SessionUID string         `json:"session_uid"`
		Key        string         `json:"key"`
		Output     map[string]any `json:"output"`
	}{uid, call.IdempotencyKey, result.Output})
	if err != nil {
		return "", "", err
	}
	return bridgeArtifact(uid, call.IdempotencyKey), bridgeDigest(body), nil
}

func verifyBridgeJournal(ctx context.Context, data, path, uid string, want bridgeExpectation) (proof bridgeReplayProof, err error) {
	proof = bridgeReplayProof{BridgeOnly: true, Reference: want.Reference, ConfigSHA256: want.ConfigSHA256, TargetModel: want.Model, TargetExamples: "not_run"}
	defer func() {
		if err != nil {
			proof.Completed = false
			proof.Error = err.Error()
		}
	}()
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Dir(path) != data {
		return proof, errors.New("demo replay requires journal in its original data directory")
	}
	if err := checkBridgeData(data); err != nil {
		return proof, err
	}
	for _, database := range []string{path, filepath.Join(data, "publications.db")} {
		if err := requireBridgeCheckpoint(database); err != nil {
			return proof, err
		}
	}
	before, err := inspectBridge(data)
	if err != nil {
		return proof, err
	}
	if before.PublicationCount != 1 || before.ReceiptCount != 1 || len(before.Artifacts) != 1 {
		return proof, errors.New("demo replay requires exactly one retained publication and receipt")
	}
	beforeJournal, err := journalBytes(path)
	if err != nil {
		return proof, err
	}
	beforeEffects, err := journalBytes(filepath.Join(data, "publications.db"))
	if err != nil {
		return proof, err
	}
	records, err := readBridgeRecords(ctx, path, uid)
	if err != nil {
		return proof, err
	}
	artifact, digest, err := bridgePublishedBinding(uid, records, want)
	if err != nil {
		return proof, err
	}
	if before.Artifacts[0].Name != artifact || before.Artifacts[0].Digest != digest {
		return proof, errors.New("retained local artifact differs from journal receipt")
	}
	h := demobridge.WithApprovalMinimum(newBridgeHarness(want.Model), func(tool string) bool { return tool == bridgeTool })
	proof.replayProof, err = verifyReplay(ctx, uid, records, h)
	if err != nil {
		return proof, err
	}
	afterRecords, err := readBridgeRecords(ctx, path, uid)
	if err != nil {
		return proof, err
	}
	after, err := inspectBridge(data)
	if err != nil {
		return proof, err
	}
	afterJournal, err := journalBytes(path)
	if err != nil {
		return proof, err
	}
	afterEffects, err := journalBytes(filepath.Join(data, "publications.db"))
	if err != nil {
		return proof, err
	}
	if !reflect.DeepEqual(beforeJournal, afterJournal) {
		return proof, errors.New("demo replay changed journal byte inventory")
	}
	if !reflect.DeepEqual(beforeEffects, afterEffects) {
		return proof, errors.New("demo replay changed publication byte inventory")
	}
	if !reflect.DeepEqual(records, afterRecords) {
		return proof, errors.New("demo replay changed decoded journal records")
	}
	if !reflect.DeepEqual(before, after) {
		return proof, errors.New("demo replay changed publication inventory")
	}
	proof.Artifact = artifact
	return proof, nil
}
