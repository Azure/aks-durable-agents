package sessionfixture

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"

	"github.com/agent-primitives/sessions/api"
)

// Run only on a consistent complete backup restored to private writable scratch.
// Original Config digest/model/session are retained before execution, never rehashed from today's profile.
func verifyBridgeJournal(ctx context.Context, path, uid, model, configSHA string) (proof replayProof, err error) {
	defer func() {
		if err != nil {
			proof.Completed = false
			proof.Error = err.Error()
		}
	}()
	if !identity(uid, 256) || !identity(model, 256) || !validBridgeDigest(configSHA) {
		return proof, errors.New("original demo session/model/Config digest required")
	}
	if err = checkBridgeData(filepath.Dir(path)); err != nil {
		return proof, err
	}
	records, err := readJournalRecords(ctx, path, uid)
	if err != nil {
		return proof, err
	}
	h := newBridgeHarness(model)
	desc, err := h.Describe(ctx)
	if err != nil {
		return proof, err
	}
	events := map[int64]api.Event{}
	starts, calls, results := 0, 0, 0
	var call *api.ToolCall
	var result *api.ToolResult
	for _, r := range records {
		events[r.Seq] = r.Event
		e := r.Event
		switch e.Kind {
		case api.EventExecutionStart:
			starts++
			s := e.ExecutionStart
			if s == nil || s.Harness != bridgeHarnessID || s.HarnessVersion != desc.Version || s.Model != model || bridgeDigest(s.Config) != configSHA {
				return proof, errors.New("original demo invocation binding mismatch")
			}
		case api.EventToolCall:
			calls++
			call = e.ToolCall
		case api.EventToolResult:
			results++
			result = e.Result
		}
	}
	if starts != 1 || calls != 1 || results != 1 || call == nil || result == nil || result.IsError || result.Code != api.ToolResultCodeUnspecified || result.ID != call.ID || validateBridgeTool(toolScope(uid), *call) != nil || call.Args["config_sha256"] != configSHA || !bridgeReceipt(uid, *call, result.Output) {
		return proof, errors.New("one successful bound local publication required")
	}
	request := events[result.ApprovalRequestSeq].Approval
	decision := events[result.ApprovalDecisionSeq].ApprovalResult
	if result.ApprovalRequestSeq <= 0 || result.ApprovalDecisionSeq <= result.ApprovalRequestSeq || request == nil || decision == nil || request.ToolCallID != call.ID || decision.ToolCallID != call.ID || !decision.Approved || decision.RequestSeq != result.ApprovalRequestSeq {
		return proof, errors.New("matching positive approval required")
	}
	db, err := readOnlyDB(filepath.Join(filepath.Dir(path), "publications.db"))
	if err != nil {
		return proof, err
	}
	defer db.Close()
	var raw, body []byte
	var artifact string
	var pubs, receipts int
	err = db.QueryRowContext(ctx, `SELECT p.artifact,p.body,r.output,(SELECT COUNT(*) FROM publications WHERE session_uid=?),(SELECT COUNT(*) FROM receipts WHERE session_uid=?) FROM publications p JOIN receipts r ON p.session_uid=r.session_uid AND p.key=r.key WHERE p.session_uid=? AND p.key=?`, uid, uid, uid, call.IdempotencyKey).Scan(&artifact, &body, &raw, &pubs, &receipts)
	if err != nil {
		return proof, err
	}
	var out map[string]any
	var stored struct {
		SessionUID string         `json:"session_uid"`
		Key        string         `json:"key"`
		Output     map[string]any `json:"output"`
	}
	if artifact != bridgeArtifact(uid, call.IdempotencyKey) || pubs != 1 || receipts != 1 || json.Unmarshal(raw, &out) != nil || json.Unmarshal(body, &stored) != nil || stored.SessionUID != uid || stored.Key != call.IdempotencyKey || !reflect.DeepEqual(stored.Output, result.Output) || !reflect.DeepEqual(out, result.Output) {
		return proof, errors.New("durable local publication/receipt differs from journal")
	}
	return verifyReplay(ctx, uid, records, h)
}
