//go:build squadproof

package squadproof

import (
	"context"
	"errors"
	"slices"

	"github.com/agent-primitives/sessions/api"
	v1 "github.com/agent-primitives/sessions/api/genpb"
	"github.com/agent-primitives/sessions/controller"
	"github.com/agent-primitives/sessions/eventlog"
	"github.com/agent-primitives/sessions/wire"
)

type ReplayProof struct {
	SessionUID string   `json:"session_uid"`
	HeadSeq    int64    `json:"head_seq"`
	HeadHash   string   `json:"head_hash"`
	Executions []string `json:"executions"`
	Covered    []string `json:"covered"`
	Models     int      `json:"model_calls"`
	Tools      int      `json:"tool_calls"`
}
type replayHarness struct {
	api.Harness
	ids []string
}

func (h *replayHarness) Run(ctx context.Context, s *api.Start, sink api.EventSink) error {
	if err := h.Harness.Run(ctx, s, sink); err != nil {
		return err
	}
	h.ids = append(h.ids, s.ExecutionID)
	return nil
}

func VerifyReplay(ctx context.Context, uid string, records []*v1.LogRecord, h api.Harness) (ReplayProof, error) {
	domain := make([]eventlog.Record, 0, len(records))
	for _, record := range records {
		if record == nil || record.GetEvent() == nil {
			return ReplayProof{}, ErrInvalid
		}
		domain = append(domain, eventlog.Record{Seq: record.GetSeq(), PrevHash: record.GetPrevHash(), Hash: record.GetContentHash(), Fence: record.GetFence(), Event: wire.EventFromProto(record.GetEvent())})
	}
	return replayRecords(ctx, uid, domain, h)
}

// Replay deliberately skips unfinished modern executions upstream. Require full
// terminal coverage before invoking the real controller, over an isolated copy.
func replayRecords(ctx context.Context, uid string, records []eventlog.Record, h api.Harness) (proof ReplayProof, err error) {
	proof.SessionUID = uid
	if !identity(uid) || len(records) == 0 {
		return proof, ErrInvalid
	}
	last := records[len(records)-1]
	proof.HeadSeq = last.Seq
	proof.HeadHash = last.Hash
	memory := eventlog.NewFrom(records)
	if err = memory.Verify(); err != nil {
		return proof, err
	}
	started, completed := map[string]bool{}, map[string]bool{}
	current := ""
	for _, record := range records {
		e := record.Event
		if e.Kind == api.EventLifecycle {
			continue
		}
		if e.Kind == api.EventExecutionStart {
			if e.ExecutionID == "" || started[e.ExecutionID] || current != "" && !completed[current] {
				return proof, ErrInvalid
			}
			current = e.ExecutionID
			started[current] = true
			proof.Executions = append(proof.Executions, current)
		} else if current == "" || e.ExecutionID != current || completed[current] {
			return proof, ErrInvalid
		}
		if e.Kind == api.EventEnd {
			if e.End == nil || e.End.State != "COMPLETED" {
				return proof, ErrHeld
			}
			completed[current] = true
		}
	}
	if len(started) == 0 {
		return proof, ErrInvalid
	}
	for _, id := range proof.Executions {
		if !completed[id] {
			return proof, ErrHeld
		}
	}
	coverage := &replayHarness{Harness: h}
	denyModel := func(context.Context, api.ModelRequest) (api.ModelResponse, error) {
		proof.Models++
		return api.ModelResponse{}, errors.New("proof replay attempted model")
	}
	denyTool := func(context.Context, controller.ToolCallContext, api.ToolCall) (api.ToolResult, error) {
		proof.Tools++
		return api.ToolResult{}, errors.New("proof replay attempted tool")
	}
	c, err := controller.New(eventlog.AsStore(memory), denyModel, controller.WithSessionUID(uid), controller.WithToolExecutor(denyTool))
	if err != nil {
		return proof, err
	}
	_, err = c.Replay(ctx, coverage)
	proof.Covered = coverage.ids
	if err != nil {
		return proof, err
	}
	if proof.Models != 0 || proof.Tools != 0 || !slices.Equal(proof.Executions, proof.Covered) {
		return proof, ErrInvalid
	}
	return proof, nil
}
