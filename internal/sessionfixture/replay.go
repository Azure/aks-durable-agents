package sessionfixture

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/agent-primitives/sessions/api"
	"github.com/agent-primitives/sessions/controller"
	"github.com/agent-primitives/sessions/eventlog"
)

type replayProof struct {
	SessionUID           string   `json:"session_uid"`
	HeadSeq              int64    `json:"head_seq"`
	HeadHash             string   `json:"head_hash"`
	CheckpointSeq        int64    `json:"checkpoint_seq"`
	ExpectedExecutionIDs []string `json:"expected_execution_ids"`
	CoveredExecutionIDs  []string `json:"covered_execution_ids"`
	ProviderCalls        int      `json:"provider_calls"`
	ExecutorCalls        int      `json:"executor_calls"`
	Completed            bool     `json:"completed"`
	Error                string   `json:"error,omitempty"`
}

type coverageHarness struct {
	api.Harness
	ids []string
}

func (h *coverageHarness) Run(ctx context.Context, s *api.Start, sink api.EventSink) error {
	if err := h.Harness.Run(ctx, s, sink); err != nil {
		return err
	}
	h.ids = append(h.ids, s.ExecutionID)
	return nil
}

// Controller.Replay deliberately skips unfinished turns. This stricter scenario proof
// rejects every unfinished invocation before invoking Replay and accounts for each Run.
func verifyReplay(ctx context.Context, uid string, records []eventlog.Record, h api.Harness) (proof replayProof, err error) {
	proof = replayProof{SessionUID: uid, ExpectedExecutionIDs: []string{}, CoveredExecutionIDs: []string{}}
	defer func() {
		if err != nil {
			proof.Error = err.Error()
		}
	}()
	if len(records) == 0 || uid == "" {
		return proof, errors.New("nonempty session journal is required")
	}
	last := records[len(records)-1]
	proof.HeadSeq = last.Seq
	proof.HeadHash = last.Hash
	memory := eventlog.NewFrom(records)
	if err = memory.Verify(); err != nil {
		return proof, err
	}
	starts := map[string]bool{}
	completed := map[string]bool{}
	current := ""
	for _, r := range records {
		e := r.Event
		if e.Kind == api.EventLifecycle {
			continue
		}
		if e.Kind == api.EventExecutionStart {
			if e.ExecutionID == "" || starts[e.ExecutionID] {
				return proof, errors.New("missing or duplicate execution ID")
			}
			// Enumerate all starts, even unfinished ones, before checking coverage below.
			starts[e.ExecutionID] = true
			proof.ExpectedExecutionIDs = append(proof.ExpectedExecutionIDs, e.ExecutionID)
			current = e.ExecutionID
		} else if e.ExecutionID == "" || !starts[e.ExecutionID] || current != e.ExecutionID || completed[e.ExecutionID] {
			return proof, errors.New("non-modern, interleaved or post-terminal execution record")
		}
		if e.Kind == api.EventEnd {
			if e.End == nil || e.End.State != "COMPLETED" {
				return proof, errors.New("execution did not end COMPLETED")
			}
			completed[e.ExecutionID] = true
			proof.CheckpointSeq = r.Seq
		}
	}
	if len(starts) == 0 {
		return proof, errors.New("no modern executions to cover")
	}
	for _, id := range proof.ExpectedExecutionIDs {
		if !completed[id] {
			return proof, fmt.Errorf("unfinished execution %q; full terminal replay refused", id)
		}
	}
	if proof.CheckpointSeq == 0 {
		return proof, errors.New("terminal END checkpoint required")
	}
	coverage := &coverageHarness{Harness: h, ids: []string{}}
	denyModel := func(context.Context, api.ModelRequest) (api.ModelResponse, error) {
		proof.ProviderCalls++
		return api.ModelResponse{}, errors.New("replay attempted provider call")
	}
	denyTool := func(context.Context, controller.ToolCallContext, api.ToolCall) (api.ToolResult, error) {
		proof.ExecutorCalls++
		return api.ToolResult{}, errors.New("replay attempted executor call")
	}
	// Replay uses an isolated copy: New cannot fence the real host or change its journal.
	c, e := controller.New(eventlog.AsStore(memory), denyModel, controller.WithSessionUID(uid), controller.WithToolExecutor(denyTool))
	if e != nil {
		return proof, e
	}
	_, err = c.Replay(ctx, coverage)
	proof.CoveredExecutionIDs = coverage.ids
	if err != nil {
		return proof, err
	}
	if proof.ProviderCalls != 0 || proof.ExecutorCalls != 0 || !slices.Equal(proof.ExpectedExecutionIDs, proof.CoveredExecutionIDs) {
		return proof, errors.New("replay coverage or zero-call assertion failed")
	}
	proof.Completed = true
	return proof, nil
}
