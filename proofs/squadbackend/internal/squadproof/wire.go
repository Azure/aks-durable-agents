//go:build squadproof

package squadproof

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"sync"
	"time"

	"github.com/agent-primitives/sessions/api"
	"github.com/agent-primitives/sessions/controller"
)

type toolRequest struct {
	Version    int            `json:"version"`
	Harness    string         `json:"harness"`
	SessionUID string         `json:"session_uid"`
	CallID     string         `json:"call_id"`
	Tool       string         `json:"tool"`
	Arguments  map[string]any `json:"arguments"`
	Key        string         `json:"idempotency_key"`
}
type toolResponse struct {
	Version int            `json:"version"`
	CallID  string         `json:"call_id"`
	IsError bool           `json:"is_error"`
	Output  map[string]any `json:"output,omitempty"`
	Error   string         `json:"error,omitempty"`
}

// ServeExecutor implements the existing Unix protocol, independently of the host
// adapter. Only the trusted local Sessions caller supplies the session envelope.
func ServeExecutor(ctx context.Context, listener net.Listener, l *Ledger) error {
	var wg sync.WaitGroup
	slots := make(chan struct{}, 16)
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			listener.Close()
		case <-done:
		}
	}()
	defer wg.Wait()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			conn.Close()
			return nil
		}
		wg.Go(func() {
			defer func() { <-slots }()
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			serveTool(ctx, conn, l)
		})
	}
}
func serveTool(ctx context.Context, conn net.Conn, l *Ledger) {
	if _, err := l.attempt(ctx, "executor", "socket"); err != nil {
		return
	}
	reader := bufio.NewReader(io.LimitReader(conn, (1<<20)+1))
	raw, err := reader.ReadBytes('\n')
	if err != nil || len(raw) > 1<<20 || reader.Buffered() != 0 {
		return
	}
	if _, _, err = canonical(raw); err != nil {
		return
	}
	var req toolRequest
	if arguments(raw, &req, "version harness session_uid call_id tool arguments idempotency_key") != nil || req.Version != 1 || !identity(req.SessionUID) || !identity(req.CallID) || !identity(req.Key) {
		return
	}
	var id string
	err = l.db.QueryRowContext(ctx, `SELECT id FROM operations WHERE session_uid=?`, req.SessionUID).Scan(&id)
	var result api.ToolResult
	if err == nil {
		var op Operation
		op, err = l.Operation(ctx, id)
		if err == nil && (req.Harness != "proof-"+op.Member || op.PackageDigest != proofDigest()) {
			err = ErrInvalid
		}
	}
	if err == nil {
		mediation := api.MediationControllerMediated
		if req.Tool == "publish" || req.Tool == "checkpoint" {
			mediation = api.MediationRequiresApproval
		}
		if err := l.hit(ctx, "executor.before-"+req.Tool); err != nil {
			return
		}
		result, err = (&Executor{Ledger: l}).Execute(ctx, controller.ToolCallContext{SessionUID: req.SessionUID}, api.ToolCall{ID: req.CallID, Tool: req.Tool, Args: req.Arguments, IdempotencyKey: req.Key, Mediation: mediation})
	}
	if err == nil {
		if cutErr := l.hit(ctx, "executor.after-"+req.Tool); cutErr != nil {
			return
		}
	}
	response := toolResponse{Version: 1, CallID: req.CallID, IsError: err != nil, Output: result.Output}
	if err != nil {
		response.Error = "proof executor refused; reconcile state before retry"
	}
	_ = json.NewEncoder(conn).Encode(response)
}
