package socketexec

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"unicode/utf8"

	"github.com/agent-primitives/sessions/api"
	"github.com/agent-primitives/sessions/controller"
)

func toolFunc(harness string, tools map[string]binding) controller.ToolFunc {
	return func(ctx context.Context, scope controller.ToolCallContext, call api.ToolCall) (api.ToolResult, error) {
		var zero api.ToolResult
		route, exists := tools[call.Tool]
		if !exists {
			return zero, stageError(harness, call.Tool, "route not configured", nil)
		}
		if !route.dedup {
			return zero, stageError(harness, call.Tool, "durable deduplication not asserted", nil)
		}
		if scope.SessionUID == "" || call.ID == "" || call.IdempotencyKey == "" || !utf8.ValidString(scope.SessionUID+call.ID+call.Tool+call.IdempotencyKey) {
			return zero, stageError(harness, call.Tool, "invalid request identity", nil)
		}
		request := struct {
			Version        int            `json:"version"`
			Harness        string         `json:"harness"`
			SessionUID     string         `json:"session_uid"`
			CallID         string         `json:"call_id"`
			Tool           string         `json:"tool"`
			Arguments      map[string]any `json:"arguments"`
			IdempotencyKey string         `json:"idempotency_key"`
		}{1, harness, scope.SessionUID, call.ID, call.Tool, call.Args, call.IdempotencyKey}
		if !validStrings(call.Args, 0) {
			return zero, stageError(harness, call.Tool, "invalid request arguments", nil)
		}
		frame, err := json.Marshal(request)
		if err != nil || len(frame)+1 > maxBytes || strictJSON(frame) != nil {
			return zero, stageError(harness, call.Tool, "invalid or oversized request", nil)
		}
		frame = append(frame, '\n')
		ctx, cancel := context.WithTimeout(ctx, timeout(route.executor))
		defer cancel()
		if ctx.Err() != nil {
			return zero, callError(ctx, harness, call.Tool, "dial canceled")
		}
		conn, err := (&net.Dialer{}).DialContext(ctx, "unix", route.executor.Socket)
		if err != nil {
			return zero, callError(ctx, harness, call.Tool, "dial failed")
		}
		defer conn.Close()
		stop := context.AfterFunc(ctx, func() { conn.Close() })
		defer stop()
		deadline, _ := ctx.Deadline()
		if err := conn.SetDeadline(deadline); err != nil {
			return zero, callError(ctx, harness, call.Tool, "deadline failed")
		}
		for len(frame) != 0 {
			n, err := conn.Write(frame)
			if err != nil || n == 0 {
				return zero, callError(ctx, harness, call.Tool, "write failed")
			}
			frame = frame[n:]
		}
		// LimitReader bounds total bytes even without a newline or EOF; the
		// extra byte distinguishes an exact-size frame from an oversized one.
		line, err := bufio.NewReader(io.LimitReader(conn, maxBytes+1)).ReadBytes('\n')
		if err != nil || len(line) > maxBytes {
			return zero, callError(ctx, harness, call.Tool, "read failed or frame too large")
		}
		var response struct {
			Version int            `json:"version"`
			CallID  string         `json:"call_id"`
			IsError *bool          `json:"is_error"`
			Output  map[string]any `json:"output"`
			Error   string         `json:"error"`
		}
		if object(line, &response, "version call_id is_error output error", "output") != nil || response.Version != 1 || response.CallID != call.ID || response.IsError == nil {
			return zero, stageError(harness, call.Tool, "invalid or uncorrelated response", nil)
		}
		return api.ToolResult{Output: response.Output, IsError: *response.IsError, Error: response.Error}, nil
	}
}
