package socketexec_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/agent-primitives/sessions/api"
)

func TestFrameBoundsIncludeNewlineAndNilArgumentsRemainNull(t *testing.T) {
	ln := listener(t)
	fn := executor(t, config(ln.Addr().String(), `,"durable_dedup":true`, ""))
	valid := `{"version":1,"call_id":"call-1","is_error":false}`
	response := valid + strings.Repeat(" ", maxFrame-len(valid)-1) + "\n"
	request, _ := serveOnce(t, ln, response, true)
	c := call()
	c.Args = nil
	if _, err := fn(context.Background(), scope, c); err != nil {
		t.Fatalf("maximum-sized response refused: %v", err)
	}
	var frame map[string]any
	if err := json.Unmarshal(<-request, &frame); err != nil {
		t.Fatal(err)
	}
	args, present := frame["arguments"]
	if !present || args != nil {
		t.Fatalf("nil arguments not preserved: %v", frame)
	}

	// Literal overhead includes the terminating newline, independent of encoder ordering.
	empty := `{"version":1,"harness":"publisher","session_uid":"session-a","call_id":"call-1","tool":"publish","arguments":{"text":""},"idempotency_key":"key-1"}` + "\n"
	c.Args = map[string]any{"text": strings.Repeat("x", maxFrame-len(empty))}
	request, _ = serveOnce(t, ln, valid+"\n", true)
	if _, err := fn(context.Background(), scope, c); err != nil {
		t.Fatalf("maximum-sized request refused: %v", err)
	}
	if got := len(<-request); got != maxFrame {
		t.Fatalf("request bytes=%d want=%d", got, maxFrame)
	}
	c.Args["text"] = c.Args["text"].(string) + "x"
	if _, err := fn(context.Background(), scope, c); err == nil {
		t.Fatal("request exceeding frame bound accepted")
	}
	noDial(t, ln)
}

func TestInvalidUTF8ArgumentsNeverDial(t *testing.T) {
	for _, args := range []map[string]any{
		{"text": string([]byte{0xff})},
		{string([]byte{0xff}): "value"},
		{"nested": []any{map[string]any{"text": string([]byte{0xff})}}},
	} {
		ln := listener(t)
		fn := executor(t, config(ln.Addr().String(), `,"durable_dedup":true`, ""))
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		c := call()
		c.Args = args
		_, err := fn(ctx, scope, c)
		cancel()
		if err == nil {
			t.Fatal("invalid UTF-8 arguments accepted")
		}
		noDial(t, ln)
	}
}

func TestAlreadyCanceledDoesNotDial(t *testing.T) {
	ln := listener(t)
	fn := executor(t, config(ln.Addr().String(), `,"durable_dedup":true`, ""))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := fn(ctx, scope, api.ToolCall{ID: "call-1", Tool: "publish", IdempotencyKey: "key-1"}); err == nil {
		t.Fatal("canceled call accepted")
	}
	noDial(t, ln)
}
