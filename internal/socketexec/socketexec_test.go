package socketexec_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Azure/aks-durable-agents/internal/socketexec"
	"github.com/agent-primitives/sessions/api"
	"github.com/agent-primitives/sessions/controller"
)

const maxFrame = 1 << 20

func config(socket, dedup, timeout string) string {
	return fmt.Sprintf(`{"version":1,"executors":[{"name":"pub","type":"unix","socket":%q%s}],"tools":[{"harness":"publisher","tool":"publish","executor":"pub"%s}]}`, socket, timeout, dedup)
}

func load(t *testing.T, text string) (map[string]controller.ToolFunc, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tools.json")
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	return socketexec.Load(path, map[string]string{"publisher": "unused", "Publisher": "unused"})
}

func executor(t *testing.T, text string) controller.ToolFunc {
	t.Helper()
	all, err := load(t, text)
	if err != nil {
		t.Fatal(err)
	}
	fn := all["publisher"]
	if fn == nil {
		t.Fatal("missing publisher executor")
	}
	return fn
}

func listener(t *testing.T) *net.UnixListener {
	t.Helper()
	// Keep well below the portable 103-byte socket path limit.
	dir, err := os.MkdirTemp("", "sockexec-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(dir, "s"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

func call() api.ToolCall {
	return api.ToolCall{ID: "call-1", Tool: "publish", Args: map[string]any{"text": "private-value", "n": float64(2)}, IdempotencyKey: "key-1"}
}

var scope = controller.ToolCallContext{SessionUID: "session-a"}

func noDial(t *testing.T, ln *net.UnixListener) {
	t.Helper()
	ln.SetDeadline(time.Now().Add(30 * time.Millisecond))
	conn, err := ln.Accept()
	if err == nil {
		conn.Close()
		t.Fatal("unexpected socket connection")
	}
	if e, ok := err.(net.Error); !ok || !e.Timeout() {
		t.Fatalf("accept: %v", err)
	}
	ln.SetDeadline(time.Time{})
}

func TestLoadEmptyAndExactHarnessRoutes(t *testing.T) {
	got, err := socketexec.Load("", nil)
	if err != nil || len(got) != 0 {
		t.Fatalf("empty config: %v %v", got, err)
	}
	for _, text := range []string{`{"version":1}`, `{"version":1,"executors":[],"tools":[]}`} {
		got, err = load(t, text)
		if err != nil || len(got) != 0 {
			t.Fatalf("empty routes: %v %v", got, err)
		}
	}
	ln := listener(t)
	all, err := load(t, config(ln.Addr().String(), `,"durable_dedup":true`, ""))
	if err != nil || len(all) != 1 || all["publisher"] == nil || all["Publisher"] != nil {
		t.Fatalf("route map: %v %v", all, err)
	}
	noDial(t, ln) // Load must not probe even a reachable executor.
}

func TestLoadBindingsExactDurableDeclarations(t *testing.T) {
	text := `{"version":1,"executors":[{"name":"pub","type":"unix","socket":"/tmp/publish.sock"}],"tools":[
		{"harness":"publisher","tool":"publish","executor":"pub","durable_dedup":true},
		{"harness":"publisher","tool":"false","executor":"pub","durable_dedup":false},
		{"harness":"publisher","tool":"omitted","executor":"pub"},
		{"harness":"publisher","tool":"null","executor":"pub","durable_dedup":null},
		{"harness":"Publisher","tool":"Publish","executor":"pub","durable_dedup":true}]}`
	path := filepath.Join(t.TempDir(), "tools.json")
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	harnesses := map[string]string{"publisher": "unused", "Publisher": "unused"}
	bindings, err := socketexec.LoadBindings(path, harnesses)
	if err != nil || len(bindings) != 2 {
		t.Fatalf("bindings=%v err=%v", bindings, err)
	}
	for _, tc := range []struct {
		harness, tool string
		want          bool
	}{
		{"publisher", "publish", true}, {"publisher", "Publish", false},
		{"publisher", "false", false}, {"publisher", "omitted", false},
		{"publisher", "null", false}, {"publisher", "unknown", false},
		{"Publisher", "Publish", true}, {"Publisher", "publish", false},
	} {
		if got := bindings[tc.harness].DurableDedup(tc.tool); got != tc.want {
			t.Errorf("%s/%s durable=%t want %t", tc.harness, tc.tool, got, tc.want)
		}
	}
	invalid := strings.Replace(text, `"tool":"false","executor":"pub"`, `"tool":"false","executor":"missing"`, 1)
	if err := os.WriteFile(path, []byte(invalid), 0600); err != nil {
		t.Fatal(err)
	}
	if bindings, err := socketexec.LoadBindings(path, harnesses); err == nil || len(bindings) != 0 {
		t.Fatalf("invalid later route leaked partial declarations: %v %v", bindings, err)
	}
}

func TestLoadRejectsMalformedAndMismatchedConfig(t *testing.T) {
	valid := config("/tmp/publish.sock", `,"durable_dedup":true`, "")
	cases := map[string]string{
		"missing-version": `{}`, "null-root": `null`, "array-root": `[]`,
		"wrong-version":    strings.Replace(valid, `"version":1`, `"version":2`, 1),
		"float-version":    strings.Replace(valid, `"version":1`, `"version":1.0`, 1),
		"string-version":   strings.Replace(valid, `"version":1`, `"version":"1"`, 1),
		"null-version":     strings.Replace(valid, `"version":1`, `"version":null`, 1),
		"duplicate":        strings.Replace(valid, `"version":1`, `"version":1,"version":1`, 1),
		"nested-duplicate": strings.Replace(valid, `"type":"unix"`, `"type":"unix","type":"unix"`, 1),
		"unknown":          strings.Replace(valid, `"version":1`, `"version":1,"secret":"private-value"`, 1),
		"case":             strings.Replace(valid, `"version"`, `"Version"`, 1),
		"nested-case":      strings.Replace(valid, `"socket"`, `"Socket"`, 1),
		"trailing":         valid + `{}`, "utf8": valid + string([]byte{0xff}),
		"null-executors": `{"version":1,"executors":null}`, "null-tools": `{"version":1,"tools":null}`,
		"null-executor":         `{"version":1,"executors":[null]}`,
		"missing-executor-name": strings.Replace(valid, `"name":"pub",`, ``, 1),
		"empty-tool":            strings.Replace(valid, `"tool":"publish"`, `"tool":""`, 1),
		"null-socket":           strings.Replace(valid, `"/tmp/publish.sock"`, `null`, 1),
		"relative-socket":       strings.Replace(valid, `/tmp/publish.sock`, `publish.sock`, 1),
		"nul-socket":            strings.Replace(valid, `/tmp/publish.sock`, `/tmp/a\u0000b`, 1),
		"long-socket":           strings.Replace(valid, `/tmp/publish.sock`, "/"+strings.Repeat("a", 103), 1),
		"wrong-type":            strings.Replace(valid, `"type":"unix"`, `"type":"http"`, 1),
		"unknown-executor":      strings.Replace(valid, `"executor":"pub"`, `"executor":"missing"`, 1),
		"unknown-harness":       strings.Replace(valid, `"harness":"publisher"`, `"harness":"other"`, 1),
		"wildcard-harness":      strings.Replace(valid, `"harness":"publisher"`, `"harness":"*"`, 1),
		"wildcard-tool":         strings.Replace(valid, `"tool":"publish"`, `"tool":"*"`, 1),
		"duplicate-route":       strings.Replace(valid, `"tools":[`, `"tools":[{"harness":"publisher","tool":"publish","executor":"pub"},`, 1),
		"duplicate-executor":    strings.Replace(valid, `"executors":[`, `"executors":[{"name":"pub","type":"unix","socket":"/tmp/another.sock"},`, 1),
		"wrong-dedup":           strings.Replace(valid, `"durable_dedup":true`, `"durable_dedup":"true"`, 1),
		"null-timeout":          config("/tmp/publish.sock", "", `,"timeout_ms":null`),
		"zero-timeout":          config("/tmp/publish.sock", "", `,"timeout_ms":0`),
		"large-timeout":         config("/tmp/publish.sock", "", `,"timeout_ms":300001`),
		"float-timeout":         config("/tmp/publish.sock", "", `,"timeout_ms":1.5`),
		"oversized":             valid + strings.Repeat(" ", maxFrame),
		"deep":                  `{"version":1,"unknown":` + strings.Repeat("[", 101) + `0` + strings.Repeat("]", 101) + `}`,
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := load(t, text)
			if err == nil || len(got) != 0 {
				t.Fatalf("accepted invalid configuration: map=%v err=%v", got, err)
			}
			if strings.Contains(err.Error(), "private-value") {
				t.Fatalf("config error leaked input: %v", err)
			}
		})
	}
}

func TestRefusalsNeverDial(t *testing.T) {
	ln := listener(t)
	for _, dedup := range []string{"", `,"durable_dedup":null`, `,"durable_dedup":false`} {
		fn := executor(t, config(ln.Addr().String(), dedup, ""))
		if _, err := fn(context.Background(), scope, call()); err == nil {
			t.Fatal("unsafe dedup declaration accepted")
		}
	}
	fn := executor(t, config(ln.Addr().String(), `,"durable_dedup":true`, ""))
	for _, tool := range []string{"Publish", "publish-more", "*", ""} {
		c := call()
		c.Tool = tool
		if _, err := fn(context.Background(), scope, c); err == nil {
			t.Fatalf("unconfigured tool %q accepted", tool)
		}
	}
	for _, mutate := range []func(*api.ToolCall){
		func(c *api.ToolCall) { c.ID = "" },
		func(c *api.ToolCall) { c.IdempotencyKey = "" },
		func(c *api.ToolCall) { c.Args = map[string]any{"text": strings.Repeat("x", maxFrame)} },
		func(c *api.ToolCall) { c.Args = map[string]any{"bad": make(chan int)} },
	} {
		c := call()
		mutate(&c)
		if _, err := fn(context.Background(), scope, c); err == nil {
			t.Fatal("invalid request accepted")
		}
	}
	if _, err := fn(context.Background(), controller.ToolCallContext{}, call()); err == nil {
		t.Fatal("empty session accepted")
	}
	noDial(t, ln)
}

func serveOnce(t *testing.T, ln *net.UnixListener, reply string, hold bool) (<-chan []byte, <-chan struct{}) {
	t.Helper()
	request := make(chan []byte, 1)
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		conn, err := ln.Accept()
		if err != nil {
			request <- nil
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		line, _ := bufio.NewReader(conn).ReadBytes('\n')
		request <- line
		io.WriteString(conn, reply)
		if hold {
			io.Copy(io.Discard, conn)
		}
	}()
	return request, closed
}

func TestRoundTripPreservesIdentityArgumentsAndPublicResult(t *testing.T) {
	for _, tc := range []struct {
		reply  string
		result api.ToolResult
	}{
		{`{"version":1,"call_id":"call-1","is_error":false,"output":{"text":"published","count":2}}` + "\n", api.ToolResult{Output: map[string]any{"text": "published", "count": float64(2)}}},
		{`{"version":1,"call_id":"call-1","is_error":true,"error":"not permitted"}` + "\n", api.ToolResult{IsError: true, Error: "not permitted"}},
		{`{"version":1,"call_id":"call-1","is_error":false,"output":null}` + "\n", api.ToolResult{}},
	} {
		ln := listener(t)
		fn := executor(t, config(ln.Addr().String(), `,"durable_dedup":true`, ""))
		request, _ := serveOnce(t, ln, tc.reply, true) // No EOF needed to return a result.
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		got, err := fn(ctx, scope, call())
		cancel()
		if err != nil || !reflect.DeepEqual(got, tc.result) {
			t.Fatalf("result=%+v err=%v want=%+v", got, err, tc.result)
		}
		var frame map[string]any
		if err := json.Unmarshal(<-request, &frame); err != nil {
			t.Fatal(err)
		}
		want := map[string]any{"version": float64(1), "harness": "publisher", "session_uid": "session-a", "call_id": "call-1", "tool": "publish", "arguments": map[string]any{"text": "private-value", "n": float64(2)}, "idempotency_key": "key-1"}
		if !reflect.DeepEqual(frame, want) {
			t.Fatalf("request=%v want=%v", frame, want)
		}
		noDial(t, ln)
	}
}

func TestRejectsBadResponsesWithoutRetryOrPayloadLeak(t *testing.T) {
	valid := `{"version":1,"call_id":"call-1","is_error":false,"output":{"text":"private-value"}}`
	cases := map[string]string{
		"truncated": valid, "empty": "", "oversized": valid + strings.Repeat(" ", maxFrame) + "\n",
		"duplicate":        strings.Replace(valid, `"version":1`, `"version":1,"version":1`, 1) + "\n",
		"nested-duplicate": strings.Replace(valid, `"text":"private-value"`, `"text":"private-value","text":"other"`, 1) + "\n",
		"version":          strings.Replace(valid, `"version":1`, `"version":2`, 1) + "\n",
		"correlation":      strings.Replace(valid, `"call-1"`, `"another-call"`, 1) + "\n",
		"unknown":          strings.Replace(valid, `"version":1`, `"version":1,"uri":"private-value"`, 1) + "\n",
		"case":             strings.Replace(valid, `"is_error"`, `"Is_Error"`, 1) + "\n",
		"missing-status":   strings.Replace(valid, `"is_error":false,`, "", 1) + "\n",
		"null-status":      strings.Replace(valid, `"is_error":false`, `"is_error":null`, 1) + "\n",
		"wrong-status":     strings.Replace(valid, `"is_error":false`, `"is_error":"false"`, 1) + "\n",
		"null-version":     strings.Replace(valid, `"version":1`, `"version":null`, 1) + "\n",
		"null-call-id":     strings.Replace(valid, `"call_id":"call-1"`, `"call_id":null`, 1) + "\n",
		"null-error":       strings.TrimSuffix(valid, "}") + `,"error":null}` + "\n",
		"wrong-output":     strings.Replace(valid, `{"text":"private-value"}`, `[]`, 1) + "\n",
		"utf8":             strings.Replace(valid, "private-value", string([]byte{0xff}), 1) + "\n",
		"trailing":         valid + `{}` + "\n",
		"deep":             strings.Replace(valid, `"private-value"`, strings.Repeat("[", 101)+`0`+strings.Repeat("]", 101), 1) + "\n",
	}
	for name, reply := range cases {
		t.Run(name, func(t *testing.T) {
			ln := listener(t)
			fn := executor(t, config(ln.Addr().String(), `,"durable_dedup":true`, ""))
			request, _ := serveOnce(t, ln, reply, false)
			_, err := fn(context.Background(), scope, call())
			if err == nil {
				t.Fatal("bad response accepted")
			}
			if strings.Contains(err.Error(), "private-value") || !strings.Contains(err.Error(), "publisher") || !strings.Contains(err.Error(), "publish") {
				t.Fatalf("unsafe or unhelpful error: %v", err)
			}
			if len(<-request) == 0 {
				t.Fatal("no request sent")
			}
			noDial(t, ln)
		})
	}
}

func TestCancellationAndConfiguredTimeoutCloseBlockedRead(t *testing.T) {
	for _, cancelCall := range []bool{true, false} {
		t.Run(fmt.Sprint(cancelCall), func(t *testing.T) {
			ln := listener(t)
			fn := executor(t, config(ln.Addr().String(), `,"durable_dedup":true`, `,"timeout_ms":100`))
			request, closed := serveOnce(t, ln, "", true)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := fn(ctx, scope, call()); done <- err }()
			select {
			case <-request:
			case <-time.After(time.Second):
				t.Fatal("request not received")
			}
			if cancelCall {
				cancel()
			}
			select {
			case err := <-done:
				want := context.DeadlineExceeded
				if cancelCall {
					want = context.Canceled
				}
				if !errors.Is(err, want) {
					t.Fatalf("error=%v want=%v", err, want)
				}
			case <-time.After(time.Second):
				t.Fatal("blocked read not interrupted")
			}
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("cancellation did not close the connection")
			}
			noDial(t, ln)
		})
	}
}
