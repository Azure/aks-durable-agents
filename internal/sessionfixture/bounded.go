package sessionfixture

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/agent-primitives/sessions/api"
)

const draftA = "Northwind release notes\n\nProposal A: open the fictional local preview to three reviewers.\nNothing is sent outside this machine.\n"
const draftB = "Northwind release notes\n\nProposal B: invite five fictional reviewers to the local preview.\nNothing is sent outside this machine.\n"
const maxFrame = 1 << 20

type executorRequest struct {
	Version    int            `json:"version"`
	Harness    string         `json:"harness"`
	SessionUID string         `json:"session_uid"`
	CallID     string         `json:"call_id"`
	Tool       string         `json:"tool"`
	Arguments  map[string]any `json:"arguments"`
	Key        string         `json:"idempotency_key"`
}
type executorResponse struct {
	Version int            `json:"version"`
	CallID  string         `json:"call_id"`
	IsError bool           `json:"is_error"`
	Output  map[string]any `json:"output,omitempty"`
	Error   string         `json:"error,omitempty"`
}

// encoding/json accepts duplicate members and case-folds struct field names.
// Validate the token tree first, then apply an exact top-level field allowlist.
func strictJSON(raw []byte, keys []string, dst any) error {
	if !utf8.Valid(raw) {
		return errors.New("invalid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 100 {
			return errors.New("JSON nesting exceeds limit")
		}
		t, err := dec.Token()
		if err != nil {
			return err
		}
		d, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch d {
		case '{':
			seen := map[string]bool{}
			for dec.More() {
				k, err := dec.Token()
				if err != nil {
					return err
				}
				s, ok := k.(string)
				if !ok || seen[s] {
					return errors.New("duplicate JSON member")
				}
				seen[s] = true
				if err = value(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for dec.More() {
				if err = value(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
		_, err = dec.Token()
		return err
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return errors.New("JSON object required")
	}
	allowed := map[string]bool{}
	for _, k := range keys {
		allowed[k] = true
	}
	for k := range obj {
		if !allowed[k] {
			return errors.New("unknown JSON member")
		}
	}
	return json.Unmarshal(raw, dst)
}
func decodeExecutorRequest(raw []byte) (executorRequest, error) {
	return decodeExecutorRequestScenario(raw, "v1")
}
func decodeExecutorRequestScenario(raw []byte, scenario string) (req executorRequest, err error) {
	err = strictJSON(raw, []string{"version", "harness", "session_uid", "call_id", "tool", "arguments", "idempotency_key"}, &req)
	if err != nil {
		return req, err
	}
	harness := "release-notes"
	if scenario == bridgeScenario {
		harness = bridgeHarnessID
	}
	if req.Version != 1 || req.Harness != harness {
		return req, errors.New("unsupported version or route")
	}
	c := api.ToolCall{ID: req.CallID, Tool: req.Tool, Args: req.Arguments, IdempotencyKey: req.Key, Mediation: api.MediationRequiresApproval}
	return req, validateToolScenario(toolScope(req.SessionUID), c, scenario)
}
func listenPrivateSocket(path string) (net.Listener, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 103 {
		return nil, errors.New("absolute bounded socket path required")
	}
	if err := privateParent(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("socket path already exists; verify stopped owner before operator removal")
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	listener.SetUnlinkOnClose(false)
	if err = os.Chmod(path, 0600); err != nil {
		listener.Close()
		return nil, err
	}
	return listener, nil
}
func serveExecutor(ctx context.Context, l net.Listener, e *executor) error {
	var wg sync.WaitGroup
	slots := make(chan struct{}, 16)
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			l.Close()
		case <-done:
		}
	}()
	defer wg.Wait()
	for {
		conn, err := l.Accept()
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
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			serveExecutorConn(ctx, conn, e)
		})
	}
}
func serveExecutorConn(ctx context.Context, conn net.Conn, e *executor) {
	reader := bufio.NewReader(io.LimitReader(conn, maxFrame+1))
	raw, err := reader.ReadBytes('\n')
	if err != nil || len(raw) > maxFrame || reader.Buffered() != 0 {
		return
	}
	req, err := decodeExecutorRequestScenario(raw, e.scenario)
	if err != nil {
		return
	}
	result, err := e.execute(ctx, toolScope(req.SessionUID), api.ToolCall{ID: req.CallID, Tool: req.Tool, Args: req.Arguments, IdempotencyKey: req.Key, Mediation: api.MediationRequiresApproval})
	response := executorResponse{Version: 1, CallID: req.CallID, IsError: err != nil, Output: result.Output}
	if err != nil {
		response.Error = "fictional publication refused; reconcile durable state before retry"
	}
	json.NewEncoder(conn).Encode(response)
}
