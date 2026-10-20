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
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The helper is reachable only inside the Go test binary; no production fault
// environment variable or RPC is exposed to the browser or fixture CLI.
func TestExecutorOwnedProcessHelper(t *testing.T) {
	if os.Getenv("REFERENCE_TEST_EXECUTOR_CHILD") != "yes" {
		return
	}
	ex, err := openExecutor(os.Getenv("REFERENCE_TEST_DATABASE"))
	if err != nil {
		os.Exit(91)
	}
	defer ex.close()
	if os.Getenv("REFERENCE_TEST_CRASH") == "yes" {
		ex.afterCommit = func() error { os.Exit(86); return nil }
	}
	l, err := listenPrivateSocket(os.Getenv("REFERENCE_TEST_SOCKET"))
	if err != nil {
		os.Exit(92)
	}
	defer l.Close()
	json.NewEncoder(os.Stdout).Encode(map[string]string{"socket": l.Addr().String()})
	if err = serveExecutor(context.Background(), l, ex); err != nil {
		os.Exit(93)
	}
}
func startExecutorChild(t *testing.T, database, socket string, crash bool) *exec.Cmd {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(executable, "-test.run=^TestExecutorOwnedProcessHelper$")
	child.Env = []string{"REFERENCE_TEST_EXECUTOR_CHILD=yes", "REFERENCE_TEST_DATABASE=" + database, "REFERENCE_TEST_SOCKET=" + socket}
	if crash {
		child.Env = append(child.Env, "REFERENCE_TEST_CRASH=yes")
	}
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	child.Stderr = &stderr
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if child.ProcessState == nil {
			child.Process.Kill()
			child.Wait()
		}
	})
	ready := make(chan error, 1)
	go func() {
		var value struct{ Socket string }
		err := json.NewDecoder(stdout).Decode(&value)
		if err == nil && value.Socket != socket {
			err = errors.New("child socket readiness mismatch")
		}
		ready <- err
	}()
	select {
	case err = <-ready:
		if err != nil {
			// Join the stderr-copy goroutine before reading its buffer.
			_ = child.Process.Kill()
			_ = child.Wait()
			t.Fatalf("executor child readiness: %v %s", err, stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("executor child readiness timeout")
	}
	return child
}
func socketInvoke(t *testing.T, socket string, req executorRequest) (executorResponse, error) {
	t.Helper()
	c, err := net.DialTimeout("unix", socket, time.Second)
	if err != nil {
		return executorResponse{}, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if err = json.NewEncoder(c).Encode(req); err != nil {
		return executorResponse{}, err
	}
	raw, err := bufio.NewReader(c).ReadBytes('\n')
	if err != nil {
		return executorResponse{}, err
	}
	var result executorResponse
	err = json.Unmarshal(raw, &result)
	return result, err
}

// A real subprocess exits after COMMIT and before reply. The recorded stopped
// owner is then replaced against the same database; same tuple/new call ID must
// return the stored receipt and exactly one publication, not perform a new effect.
func TestExecutorProcessCrashAfterCommitRedrive(t *testing.T) {
	dir := privateTempDir(t)
	database := filepath.Join(dir, "publications.db")
	socket := filepath.Join(dir, "publish.sock")
	crashed := startExecutorChild(t, database, socket, true)
	req := executorRequest{Version: 1, Harness: "release-notes", SessionUID: "session-after-crash", CallID: "original-call", Tool: "publish_release_notes", Arguments: publication().Args, Key: "original-key"}
	if _, err := socketInvoke(t, socket, req); err == nil || !errors.Is(err, io.EOF) {
		t.Fatalf("expected lost reply from process crash: %v", err)
	}
	err := crashed.Wait()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 86 {
		t.Fatalf("wrong crash boundary: %v", err)
	}
	before, err := readEvidence(dir)
	if err != nil || before.PublicationCount != 1 || before.ReceiptCount != 1 {
		t.Fatalf("durable crash inventory: %#v %v", before, err)
	}
	// Test operator removal is allowed only after Wait proved this exact child is
	// stopped, and only its private socket, never an arbitrary preexisting endpoint.
	info, err := os.Lstat(socket)
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("owned stale socket: %v %v", info, err)
	}
	if err = os.Remove(socket); err != nil {
		t.Fatal(err)
	}
	restarted := startExecutorChild(t, database, socket, false)
	req.CallID = "current-redrive-call"
	result, err := socketInvoke(t, socket, req)
	if err != nil || result.IsError || result.CallID != "current-redrive-call" || result.Output["artifact"] != before.Artifacts[0].Name {
		t.Fatalf("redrive receipt: %#v %v", result, err)
	}
	after, err := readEvidence(dir)
	if err != nil || !bytes.Equal(mustJSON(t, before), mustJSON(t, after)) {
		t.Fatalf("redrive duplicated publication: %#v %v", after, err)
	}
	req.Arguments = map[string]any{"draft": draftB, "destination": "release-notes-demo"}
	conflict, err := socketInvoke(t, socket, req)
	if err != nil || !conflict.IsError || !strings.Contains(conflict.Error, "reconcile") {
		t.Fatalf("changed tuple accepted: %#v %v", conflict, err)
	}
	restarted.Process.Kill()
	restarted.Wait()
}
