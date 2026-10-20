package sessionfixture

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// Reusing a tuple with another correlation ID must redrive its one durable receipt.
func TestExecutorCorrelatedRedriveAndAtomicCrash(t *testing.T) {
	ex, err := newExecutor(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer ex.close()
	c := publication()
	first, err := ex.execute(t.Context(), toolScope("s"), c)
	if err != nil {
		t.Fatal(err)
	}
	c.ID = "redrive-call"
	again, err := ex.execute(t.Context(), toolScope("s"), c)
	if err != nil || again.ID != "redrive-call" || again.Output["artifact"] != first.Output["artifact"] {
		t.Fatalf("correlated dedup: %#v %v", again, err)
	}
	p, r, err := ex.counts()
	if err != nil || p != 1 || r != 1 {
		t.Fatalf("not atomic: %d %d %v", p, r, err)
	}
	c.IdempotencyKey = "crash-key"
	c.ID = "crash-call"
	ex.afterCommit = func() error { return errors.New("crash after commit") }
	if _, err = ex.execute(t.Context(), toolScope("s"), c); err == nil {
		t.Fatal("crash hook did not interrupt reply")
	}
	ex.afterCommit = nil
	if _, err = ex.execute(t.Context(), toolScope("s"), c); err != nil {
		t.Fatal(err)
	}
	p, r, err = ex.counts()
	if err != nil || p != 2 || r != 2 {
		t.Fatalf("crash duplicate: %d %d %v", p, r, err)
	}
}

// Strict parsing must reject duplicate/unknown/miscased keys and unapproved routes before effects.
func TestExecutorProtocolStrictFrames(t *testing.T) {
	ex, err := newExecutor(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer ex.close()
	req := executorRequest{Version: 1, Harness: "release-notes", SessionUID: "s", CallID: "c", Tool: "publish_release_notes", Arguments: publication().Args, Key: "k"}
	raw, _ := json.Marshal(req)
	valid := string(raw)
	for _, line := range []string{
		valid[:len(valid)-1] + ",\"version\":1}",
		valid[:len(valid)-1] + ",\"unknown\":1}",
		"{\"Version\":1}",
		valid + " {}",
	} {
		if _, err := decodeExecutorRequest([]byte(line)); err == nil {
			t.Fatalf("unsafe frame accepted: %s", line)
		}
	}
	socket := filepath.Join(privateTempDir(t), "publish.sock")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	listener, err := listenPrivateSocket(socket)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- serveExecutor(ctx, listener, ex) }()
	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	conn.Write(append(raw, '\n'))
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	conn.Close()
	if err != nil {
		t.Fatal(err)
	}
	var resp executorResponse
	if err = json.Unmarshal(line, &resp); err != nil || resp.IsError || resp.CallID != "c" || resp.Output["simulated"] != true {
		t.Fatalf("%s %v", line, err)
	}
	cancel()
	<-done
	info, err := os.Stat(socket)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("socket mode %v %v", info, err)
	}
	if _, err = listenPrivateSocket(socket); err == nil {
		t.Fatal("unsafe stale socket replacement")
	}
}

func TestExecutorRejectsUnfrozenDraft(t *testing.T) {
	ex, err := newExecutor(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer ex.close()
	c := publication()
	c.Args["draft"] = "unfrozen"
	if _, err = ex.execute(t.Context(), toolScope("s"), c); err == nil {
		t.Fatal("unfrozen draft published")
	}
}
