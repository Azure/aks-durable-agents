//go:build squadproof

package squadproof

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestProofServingRolesRequireOptIn(t *testing.T) {
	for _, args := range [][]string{nil, {"unknown"}, {"host"}, {"harness", "--role=lead"}, {"executor"}, {"harness", "--proof-only", "--role=other"}, {"harness", "--proof-only", "--role=lead", "--addr=0.0.0.0:9000"}, {"executor", "--proof-only", "--data=relative"}} {
		if err := RunCLI(t.Context(), args, &bytes.Buffer{}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("unsafe role accepted: %v: %v", args, err)
		}
	}
}

func TestProofExecutorLifecycle(t *testing.T) {
	_, path := openTestLedger(t)
	data := filepath.Dir(path)
	ctx, cancel := context.WithCancel(t.Context())
	var output bytes.Buffer
	// Readiness is a synchronous writer callback, not a sleep or a port probe.
	ready := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		done <- RunCLI(ctx, []string{"executor", "--proof-only", "--data=" + data}, readyWriter{&output, ready})
	}()
	select {
	case <-ready:
	case err := <-done:
		cancel()
		t.Fatalf("executor failed before readiness: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(data, "tools.sock")); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(data, "tools.sock")); !os.IsNotExist(err) {
		t.Fatalf("socket not cleaned: %v", err)
	}
}

func TestProofExecutorRefusesExistingSocketPath(t *testing.T) {
	_, path := openTestLedger(t)
	data := filepath.Dir(path)
	socket := filepath.Join(data, "tools.sock")
	before := []byte("retain stopped-owner evidence")
	if err := os.WriteFile(socket, before, 0600); err != nil {
		t.Fatal(err)
	}
	err := RunCLI(t.Context(), []string{"executor", "--proof-only", "--data=" + data}, &bytes.Buffer{})
	if !errors.Is(err, ErrHeld) {
		t.Fatalf("existing path not held: %v", err)
	}
	after, err := os.ReadFile(socket)
	if err != nil || string(after) != string(before) {
		t.Fatalf("existing socket path replaced: %q %v", after, err)
	}
}

type readyWriter struct {
	buffer *bytes.Buffer
	ready  chan struct{}
}

func (w readyWriter) Write(p []byte) (int, error) {
	n, err := w.buffer.Write(p)
	select {
	case w.ready <- struct{}{}:
	default:
	}
	return n, err
}
