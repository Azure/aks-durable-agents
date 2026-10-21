package targetversions

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestVerificationFencesQueuedWriterBeforeConnectionRelease(t *testing.T) {
	s, _ := newStore(t)
	register(t, s, "agent")
	if _, err := s.db.Exec("UPDATE targets SET data=json_set(data,'$.Availability','ready')"); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	verifyDone := make(chan error, 1)
	go func() {
		verifyDone <- s.transaction(ctx, true, func(q query) error {
			err := s.verify(ctx, q)
			close(entered)
			<-release
			return err
		})
	}()
	<-entered
	before := s.db.Stats().WaitCount
	writerDone := make(chan error, 1)
	go func() { _, err := s.RegisterTarget(ctx, "must-not-exist"); writerDone <- err }()
	deadline := time.After(5 * time.Second)
	for s.db.Stats().WaitCount == before {
		select {
		case <-deadline:
			close(release)
			t.Fatal("writer did not queue for held connection")
		default:
			runtime.Gosched()
		}
	}
	close(release)
	if err := <-verifyDone; !errors.Is(err, ErrIntegrity) {
		t.Fatalf("verification: %v", err)
	}
	if err := <-writerDone; !errors.Is(err, ErrIntegrity) {
		t.Fatalf("queued mutation escaped corruption latch: %v", err)
	}
	if _, err := s.ReadTarget(ctx, "must-not-exist"); !errors.Is(err, ErrConflict) {
		t.Fatalf("queued writer published: %v", err)
	}
}

func TestVerificationCancellationDoesNotLatch(t *testing.T) {
	s, _ := newStore(t)
	c, cancel := context.WithCancel(ctx)
	cancel()
	if err := s.Verify(c); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if s.bad.Load() {
		t.Fatal("cancellation latched corruption")
	}
	if _, err := s.RegisterTarget(ctx, "after-cancellation"); err != nil {
		t.Fatal(err)
	}
}

func TestPathOwnershipUsesActualLstatUID(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "sidecar")
	if err := os.WriteFile(file, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{dir, file} {
		if err := ownedBy(p, uint32(os.Getuid())); err != nil {
			t.Fatalf("own path: %v", err)
		}
		if err := ownedBy(p, uint32(os.Getuid())+1); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("foreign owner accepted: %v", err)
		}
	}
	if err := ownedBy(filepath.Join(dir, "missing"), uint32(os.Getuid())); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("stat failure accepted: %v", err)
	}
}
