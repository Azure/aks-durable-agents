package decisionledger

import (
	"context"
	"database/sql"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/aks-durable-agents/entraauth"
)

// An exact retry must not disclose its retained record using authorization
// checked before a connection wait. Removing the final read check breaks this.
func TestExactRetryRechecksAccessAfterLookupWait(t *testing.T) {
	for _, reason := range []string{"expired", "revoked"} {
		t.Run(reason, func(t *testing.T) {
			store, service, _, request := serviceFixture(t)
			var now atomic.Int64
			now.Store(time.Date(2029, 1, 1, 0, 0, 0, 0, time.UTC).Unix())
			store.now = func() time.Time { return time.Unix(now.Load(), 0) }
			original, err := service.Decide(humanContext("alice", store.now().Add(time.Hour)), request)
			if err != nil {
				t.Fatal(err)
			}
			var revoked atomic.Bool
			entered := make(chan struct{})
			var held *sql.Conn
			waits := store.db.Stats().WaitCount
			service.policy = callbackPolicy{read: func() error {
				if revoked.Load() {
					return ErrDenied
				}
				if held == nil {
					var err error
					held, err = store.db.Conn(context.Background())
					if err != nil {
						return err
					}
					close(entered)
				}
				return nil
			}}
			ctx := humanContext("alice", store.now().Add(time.Second))
			type result struct {
				record DecisionRecord
				err    error
			}
			done := make(chan result, 1)
			go func() { record, err := service.Decide(ctx, request); done <- result{record, err} }()
			<-entered
			defer held.Close()
			waitForReviewCondition(t, func() bool { return store.db.Stats().WaitCount > waits })
			want := ErrDenied
			if reason == "expired" {
				now.Add(2)
				want = ErrUnauthenticated
			} else {
				revoked.Store(true)
			}
			held.Close()
			out := <-done
			if !errors.Is(out.err, want) || out.record.ID != "" {
				t.Fatalf("retry disclosed a private record after %s: id=%q err=%v", reason, out.record.ID, out.err)
			}
			actor := ctx.Value(humanKey{}).(entraauth.VerifiedHuman).Caller.Identity
			retained, err := store.lookup(context.Background(), actor, request.Workspace, request.Key)
			if err != nil || retained.ID != original.ID {
				t.Fatalf("retry changed durable outcome: %v", err)
			}
		})
	}
}

// Close must drain even db.Conn borrowers and queued reads before unlocking.
// Releasing the file lock immediately after sql.DB.Close breaks this test.
func TestStoreCloseKeepsLockUntilOperationsDrain(t *testing.T) {
	for _, operation := range []string{"transaction", "lookup", "subject"} {
		t.Run(operation, func(t *testing.T) {
			store, service, _, request := serviceFixture(t)
			ctx := humanContext("alice", time.Now().Add(time.Hour))
			original, err := service.Decide(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			actor := ctx.Value(humanKey{}).(entraauth.VerifiedHuman).Caller.Identity
			release := make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			defer unblock()
			entered := make(chan struct{})
			done := make(chan error, 1)
			waits := store.db.Stats().WaitCount
			var held *sql.Conn
			if operation != "transaction" {
				held, err = store.db.Conn(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				defer held.Close()
			}
			go func() {
				switch operation {
				case "transaction":
					done <- store.transaction(context.Background(), func(c *sql.Conn) error {
						close(entered)
						<-release
						_, err := c.ExecContext(context.Background(), "UPDATE metadata SET schema_version=schema_version WHERE id=1")
						return err
					})
				case "lookup":
					record, err := store.lookup(context.Background(), actor, request.Workspace, request.Key)
					if err == nil && record.ID != original.ID {
						err = ErrConflict
					}
					done <- err
				case "subject":
					_, _, err := store.subject(context.Background(), request.Subject)
					done <- err
				}
			}()
			if operation == "transaction" {
				<-entered
			} else {
				waitForReviewCondition(t, func() bool { return store.db.Stats().WaitCount > waits })
			}
			closed := make(chan error, 1)
			go func() { closed <- store.Close() }()
			waitForReviewCondition(t, func() bool {
				store.lifecycle.Lock()
				closing := store.closing
				store.lifecycle.Unlock()
				select {
				case err := <-closed:
					t.Fatalf("Close returned while %s was in flight: %v", operation, err)
				default:
				}
				return closing
			})
			if other, err := Open(store.path, store.ID(), "host-lineage"); !errors.Is(err, ErrUnavailable) {
				if other != nil {
					other.Close()
				}
				t.Fatalf("lifetime lock released before %s drained: %v", operation, err)
			}
			if err := store.transaction(context.Background(), func(*sql.Conn) error { return nil }); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("new operation admitted during Close: %v", err)
			}
			if _, _, err := store.subject(context.Background(), request.Subject); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("new subject read admitted during Close: %v", err)
			}
			if _, err := store.lookup(context.Background(), actor, request.Workspace, request.Key); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("new record read admitted during Close: %v", err)
			}
			if held != nil {
				held.Close()
			}
			unblock()
			if err := <-done; err != nil {
				t.Fatalf("admitted %s failed while draining: %v", operation, err)
			}
			if err := <-closed; err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatalf("repeated Close: %v", err)
			}
			reopened, err := Open(store.path, store.ID(), "host-lineage")
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			record, err := reopened.lookup(context.Background(), actor, request.Workspace, request.Key)
			if err != nil || record.ID != original.ID {
				t.Fatalf("draining changed durable outcome: %v", err)
			}
		})
	}
}

func waitForReviewCondition(t *testing.T, ready func() bool) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for !ready() {
		select {
		case <-deadline.C:
			t.Fatal("concurrency barrier not reached")
		default:
			runtime.Gosched()
		}
	}
}
