package decisionledger

import (
	"context"
	"database/sql"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/aks-durable-agents/entraauth"
)

// A cached response remains protected even after its decision has committed.
func TestCachedRetryExpiryDuringLookup(t *testing.T) {
	s, svc, _, r := serviceFixture(t)
	base := time.Date(2029, 1, 1, 0, 0, 0, 0, time.UTC)
	var clock atomic.Int64
	clock.Store(base.Unix())
	s.now = func() time.Time { return time.Unix(clock.Load(), 0) }
	until := base.Add(time.Second)
	ctx := humanContext("alice", until)
	original, err := svc.Decide(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	var held *sql.Conn
	reads := 0
	svc.policy = callbackPolicy{read: func() error {
		reads++
		if reads == 1 {
			var err error
			held, err = s.db.Conn(context.Background())
			if err == nil {
				t.Cleanup(func() { held.Close() })
			}
			return err
		}
		return nil
	}, decide: func(entraauth.VerifiedHuman, Subject, Action, func(Authorization) error) error {
		t.Error("exact retry reached write policy")
		return ErrUnavailable
	}}
	waits := s.db.Stats().WaitCount
	type response struct {
		record DecisionRecord
		err    error
	}
	done := make(chan response, 1)
	go func() { record, err := svc.Decide(ctx, r); done <- response{record, err} }()
	waitForReviewCondition(t, func() bool {
		select {
		case out := <-done:
			t.Fatalf("retry did not wait: %v", out.err)
		default:
		}
		return s.db.Stats().WaitCount > waits
	})
	if held == nil {
		t.Fatal("no held connection")
	}
	clock.Store(until.Unix())
	held.Close()
	out := <-done
	if !errors.Is(out.err, ErrUnauthenticated) || out.record.ID != "" {
		t.Fatalf("expired retry disclosed cached record: id=%q original=%q reads=%d err=%v", out.record.ID, original.ID, reads, out.err)
	}
}
