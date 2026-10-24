package qualification

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"modernc.org/sqlite"
)

// Cancel at a selected SQL boundary while keeping the actual SQLite execution,
// commit, and rollback behavior. All hook state belongs to one test context.
type completionCancelKey struct{}
type completionCancelHook struct {
	query  string
	seen   int
	cancel context.CancelFunc
}
type completionCancelDriver struct{}
type completionCancelConn struct{ driver.Conn }

func (completionCancelDriver) Open(name string) (driver.Conn, error) {
	c, err := (&sqlite.Driver{}).Open(name)
	if err != nil {
		return nil, err
	}
	return completionCancelConn{c}, nil
}
func (c completionCancelConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if hook, ok := ctx.Value(completionCancelKey{}).(*completionCancelHook); ok && strings.HasPrefix(query, hook.query) {
		hook.seen++
		if hook.seen == 2 {
			hook.cancel()
		}
	}
	return c.Conn.(driver.ExecerContext).ExecContext(ctx, query, args)
}
func (c completionCancelConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, query, args)
}

var registerCompletionCancelDriver sync.Once

func cancelCompletion(t *testing.T, s *Store, l lease, obs []Observation, query string) Record {
	t.Helper()
	if err := s.db.Close(); err != nil {
		t.Fatal(err)
	}
	registerCompletionCancelDriver.Do(func() { sql.Register("qualification-completion-cancel", completionCancelDriver{}) })
	db, err := sql.Open("qualification-completion-cancel", dbURI(filepath.Join(s.dir, "records.db"), false))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	s.db = db
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx = context.WithValue(ctx, completionCancelKey{}, &completionCancelHook{query: query, cancel: cancel})
	if _, err = s.complete(ctx, l, obs); !errors.Is(err, context.Canceled) {
		t.Fatalf("completion cancellation at %q: %v", query, err)
	}
	r, err := s.Read(context.Background(), l.ID)
	if err != nil || r.State != Verifying || r.Generation != l.Generation || !r.CompletedAt.IsZero() || objectDigest("observations-v1", r.Observations) != objectDigest("observations-v1", obs) {
		t.Fatalf("verifying intent not retained after cancellation: %+v %v", r, err)
	}
	return r
}

func TestCompletionResumesVerifyingAfterCancellation(t *testing.T) {
	for _, query := range []string{"BEGIN IMMEDIATE", "UPDATE records SET body=", "COMMIT"} {
		for _, reopen := range []bool{false, true} {
			name := query
			if reopen {
				name += "/reopen"
			}
			t.Run(name, func(t *testing.T) {
				s, dir := testStore(t)
				p := testPlan()
				l := begin(t, s, p)
				obs := []Observation{observation(t, s, "candidate", "hello")}
				intent := cancelCompletion(t, s, l, obs, query)
				if reopen {
					lineage := s.Lineage()
					if err := s.Close(); err != nil {
						t.Fatal(err)
					}
					var err error
					s, err = Open(dir, lineage)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = s.Close() })
					got, err := s.Read(context.Background(), l.ID)
					if err != nil || got.State != Verifying || got.Digest != intent.Digest {
						t.Fatalf("Open advanced or changed verifying intent: %+v %v", got, err)
					}
				}
				done, err := s.complete(context.Background(), l, obs)
				if err != nil || done.State != Passed || done.Generation != l.Generation || done.CompletedAt.IsZero() {
					t.Fatalf("identical retry did not resume: %+v %v", done, err)
				}
				if _, err = s.VerifyForActivation(context.Background(), l.ID, p, time.Now()); err != nil {
					t.Fatalf("resumed evidence not verifiable: %v", err)
				}
				again, err := s.complete(context.Background(), l, obs)
				if err != nil || again.Digest != done.Digest || !again.CompletedAt.Equal(done.CompletedAt) {
					t.Fatalf("terminal retry not idempotent: %+v %v", again, err)
				}
			})
		}
	}
}

func TestCompletionVerifyingRetryRejectsChangedEvidence(t *testing.T) {
	s, _ := testStore(t)
	l := begin(t, s, testPlan())
	obs := []Observation{observation(t, s, "candidate", "hello")}
	intent := cancelCompletion(t, s, l, obs, "BEGIN IMMEDIATE")
	changed := []Observation{observation(t, s, "replacement", "hello again")}
	if _, err := s.complete(context.Background(), l, changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed verifying evidence accepted: %v", err)
	}
	retained, err := s.Read(context.Background(), l.ID)
	if err != nil || retained.Digest != intent.Digest {
		t.Fatalf("conflicting retry changed retained intent: %+v %v", retained, err)
	}
	if done, err := s.complete(context.Background(), l, obs); err != nil || done.State != Passed {
		t.Fatalf("conflict poisoned identical retry: %s %v", done.State, err)
	}
}

func TestCompletionVerifyingRetryReevaluatesEvidenceAndExpiry(t *testing.T) {
	for _, name := range []string{"corrupted-evidence", "expired-plan"} {
		t.Run(name, func(t *testing.T) {
			s, dir := testStore(t)
			p := testPlan()
			l := begin(t, s, p)
			obs := []Observation{observation(t, s, "candidate", "hello")}
			intent := cancelCompletion(t, s, l, obs, "BEGIN IMMEDIATE")
			if name == "corrupted-evidence" {
				path := filepath.Join(dir, "evidence", obs[0].Candidate.Blob.Digest[7:])
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				data = bytes.Replace(data, []byte("hello"), []byte("jello"), 1)
				if err = os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				// Simulate expiry without a timing race or a sleep.
				intent.Request.Plan.ExpiresAt = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
				intent.RequestDigest = objectDigest("qualification-request-v1", intent.Request)
				intent.PlanDigest = objectDigest("qualification-plan-v1", intent.Request.Plan)
				if err := s.save(context.Background(), intent, false); err != nil {
					t.Fatal(err)
				}
			}
			done, err := s.complete(context.Background(), l, obs)
			if err != nil || done.State != Incomplete || done.Reason != "evidence" {
				t.Fatalf("retry reused previous evaluation: %+v %v", done, err)
			}
			if _, err = s.VerifyForActivation(context.Background(), l.ID, p, time.Now()); !errors.Is(err, ErrIneligible) {
				t.Fatalf("incomplete retry eligible: %v", err)
			}
		})
	}
}

func TestCompletionVerifyingRetryIsFencedByInterrupt(t *testing.T) {
	s, _ := testStore(t)
	l := begin(t, s, testPlan())
	obs := []Observation{observation(t, s, "candidate", "hello")}
	cancelCompletion(t, s, l, obs, "BEGIN IMMEDIATE")
	stopped, err := s.interrupt(context.Background(), l)
	if err != nil || stopped.State != Incomplete || stopped.Generation != l.Generation+1 {
		t.Fatalf("interrupt verifying: %+v %v", stopped, err)
	}
	if _, err = s.complete(context.Background(), l, obs); !errors.Is(err, ErrConflict) {
		t.Fatalf("fenced verifying retry accepted: %v", err)
	}
	got, err := s.Read(context.Background(), l.ID)
	if err != nil || got.Digest != stopped.Digest {
		t.Fatalf("fenced retry changed terminal record: %+v %v", got, err)
	}
}

func TestInterruptRejectsStaleLease(t *testing.T) {
	for _, state := range []State{Running, Verifying} {
		t.Run(string(state), func(t *testing.T) {
			s, _ := testStore(t)
			l := begin(t, s, testPlan())
			r, err := s.Read(context.Background(), l.ID)
			if err != nil {
				t.Fatal(err)
			}
			r.State = state
			r.Generation++
			if state == Verifying {
				r.Observations = []Observation{observation(t, s, "candidate", "hello")}
			}
			if err = s.save(context.Background(), r, false); err != nil {
				t.Fatal(err)
			}
			before, err := s.Read(context.Background(), l.ID)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.interrupt(context.Background(), l); !errors.Is(err, ErrConflict) {
				t.Fatalf("stale lease interrupted current generation: %v", err)
			}
			if _, err = s.complete(context.Background(), l, before.Observations); !errors.Is(err, ErrConflict) {
				t.Fatalf("stale completion accepted: %v", err)
			}
			got, err := s.Read(context.Background(), l.ID)
			if err != nil || got.Digest != before.Digest {
				t.Fatalf("stale lease changed current record: %+v %v", got, err)
			}
			if _, err = s.interrupt(context.Background(), lease{l.ID, before.Generation}); err != nil {
				t.Fatalf("current lease could not interrupt: %v", err)
			}
		})
	}
}
