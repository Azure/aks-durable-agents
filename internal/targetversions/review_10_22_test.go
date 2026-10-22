package targetversions

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Omitting UTF-8/control/byte-length checks accepts invalid copied actors; invalid
// UTF-8 additionally poisons history because JSON cannot preserve the input bytes.
func TestReview1022InvalidDecisionActorsLeaveStoreHealthy(t *testing.T) {
	for _, value := range []struct{ name, text string }{
		{"invalid-utf8", string([]byte{'x', 0xff})},
		{"ascii-control", "person\x00suffix"},
		{"unicode-control", "person\u0085suffix"},
		{"oversize", strings.Repeat("x", 257)},
		{"empty", ""},
	} {
		for _, field := range []string{"issuer", "subject"} {
			for _, location := range []string{"matched", "decision-only", "authorization-only"} {
				t.Run(value.name+"/"+field+"/"+location, func(t *testing.T) {
					s, p := newStore(t)
					target := register(t, s, "agent")
					r := request(target, "actor")
					if location != "authorization-only" {
						if field == "issuer" {
							r.DecisionRecord.Actor.Issuer = value.text
						} else {
							r.DecisionRecord.Actor.Subject = value.text
						}
					}
					if location != "decision-only" {
						if field == "issuer" {
							r.DecisionRecord.Authorization.Actor.Issuer = value.text
						} else {
							r.DecisionRecord.Authorization.Actor.Subject = value.text
						}
					}
					if _, err := s.Begin(ctx, r); !errors.Is(err, ErrInvalid) {
						t.Errorf("invalid copied actor accepted or misclassified: %v", err)
					}
					if err := s.Verify(ctx); err != nil {
						t.Errorf("refused actor damaged store: %v", err)
					}
					if got, err := s.ReadTarget(ctx, target.ID); err != nil || got != target {
						t.Errorf("refused actor changed target: %+v (%v)", got, err)
					}
					var count int
					if err := s.db.QueryRow("SELECT count(*) FROM operations").Scan(&count); err != nil || count != 0 {
						t.Errorf("refused actor persisted operations: %d (%v)", count, err)
					}
					if err := s.Close(); err != nil {
						t.Fatal(err)
					}
					reopened, err := Open(p, s.ID)
					if err != nil {
						t.Fatalf("store cannot reopen after refused actor: %v", err)
					}
					defer reopened.Close()
					if err := reopened.Verify(ctx); err != nil {
						t.Fatal(err)
					}
				})
			}
		}
	}
}

func TestReview1022ValidDecisionActorsSurviveReopen(t *testing.T) {
	for _, actor := range []struct{ name, issuer, subject string }{
		{"unicode", "認証 issuer", "Tāne 人"},
		{"long", strings.Repeat("i", 129), strings.Repeat("s", 200)},
		{"byte-boundary", strings.Repeat("i", 256), strings.Repeat("s", 256)},
		{"unicode-byte-boundary", strings.Repeat("é", 128), strings.Repeat("界", 85) + "x"},
	} {
		t.Run(actor.name, func(t *testing.T) {
			s, p := newStore(t)
			r := request(register(t, s, "agent"), "actor")
			r.DecisionRecord.Actor = Identity{Issuer: actor.issuer, Subject: actor.subject}
			r.DecisionRecord.Authorization.Actor = r.DecisionRecord.Actor
			o := begin(t, s, r)
			if err := s.Verify(ctx); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := Open(p, s.ID)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			got, err := reopened.ReadOperation(ctx, o.ID)
			if err != nil {
				t.Fatal(err)
			}
			if got.Request.DecisionRecord.Actor.Issuer != actor.issuer || got.Request.DecisionRecord.Actor.Subject != actor.subject || got.Request.DecisionRecord.Authorization == nil || got.Request.DecisionRecord.Authorization.Actor != got.Request.DecisionRecord.Actor {
				t.Fatal("actor evidence did not round-trip")
			}
			if err := reopened.Verify(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Cancellation after a proven mismatch cannot erase that proof or release a
// queued mutation before the corruption latch is published.
func TestReview1022ConfirmedMismatchThenCancellationFencesQueuedWriter(t *testing.T) {
	for _, damage := range []string{"target", "event"} {
		t.Run(damage, func(t *testing.T) {
			s, _ := newStore(t)
			register(t, s, "agent")
			stmt := "UPDATE targets SET data=json_set(data,'$.Availability','ready')"
			if damage == "event" {
				stmt = "UPDATE events SET data=json_set(data,'$.Target.Availability','ready')"
			}
			if _, err := s.db.Exec(stmt); err != nil {
				t.Fatal(err)
			}
			verifyCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			entered, release := make(chan struct{}), make(chan struct{})
			verifyDone, writerDone := make(chan error, 1), make(chan error, 1)
			go func() {
				verifyDone <- s.transaction(verifyCtx, true, func(q query) error {
					err := s.verify(verifyCtx, q)
					close(entered)
					<-release
					cancel()
					return err
				})
			}()
			<-entered
			before := s.db.Stats().WaitCount
			go func() { _, err := s.RegisterTarget(ctx, "must-not-exist"); writerDone <- err }()
			deadline := time.After(5 * time.Second)
			for s.db.Stats().WaitCount == before {
				select {
				case <-deadline:
					close(release)
					t.Fatal("writer did not queue for verification connection")
				default:
					runtime.Gosched()
				}
			}
			close(release)
			if err := <-verifyDone; !errors.Is(err, ErrIntegrity) {
				t.Errorf("proven corruption was hidden by cancellation: %v", err)
			}
			if !s.bad.Load() {
				t.Error("proven corruption did not latch")
			}
			if err := <-writerDone; !errors.Is(err, ErrIntegrity) {
				t.Errorf("queued mutation escaped corruption latch: %v", err)
			}
			if _, err := s.ReadTarget(ctx, "must-not-exist"); !errors.Is(err, ErrConflict) {
				t.Errorf("queued writer published: %v", err)
			}
			if _, err := s.RegisterTarget(ctx, "later-writer"); !errors.Is(err, ErrIntegrity) {
				t.Errorf("next mutation escaped corruption latch: %v", err)
			}
		})
	}
}

// This double fails a query without producing evidence of a mismatch. The real
// verifier and transaction wrapper must not promote that failure into a latch.
type review1022CanceledQuery struct {
	query
	statement string
	readErr   error
	cancel    context.CancelFunc
}

func (q review1022CanceledQuery) QueryContext(ctx context.Context, stmt string, args ...any) (*sql.Rows, error) {
	if stmt == q.statement {
		q.cancel()
		return nil, q.readErr
	}
	return q.query.QueryContext(ctx, stmt, args...)
}

func TestReview1022CanceledQueryErrorWithoutMismatchDoesNotLatch(t *testing.T) {
	for _, statement := range []string{
		"PRAGMA foreign_key_check",
		"SELECT target,sequence,data FROM events ORDER BY target,sequence",
	} {
		t.Run(statement, func(t *testing.T) {
			s, _ := newStore(t)
			register(t, s, "agent")
			verifyCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			readErr := errors.New("test-only failed query")
			err := s.transaction(verifyCtx, true, func(q query) error {
				err := s.verify(verifyCtx, review1022CanceledQuery{query: q, statement: statement, readErr: readErr, cancel: cancel})
				if !errors.Is(err, readErr) {
					t.Errorf("query failure was turned into mismatch proof: %v", err)
				}
				return err
			})
			if !errors.Is(err, context.Canceled) {
				t.Errorf("query cancellation: %v", err)
			}
			if s.bad.Load() {
				t.Error("unproven query failure latched corruption")
			}
			if _, err := s.RegisterTarget(ctx, "after-query-cancellation"); err != nil {
				t.Fatal("query failure fenced healthy store", err)
			}
			if err := s.Verify(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestReview1022UnsafeRollbackJournalRefusedWithoutChangingHealthyStore(t *testing.T) {
	for _, api := range []string{"Open", "Create"} {
		for _, damage := range []string{"symlink", "0644"} {
			t.Run(api+"/"+damage, func(t *testing.T) {
				s, healthyPath := newStore(t)
				target := register(t, s, "agent")
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
				before, err := os.ReadFile(healthyPath)
				if err != nil {
					t.Fatal(err)
				}
				path := healthyPath
				if api == "Create" {
					path = filepath.Join(filepath.Dir(healthyPath), "new.db")
				}
				journal := path + "-journal"
				marker := []byte("not a SQLite journal; must remain untouched")
				if damage == "symlink" {
					targetPath := filepath.Join(filepath.Dir(healthyPath), "journal-target")
					if err := os.WriteFile(targetPath, marker, 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(targetPath, journal); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := os.WriteFile(journal, marker, 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.Chmod(journal, 0644); err != nil {
						t.Fatal(err)
					}
				}
				var opened *Store
				if api == "Create" {
					opened, err = Create(path)
				} else {
					opened, err = Open(path, s.ID)
				}
				if opened != nil {
					opened.Close()
				}
				if !errors.Is(err, ErrIntegrity) {
					t.Errorf("unsafe journal accepted or misclassified: %v", err)
				}
				after, err := os.ReadFile(healthyPath)
				if err != nil || !bytes.Equal(after, before) {
					t.Errorf("refusal changed healthy database: %v", err)
				}
				if api == "Create" {
					if _, err := os.Lstat(path); !os.IsNotExist(err) {
						t.Errorf("refused Create left database behind: %v", err)
					}
				}
				got, err := os.ReadFile(journal)
				if err != nil || !bytes.Equal(got, marker) {
					t.Errorf("refusal changed journal or its symlink target: %v", err)
				}
				info, err := os.Lstat(journal)
				if err != nil {
					t.Fatal(err)
				}
				if damage == "symlink" && info.Mode()&os.ModeSymlink == 0 {
					t.Error("refusal replaced journal symlink")
				}
				if damage == "0644" && info.Mode().Perm() != 0644 {
					t.Error("refusal repaired journal permissions")
				}
				if err := os.Remove(journal); err != nil {
					t.Fatal(err)
				}
				reopened, err := Open(healthyPath, s.ID)
				if err != nil {
					t.Fatal("refusal damaged retained store", err)
				}
				defer reopened.Close()
				if got, err := reopened.ReadTarget(ctx, "agent"); err != nil || got != target {
					t.Fatalf("retained target changed: %+v (%v)", got, err)
				}
				if err := reopened.Verify(ctx); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

// All FK targets still exist and every immutable JSON fact remains byte-for-byte
// intact. Only the final indexed-column/snapshot comparison can detect this.
func TestReview1022IndexedColumnsMustMatchImmutableJSON(t *testing.T) {
	for _, column := range []string{"target", "decision_id"} {
		t.Run(column, func(t *testing.T) {
			s, p := newStore(t)
			o := begin(t, s, request(register(t, s, "agent"), "first"))
			register(t, s, "other")
			if err := s.Verify(ctx); err != nil {
				t.Fatal(err)
			}
			var before []byte
			if err := s.db.QueryRow("SELECT data FROM operations WHERE id=?", o.ID).Scan(&before); err != nil {
				t.Fatal(err)
			}
			value := "other-decision"
			if column == "target" {
				value = "other"
			}
			if _, err := s.db.Exec("UPDATE operations SET "+column+"=? WHERE id=?", value, o.ID); err != nil {
				t.Fatal(err)
			}
			var after []byte
			if err := s.db.QueryRow("SELECT data FROM operations WHERE id=?", o.ID).Scan(&after); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("test changed JSON instead of only its indexed column")
			}
			if err := s.basicVerify(ctx, s.db); err != nil {
				t.Fatal("test damage must retain SQLite integrity and valid FKs", err)
			}
			if err := s.Verify(ctx); !errors.Is(err, ErrIntegrity) {
				t.Errorf("indexed column disagrees with immutable JSON: %v", err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := Open(p, s.ID)
			if reopened != nil {
				reopened.Close()
			}
			if !errors.Is(err, ErrIntegrity) {
				t.Errorf("Open accepted indexed-column drift: %v", err)
			}
		})
	}
}

// Change a later event and its current projection coherently, not the original
// reservation event. Fact equality cannot substitute for transition replay.
func TestReview1022LaterEventsCannotRewriteReservedAuthority(t *testing.T) {
	for _, phase := range []string{"predecessor-retired", "committed"} {
		t.Run(phase, func(t *testing.T) {
			s, p := newStore(t)
			o := reserved(t, s, prepared(t, s, begin(t, s, request(register(t, s, "agent"), "first"))))
			original := clone(*o.Reserved)
			o = retired(t, s, o)
			if phase == "committed" {
				v, err := s.Commit(ctx, step(o), receipt(s, o, "commit"))
				o = must(t, v, err)
			}
			if err := s.Verify(ctx); err != nil {
				t.Fatal(err)
			}
			changed := clone(o)
			changed.Reserved.PolicyEpoch = "changed-epoch"
			if !changed.Reserved.valid(changed.Request.TargetID, "accept", changed.ReservedAt) {
				t.Fatal("test mutation must remain a structurally valid snapshot")
			}
			events, err := s.History(ctx, "agent", 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			last := events[len(events)-1]
			if last.ToPhase != phase || last.Operation == nil || last.Operation.ID != o.ID {
				t.Fatal("unexpected history tail")
			}
			last.Operation = &changed
			if _, err := s.db.Exec("UPDATE events SET data=? WHERE target=? AND sequence=?", encoded(last), "agent", last.Sequence); err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.Exec("UPDATE operation_state SET data=? WHERE id=?", encoded(changed), o.ID); err != nil {
				t.Fatal(err)
			}
			history, err := s.History(ctx, "agent", 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			if len(history) < 5 || history[3].ToPhase != "reserved" || history[3].Operation == nil || history[3].Operation.Reserved == nil || !same(*history[3].Operation.Reserved, original) {
				t.Fatal("test accidentally rewrote original reservation")
			}
			retained, err := s.ReadOperation(ctx, o.ID)
			if err != nil || !same(*history[len(history)-1].Operation, retained) {
				t.Fatal("test must keep current projection equal to the altered event", err)
			}
			if err := s.basicVerify(ctx, s.db); err != nil {
				t.Fatal("test mutation must retain SQLite integrity and valid FKs", err)
			}
			if err := s.Verify(ctx); !errors.Is(err, ErrIntegrity) {
				t.Errorf("later event rewrote frozen authority: %v", err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := Open(p, s.ID)
			if reopened != nil {
				reopened.Close()
			}
			if !errors.Is(err, ErrIntegrity) {
				t.Errorf("Open accepted rewritten authority: %v", err)
			}
		})
	}
}

// This immutable schema-1 fixture was produced by a3ef19a using real
// Create/Begin/MarkPrepared/Reserve calls, then closed before its bytes were saved.
// It deliberately retains copied DecisionRecord and Reserved authority evidence:
// an incompatible DTO encoding change needs an explicit schema/codec decision.
func TestSchema1GoldenStoreStillOpens(t *testing.T) {
	const storeID = "PDMKT6HNIRARM7QKWMNBWARTD3"
	const operationID = "IXV3Y7Y3DHRD7HGCR72ZXKRAUX"
	fixture, err := os.ReadFile(filepath.Join("testdata", "schema1", "golden.db"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(privateTempDir(t), "golden.db")
	if err := os.WriteFile(path, fixture, 0600); err != nil {
		t.Fatal(err)
	}
	for round := 0; round < 2; round++ {
		s, err := Open(path, storeID)
		if err != nil {
			t.Fatalf("schema-1 fixture Open %d: %v", round, err)
		}
		t.Cleanup(func() { s.Close() })
		if s.ID != storeID || s.BackendLineageID != "YMCUR4DYD6STSNFP6KIX2S3N6L" {
			t.Fatal("fixture lineage changed")
		}
		target, err := s.ReadTarget(ctx, "golden-agent")
		if err != nil || target.Revision != 4 || target.Generation != 1 || target.OperationID != operationID || target.Availability != "fenced" {
			t.Fatalf("fixture target: %+v (%v)", target, err)
		}
		o, err := s.ReadOperation(ctx, operationID)
		if err != nil {
			t.Fatal(err)
		}
		if o.Phase != "reserved" || o.Revision != 3 || o.Generation != 1 || o.Version.ID != "W3QFTGY4SIWNBJRONAH2SCLMJO" || o.Reserved == nil {
			t.Fatalf("fixture lost its reserved operation: %+v", o)
		}
		d := o.Request.DecisionRecord
		if d.ID != "decision-golden-reserved" || d.StoreID != "decisions" || d.Actor.Issuer != "issuer" || d.Actor.Subject != "person" || d.Authorization == nil || d.Authorization.Actor != d.Actor || d.Authorization.Role != "Agent.Approver" {
			t.Fatalf("fixture lost copied decision evidence: %+v", d)
		}
		at := time.Date(2025, 10, 22, 12, 0, 0, 0, time.UTC)
		if !o.ReservedAt.Equal(at) || o.Reserved.PolicyVersion != "current-policy" || o.Reserved.PolicyEpoch != "epoch" || o.Reserved.OperationRevision != 2 || o.Reserved.Phase != "prepared" || !same(o.Reserved.DecisionRecord, d) {
			t.Fatal("fixture reservation evidence changed")
		}
		events, err := s.History(ctx, "golden-agent", 0, 100)
		if err != nil || len(events) != 4 {
			t.Fatalf("fixture history: %d events (%v)", len(events), err)
		}
		for i, phase := range []string{"", "preparing", "prepared", "reserved"} {
			if events[i].Sequence != uint64(i+1) || events[i].ToPhase != phase {
				t.Fatalf("fixture event %d: %+v", i, events[i])
			}
		}
		if events[3].Operation == nil || !same(*events[3].Operation, o) {
			t.Fatal("fixture projection disagrees with reservation history")
		}
		if err := s.Verify(ctx); err != nil {
			t.Fatal(err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, fixture) {
		t.Fatalf("read-only compatibility checks rewrote schema-1 bytes: %v", err)
	}
}
