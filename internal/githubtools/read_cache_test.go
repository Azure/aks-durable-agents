package githubtools

import (
	"bytes"
	"database/sql"
	"errors"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agent-primitives/sessions/api"
)

func testReadCall() ReadCall {
	return ReadCall{SessionUID: "session", ExecutionID: "execution", CallID: "read", Key: "read-key", CallSeq: 3, CallHash: strings.Repeat("a", 64), Requester: api.CallerIdentity{Issuer: "issuer", Subject: "requester"}, AppID: "1", InstallationID: "2", RepositoryID: "3", IssueNumber: 7}
}
func reopenNative(t *testing.T, s *Store) *Store {
	t.Helper()
	path, id := s.path, s.ID()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := Open(path, id, "host-lineage", testBinding)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { next.Close() })
	return next
}
func TestReadCacheLifecycleAndEscapedData(t *testing.T) {
	s := testStore(t)
	call := testReadCall()
	pending, err := s.PrepareRead(t.Context(), call)
	if err != nil || pending.Outcome != nil || pending.StartedAt.IsZero() {
		t.Fatalf("pending: %+v %v", pending, err)
	}
	s = reopenNative(t, s)
	again, err := s.PrepareRead(t.Context(), call)
	if err != nil || !reflect.DeepEqual(pending, again) {
		t.Fatalf("pending changed: %+v %v", again, err)
	}
	result := ReadOutcome{Issue: Issue{Number: 7, Title: "Title\twith control", Body: strings.Repeat("<\"\\", 24000), URL: "https://github.com/example/repo/issues/7?view=full"}}
	s.now = func() time.Time { return pending.StartedAt.Add(-time.Hour) }
	saved, err := s.SaveRead(t.Context(), call, result)
	if err != nil || saved.Outcome == nil || *saved.Outcome != result || !saved.FinishedAt.Before(saved.StartedAt) {
		t.Fatalf("saved: %+v %v", saved, err)
	}
	s = reopenNative(t, s)
	got, err := s.Read(t.Context(), call)
	if err != nil || !reflect.DeepEqual(got, saved) {
		t.Fatalf("saved read changed: %+v %v", got, err)
	}
	changed := result
	changed.Issue.Body = "new response"
	got, err = s.SaveRead(t.Context(), call, changed)
	if err != nil || !reflect.DeepEqual(got, saved) {
		t.Fatalf("first result was overwritten: %v", err)
	}
}
func TestReadCacheConcurrentFirstOutcomeWins(t *testing.T) {
	s := testStore(t)
	call := testReadCall()
	if _, err := s.PrepareRead(t.Context(), call); err != nil {
		t.Fatal(err)
	}
	var work sync.WaitGroup
	results := make(chan ReadRecord, 8)
	for i := range 8 {
		work.Go(func() {
			outcome := ReadOutcome{Issue: Issue{Number: 7, Title: "Title", Body: strings.Repeat("x", i), URL: "display"}}
			record, err := s.SaveRead(t.Context(), call, outcome)
			if err != nil {
				t.Error(err)
				return
			}
			results <- record
		})
	}
	work.Wait()
	close(results)
	saved, err := s.Read(t.Context(), call)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for record := range results {
		count++
		if !reflect.DeepEqual(saved, record) {
			t.Fatal("concurrent cache returned a different outcome")
		}
	}
	if count != 8 {
		t.Fatal("lost completion")
	}
}

func TestReadCacheErrorsAndBinding(t *testing.T) {
	for _, code := range []string{"read_unavailable", "access_unavailable"} {
		t.Run(code, func(t *testing.T) {
			s := testStore(t)
			call := testReadCall()
			if _, err := s.PrepareRead(t.Context(), call); err != nil {
				t.Fatal(err)
			}
			saved, err := s.SaveRead(t.Context(), call, ReadOutcome{FailureCode: code})
			if err != nil {
				t.Fatal(err)
			}
			s = reopenNative(t, s)
			got, err := s.Read(t.Context(), call)
			if err != nil || !reflect.DeepEqual(saved, got) {
				t.Fatalf("cached error changed: %v", err)
			}
			for _, mutate := range []func(*ReadCall){func(c *ReadCall) { c.CallHash = strings.Repeat("b", 64) }, func(c *ReadCall) { c.RepositoryID = "4" }, func(c *ReadCall) { c.CallSeq++ }, func(c *ReadCall) { c.Requester.Subject = "other" }, func(c *ReadCall) { c.IssueNumber++ }} {
				changed := call
				mutate(&changed)
				if _, err = s.PrepareRead(t.Context(), changed); !errors.Is(err, ErrConflict) {
					t.Fatalf("changed read accepted: %v", err)
				}
			}
		})
	}
}
func TestReadWriteKeyCollisionBothDirections(t *testing.T) {
	for _, first := range []string{"read", "write"} {
		t.Run(first, func(t *testing.T) {
			s := testStore(t)
			a := testApproval()
			read := testReadCall()
			read.Key = a.Call.Key
			if first == "read" {
				if _, err := s.PrepareRead(t.Context(), read); err != nil {
					t.Fatal(err)
				}
				if err := s.PrepareApproval(t.Context(), a); !errors.Is(err, ErrConflict) {
					t.Fatalf("write reused read key: %v", err)
				}
				if _, _, err := s.Reserve(t.Context(), a.Call, 5); !errors.Is(err, ErrConflict) {
					t.Fatalf("reserve reused read key: %v", err)
				}
			} else {
				if err := s.PrepareApproval(t.Context(), a); err != nil {
					t.Fatal(err)
				}
				if _, err := s.PrepareRead(t.Context(), read); !errors.Is(err, ErrConflict) {
					t.Fatalf("read reused write key: %v", err)
				}
			}
		})
	}
}
func TestReadCacheRefusesInvalidOrCorruptEvidence(t *testing.T) {
	for _, kind := range []string{"projection", "outcome", "mixed-kind"} {
		t.Run(kind, func(t *testing.T) {
			s := testStore(t)
			call := testReadCall()
			if _, err := s.PrepareRead(t.Context(), call); err != nil {
				t.Fatal(err)
			}
			if _, err := s.SaveRead(t.Context(), call, ReadOutcome{Issue: Issue{Number: 8, Title: "wrong", URL: "display"}}); !errors.Is(err, ErrInvalid) {
				t.Fatalf("wrong issue accepted: %v", err)
			}
			if _, err := s.SaveRead(t.Context(), call, ReadOutcome{FailureCode: "raw-provider-message"}); !errors.Is(err, ErrInvalid) {
				t.Fatalf("unsafe failure accepted: %v", err)
			}
			if kind == "projection" {
				_, _ = s.db.Exec("UPDATE reads SET session_uid='other'")
			}
			if kind == "outcome" {
				record, _ := s.Read(t.Context(), call)
				record.Outcome = &ReadOutcome{Issue: Issue{Number: 8, Title: "wrong", URL: "display"}}
				record.FinishedAt = time.Now().UTC()
				_, _ = s.db.Exec("UPDATE reads SET record=?", encode(record))
			}
			if kind == "mixed-kind" {
				a := testApproval()
				a.Call.Key = call.Key
				r := ApprovalRecord{Approval: a, ID: "fake", PreparedAt: time.Now().UTC()}
				if _, err := s.db.Exec("INSERT INTO approvals VALUES(?,?,?,?,?,?)", r.ID, a.Call.slot(), a.Call.SessionUID, a.Call.Key, "active", encode(r)); err != nil {
					t.Fatal(err)
				}
			}
			path, id := s.path, s.ID()
			s.Close()
			if opened, err := Open(path, id, "host-lineage", testBinding); !errors.Is(err, ErrUnavailable) {
				if opened != nil {
					opened.Close()
				}
				t.Fatalf("corrupt read reopened: %v", err)
			}
		})
	}
}
func TestSchemaOneRefusedWithoutMigration(t *testing.T) {
	s := testStore(t)
	prepared(t, s)
	path, id := s.path, s.ID()
	s.Close()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{"DROP TABLE reads", "UPDATE metadata SET schema_version=1", "PRAGMA user_version=1"} {
		if _, err = db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := Open(path, id, "host-lineage", testBinding)
	if !errors.Is(err, ErrUnavailable) {
		if opened != nil {
			opened.Close()
		}
		t.Fatalf("schema1 adopted: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("schema1 was modified: %v", err)
	}
}
