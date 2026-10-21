package decisionledger

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agent-primitives/sessions/api"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Initialize(filepath.Join(t.TempDir(), "private", "ledger.sqlite"), "host-lineage")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
func TestStoreIdentityAndSubjects(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	id := s.ID()
	ref, err := s.RegisterSubject(ctx, suiteSubject())
	if err != nil {
		t.Fatal(err)
	}
	if again, err := s.RegisterSubject(ctx, suiteSubject()); err != nil || again != ref {
		t.Fatalf("duplicate subject: %v", err)
	}
	changed := suiteSubject()
	changed.Suite.Member = "changed"
	if _, err := s.RegisterSubject(ctx, changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed registration: %v", err)
	}
	next := suiteSubject()
	next.Generation = 2
	if _, err := s.RegisterSubject(ctx, next); !errors.Is(err, ErrConflict) {
		t.Fatalf("two open generations: %v", err)
	}
	if err := s.Supersede(ctx, ref); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RegisterSubject(ctx, next); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RegisterSubject(ctx, effectSubject()); err != nil {
		t.Fatalf("kind collision: %v", err)
	}
	if _, err := Open(s.path, id, "host-lineage"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("second writer: %v", err)
	}
	s.Close()
	reopened, err := Open(s.path, id, "host-lineage")
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.ID() != id {
		t.Fatal("new identity")
	}
	stored, state, err := reopened.subject(ctx, ref)
	if err != nil || state != "superseded" || stored.ID != "proposal" {
		t.Fatalf("lost subject: %s %v", state, err)
	}
}
func TestStoreRefusesUnsafeOrForeignState(t *testing.T) {
	s := newTestStore(t)
	path, id := s.path, s.ID()
	s.Close()
	for _, tc := range []struct{ id, lineage string }{{"foreign", "host-lineage"}, {id, "foreign"}} {
		if _, err := Open(path, tc.id, tc.lineage); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("wrong lineage: %v", err)
		}
	}
	if _, err := Initialize(path, "host-lineage"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("reinitialized: %v", err)
	}
	os.Chmod(path, 0644)
	if _, err := Open(path, id, "host-lineage"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unsafe file: %v", err)
	}
	os.Chmod(path, 0600)
	link := filepath.Join(t.TempDir(), "link")
	os.Symlink(filepath.Dir(path), link)
	if _, err := Open(filepath.Join(link, "ledger.sqlite"), id, "host-lineage"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("symlink: %v", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	db.Exec("PRAGMA user_version=2")
	db.Close()
	if _, err := Open(path, id, "host-lineage"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("future schema: %v", err)
	}
	os.Truncate(path, 0)
	if _, err := Open(path, id, "host-lineage"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("empty: %v", err)
	}
	if _, err := Open(filepath.Join(t.TempDir(), "absent"), id, "host-lineage"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing: %v", err)
	}
}
func TestCommitIsAtomicAndPersonScoped(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	ref, _ := s.RegisterSubject(ctx, suiteSubject())
	a := api.CallerIdentity{Issuer: "issuer", Subject: "alice"}
	b := api.CallerIdentity{Issuer: "issuer", Subject: "bob"}
	r := DecideRequest{Workspace: ref.Workspace, Key: "shared", Subject: ref, Action: Accept}
	now := time.Date(2029, 1, 1, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	// Bob's refusal cannot occupy Alice's request key or consume the subject.
	rb, err := s.commit(ctx, b, now.Add(time.Hour), r, nil, "policy_denied")
	if err != nil || rb.Outcome != "refused" {
		t.Fatal(err)
	}
	auth := Authorization{Actor: a, Subject: ref, Action: Accept, Role: "Approver", PolicyVersion: "p1", GrantIDs: []string{"grant"}}
	ra, err := s.commit(ctx, a, now.Add(time.Hour), r, &auth, "")
	if err != nil || ra.Outcome != "recorded" || ra.ID == rb.ID {
		t.Fatalf("recording: %+v %v", ra, err)
	}
	again, err := s.commit(ctx, a, now.Add(time.Hour), r, &auth, "")
	if err != nil || again.ID != ra.ID {
		t.Fatalf("retry: %v", err)
	}
	r.Feedback = "changed"
	if _, err := s.commit(ctx, a, now.Add(time.Hour), r, &auth, ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed key: %v", err)
	}
	if err := s.Supersede(ctx, ref); !errors.Is(err, ErrConflict) {
		t.Fatalf("superseded decision: %v", err)
	}
	r.Key = "other"
	other, err := s.commit(ctx, b, now.Add(time.Hour), r, &Authorization{Actor: b, Subject: ref, Action: Accept, Role: "Approver", PolicyVersion: "p1", GrantIDs: []string{"grant"}}, "")
	if err != nil || other.RefusalCode != "subject_closed" {
		t.Fatalf("CAS: %+v %v", other, err)
	}
	id, path := s.ID(), s.path
	s.Close()
	s, err = Open(path, id, "host-lineage")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err := s.lookup(ctx, a, ref.Workspace, "shared")
	if err != nil || got.ID != ra.ID {
		t.Fatalf("read-back: %v", err)
	}
}
func TestCredentialExpiryRollsBackInsertedDecision(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	ref, _ := s.RegisterSubject(ctx, suiteSubject())
	base := time.Date(2029, 1, 1, 0, 0, 0, 0, time.UTC)
	until := base.Add(time.Second)
	calls := 0
	s.now = func() time.Time {
		calls++
		if calls >= 4 {
			return until
		}
		return base
	}
	actor := api.CallerIdentity{Issuer: "issuer", Subject: "alice"}
	r := DecideRequest{Workspace: ref.Workspace, Key: "key", Subject: ref, Action: Accept}
	auth := Authorization{Actor: actor, Subject: ref, Action: Accept, Role: "Approver", PolicyVersion: "p1", GrantIDs: []string{"grant"}}
	if _, err := s.commit(ctx, actor, until, r, &auth, ""); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("late expiry: %v", err)
	}
	if _, err := s.lookup(ctx, actor, r.Workspace, r.Key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rolled-back record exists: %v", err)
	}
	if _, state, err := s.subject(ctx, ref); err != nil || state != "open" {
		t.Fatalf("expiry consumed subject: %s %v", state, err)
	}
}

func TestSubjectExpiryImmediatelyBeforeCommit(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	subject := suiteSubject()
	ref, _ := s.RegisterSubject(ctx, subject)
	calls := 0
	s.now = func() time.Time {
		calls++
		if calls >= 4 {
			return subject.ExpiresAt
		}
		return subject.ExpiresAt.Add(-time.Second)
	}
	actor := api.CallerIdentity{Issuer: "issuer", Subject: "alice"}
	r := DecideRequest{Workspace: ref.Workspace, Key: "key", Subject: ref, Action: Accept}
	auth := Authorization{Actor: actor, Subject: ref, Action: Accept, Role: "Approver", PolicyVersion: "p1", GrantIDs: []string{"grant"}}
	if _, err := s.commit(ctx, actor, subject.ExpiresAt.Add(time.Hour), r, &auth, ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("late subject expiry: %v", err)
	}
	if _, state, err := s.subject(ctx, ref); err != nil || state != "open" {
		t.Fatalf("expired subject consumed: %s %v", state, err)
	}
}

func TestExpiredCredentialWritesNothing(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	ref, _ := s.RegisterSubject(ctx, suiteSubject())
	now := time.Date(2029, 1, 1, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	a := api.CallerIdentity{Issuer: "issuer", Subject: "alice"}
	r := DecideRequest{Workspace: ref.Workspace, Key: "key", Subject: ref, Action: Accept}
	if _, err := s.commit(ctx, a, now, r, nil, "policy_denied"); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expiry: %v", err)
	}
	if _, err := s.lookup(ctx, a, ref.Workspace, "key"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired record exists: %v", err)
	}
}
