package targetversions

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func step(o Operation) Step { return Step{o.ID, o.Revision, o.Generation} }
func receipt(s *Store, o Operation, kind string) Receipt {
	return Receipt{Kind: kind, OperationID: o.ID, TargetID: o.Request.TargetID, BackendLineageID: s.BackendLineageID, ExecutionContextID: o.Version.ExecutionContextID, Generation: o.Generation, ArtifactDigest: o.Request.Candidate.binding(), EvidenceDigest: digest, FenceDigest: digest, ContextDigest: digest, QualificationDigest: o.Request.Candidate.Qualification.Digest, Predecessor: o.Request.Predecessor}
}
func authority(s *Store, o Operation) AuthorizationSnapshot {
	d := clone(o.Request.DecisionRecord)
	return AuthorizationSnapshot{OperationID: o.ID, Generation: o.Generation, OperationRevision: o.Revision, Phase: o.Phase, DecisionRecord: d, DecisionDigest: copiedDecisionDigest(d), Actor: d.Actor, Subject: d.Request.Subject, Action: string(d.Request.Action), Role: d.Authorization.Role, TargetID: o.Request.TargetID, PolicyVersion: "current-policy", PolicyEpoch: "epoch", GrantIDs: []string{"current-grant"}, AuthorizedAt: s.now().Add(-time.Second), ExpiresAt: s.now().Add(time.Minute), CredentialExpiresAt: s.now().Add(time.Minute)}
}
func prepared(t *testing.T, s *Store, o Operation) Operation {
	t.Helper()
	v, e := s.MarkPrepared(ctx, step(o), receipt(s, o, "prepared"))
	return must(t, v, e)
}
func reserved(t *testing.T, s *Store, o Operation) Operation {
	t.Helper()
	v, e := s.Reserve(ctx, step(o), authority(s, o))
	return must(t, v, e)
}
func retired(t *testing.T, s *Store, o Operation) Operation {
	t.Helper()
	kind := "retired"
	if o.Request.Predecessor.Kind == "genesis" || o.FrozenSource == nil {
		kind = "no_source"
	}
	if o.Request.Predecessor.Kind == "abandonment" && o.FrozenSource != nil {
		kind = "already_retired"
	}
	r := receipt(s, o, kind)
	if kind == "already_retired" {
		r.PredecessorEvidence = digest
	}
	v, e := s.MarkRetired(ctx, step(o), r)
	return must(t, v, e)
}
func committed(t *testing.T, s *Store, o Operation) Operation {
	t.Helper()
	o = prepared(t, s, o)
	o = reserved(t, s, o)
	o = retired(t, s, o)
	v, e := s.Commit(ctx, step(o), receipt(s, o, "commit"))
	return must(t, v, e)
}
func activeRequest(t *testing.T, s *Store, targetID, key string) Request {
	target, e := s.ReadTarget(ctx, targetID)
	target = must(t, target, e)
	r := request(target, key)
	r.Predecessor = PredecessorRef{"version", target.ActiveVersionID}
	return r
}
func reopen(t *testing.T, s *Store, p string) *Store {
	t.Helper()
	id := s.ID
	s.Close()
	v, e := Open(p, id)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { v.Close() })
	return v
}
func TestForwardTransitionAndHistory(t *testing.T) {
	s, p := newStore(t)
	target := register(t, s, "agent")
	r := request(target, "first")
	o := begin(t, s, r)
	s = reopen(t, s, p)
	o = prepared(t, s, o)
	s = reopen(t, s, p)
	o = reserved(t, s, o)
	saved := clone(*o.Reserved)
	// Expiry after Reserve cannot turn exact completion into a fresh decision.
	s.now = func() time.Time { return time.Now().UTC().Add(time.Hour) }
	o = retired(t, s, o)
	s = reopen(t, s, p)
	target, e := s.ReadTarget(ctx, "agent")
	if e != nil || target.ActiveVersionID != "" || target.Availability != "fenced" {
		t.Fatal("premature active", target, e)
	}
	old := o
	commit := receipt(s, o, "commit")
	o, e = s.Commit(ctx, step(o), commit)
	if e != nil {
		t.Fatal(e)
	}
	if !same(saved, *o.Reserved) || o.Phase != "committed" {
		t.Fatal("reservation changed")
	}
	again, e := s.Commit(ctx, step(old), commit)
	if e != nil || again.ID != o.ID || again.Revision != o.Revision {
		t.Fatal("lost reply not idempotent", e)
	}
	target, e = s.ReadTarget(ctx, "agent")
	if e != nil || target.ActiveVersionID != o.Version.ID || target.OperationID != "" || target.Availability != "ready" {
		t.Fatal(target, e)
	}
	s = reopen(t, s, p)
	if got := begin(t, s, r); got.Phase != "committed" {
		t.Fatal("terminal retry")
	}
	changed := clone(r)
	changed.DecisionRecord.Request.Feedback = "new"
	if _, e = s.Begin(ctx, changed); !errors.Is(e, ErrConflict) {
		t.Fatal("terminal key changed", e)
	}
	next := begin(t, s, activeRequest(t, s, "agent", "second"))
	next = committed(t, s, next)
	if next.Version.ID == o.Version.ID || next.Version.ExecutionContextID == o.Version.ExecutionContextID {
		t.Fatal("context reused")
	}
	var n int
	if e = s.db.QueryRow("SELECT count(*) FROM links WHERE kind='predecessor' AND from_id=? AND to_id=?", o.Version.ID, next.Version.ID).Scan(&n); e != nil || n != 1 {
		t.Fatal("missing edge", e, n)
	}
	if e = s.db.QueryRow("SELECT count(*) FROM links WHERE kind='predecessor_reverse' AND from_id=? AND to_id=?", next.Version.ID, o.Version.ID).Scan(&n); e != nil || n != 1 {
		t.Fatal("missing reciprocal edge", e, n)
	}
}
func raceTwo(a, b func() error) (error, error) {
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	var x, y error
	go func() { defer wg.Done(); <-start; x = a() }()
	go func() { defer wg.Done(); <-start; y = b() }()
	close(start)
	wg.Wait()
	return x, y
}
func oneWinner(t *testing.T, a, b error) {
	t.Helper()
	if (a == nil) == (b == nil) {
		t.Fatalf("want exactly one winner: %v / %v", a, b)
	}
}
func TestReserveAbortRace(t *testing.T) {
	s, p := newStore(t)
	o := prepared(t, s, begin(t, s, request(register(t, s, "agent"), "a")))
	s2, e := Open(p, s.ID)
	if e != nil {
		t.Fatal(e)
	}
	defer s2.Close()
	a, b := raceTwo(func() error { _, e := s.Reserve(ctx, step(o), authority(s, o)); return e }, func() error { _, e := s2.StartAbort(ctx, step(o), "cancel"); return e })
	oneWinner(t, a, b)
	got, e := s.ReadOperation(ctx, o.ID)
	got = must(t, got, e)
	if got.Phase != "reserved" && got.Phase != "aborting" {
		t.Fatal(got.Phase)
	}
}
func TestReservationSurvivesCancellation(t *testing.T) {
	s, p := newStore(t)
	o := reserved(t, s, prepared(t, s, begin(t, s, request(register(t, s, "agent"), "a"))))
	c, cancel := context.WithCancel(ctx)
	cancel()
	if _, e := s.Commit(c, step(o), receipt(s, o, "commit")); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	s = reopen(t, s, p)
	got, e := s.ReadOperation(ctx, o.ID)
	got = must(t, got, e)
	if got.Phase != "reserved" || got.Reserved == nil {
		t.Fatal("cancel thawed")
	}
	if _, e = s.StartAbort(ctx, step(got), "late"); !errors.Is(e, ErrConflict) {
		t.Fatal("post-reserve abort", e)
	}
}
func TestReceiptIdempotencyAndBinding(t *testing.T) {
	s, _ := newStore(t)
	o := begin(t, s, request(register(t, s, "agent"), "a"))
	r := receipt(s, o, "prepared")
	original := step(o)
	o = prepared(t, s, o)
	if got, e := s.MarkPrepared(ctx, original, r); e != nil || got.Revision != o.Revision {
		t.Fatal("duplicate", e)
	}
	for name, change := range map[string]func(*Receipt){"context": func(r *Receipt) { r.ExecutionContextID = "other" }, "generation": func(r *Receipt) { r.Generation++ }, "backend": func(r *Receipt) { r.BackendLineageID = "other" }, "evidence": func(r *Receipt) { r.EvidenceDigest = "" }, "artifact": func(r *Receipt) { r.ArtifactDigest = strings.Repeat("b", 64) }, "qualification": func(r *Receipt) { r.QualificationDigest = strings.Repeat("b", 64) }, "target": func(r *Receipt) { r.TargetID = "other" }, "operation": func(r *Receipt) { r.OperationID = "other" }, "kind": func(r *Receipt) { r.Kind = "release" }, "predecessor": func(r *Receipt) { r.Predecessor.ID = "other" }, "oversize": func(r *Receipt) { r.IntentID = strings.Repeat("x", 65537) }} {
		t.Run(name, func(t *testing.T) {
			fresh := begin(t, s, request(register(t, s, "receipt-"+name), "receipt-"+name))
			bad := receipt(s, fresh, "prepared")
			change(&bad)
			if _, e := s.MarkPrepared(ctx, step(fresh), bad); !errors.Is(e, ErrConflict) {
				t.Fatal("receipt binding classification", e)
			}
		})
	}
	changedEvidence := r
	changedEvidence.EvidenceDigest = strings.Repeat("b", 64)
	if _, e := s.MarkPrepared(ctx, original, changedEvidence); !errors.Is(e, ErrConflict) {
		t.Fatal("changed saved receipt accepted", e)
	}
	a := authority(s, o)
	for name, change := range map[string]func(*AuthorizationSnapshot){"record": func(a *AuthorizationSnapshot) {
		a.DecisionRecord.ID = "other"
		a.DecisionDigest = copiedDecisionDigest(a.DecisionRecord)
	}, "digest": func(a *AuthorizationSnapshot) { a.DecisionDigest = strings.Repeat("b", 64) }, "actor": func(a *AuthorizationSnapshot) { a.Actor.Subject = "other" }, "subject": func(a *AuthorizationSnapshot) { a.Subject.ID = "other" }, "action": func(a *AuthorizationSnapshot) { a.Action = "recover" }, "expiry": func(a *AuthorizationSnapshot) { a.ExpiresAt = s.now().Add(-time.Second) }, "credential expiry": func(a *AuthorizationSnapshot) { a.CredentialExpiresAt = s.now().Add(-time.Second) }} {
		t.Run(name, func(t *testing.T) {
			bad := clone(a)
			change(&bad)
			if _, e := s.Reserve(ctx, step(o), bad); !errors.Is(e, ErrConflict) {
				t.Fatal("substituted authority classification", e)
			}
		})
	}
	o = reserved(t, s, o)
	if _, e := s.MarkRetired(ctx, original, receipt(s, o, "no_source")); !errors.Is(e, ErrConflict) {
		t.Fatal("unrelated stale step", e)
	}
}
func TestAbortReleaseUncertainty(t *testing.T) {
	s, p := newStore(t)
	target := register(t, s, "agent")
	r := request(target, "a")
	o := begin(t, s, r)
	v, e := s.StartAbort(ctx, step(o), "cancel")
	o = must(t, v, e)
	s = reopen(t, s, p)
	if _, e = s.Reserve(ctx, step(o), authority(s, o)); !errors.Is(e, ErrConflict) {
		t.Fatal("Reserve won after abort intent", e)
	}
	bad := receipt(s, o, "release")
	bad.EvidenceDigest = ""
	if _, e = s.FinishAbort(ctx, step(o), bad, false); e == nil {
		t.Fatal("unknown release accepted")
	}
	target, e = s.ReadTarget(ctx, target.ID)
	if e != nil || target.Availability != "fenced" {
		t.Fatal("unknown release thawed")
	}
	old := o
	o, e = s.FinishAbort(ctx, step(o), receipt(s, o, "release"), false)
	if e != nil || o.Phase != "aborted" {
		t.Fatal(e)
	}
	if _, e = s.FinishAbort(ctx, step(old), receipt(s, old, "release"), true); !errors.Is(e, ErrConflict) {
		t.Fatal("changed terminal outcome", e)
	}
	target, e = s.ReadTarget(ctx, target.ID)
	if e != nil || target.Availability != "unavailable" {
		t.Fatal("genesis became ready")
	}
	reuse := request(register(t, s, "other"), "different")
	reuse.DecisionRecord = r.DecisionRecord
	reuse.Subject = r.Subject
	if _, e = s.Begin(ctx, reuse); !errors.Is(e, ErrConflict) {
		t.Fatal("aborted decision reused", e)
	}
	// An aborted genesis attempt can be retried as new work, not implicit recovery.
	target, e = s.ReadTarget(ctx, "agent")
	target = must(t, target, e)
	first := committed(t, s, begin(t, s, request(target, "fresh")))
	next := begin(t, s, activeRequest(t, s, "agent", "next"))
	next = prepared(t, s, next)
	next, e = s.StartAbort(ctx, step(next), "refuse")
	if e != nil {
		t.Fatal(e)
	}
	_, e = s.FinishAbort(ctx, step(next), receipt(s, next, "release"), true)
	if e != nil {
		t.Fatal(e)
	}
	target, e = s.ReadTarget(ctx, "agent")
	if e != nil || target.ActiveVersionID != first.Version.ID || target.Availability != "ready" {
		t.Fatal("predecessor not restored", e, target)
	}
}
