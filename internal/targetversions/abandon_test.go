package targetversions

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func abandonRequest(s *Store, o Operation, key string) AbandonRequest {
	a := authority(s, o)
	a.Subject.ID = "abandon-" + key
	a.Action = "abandon_activation"
	a.Role = "Agent.Operator"
	a.DecisionRecord.ID = "operator-" + key
	a.DecisionRecord.Request.Subject = a.Subject
	a.DecisionRecord.Request.Action = a.Action
	a.DecisionRecord.Request.Key = key
	a.DecisionRecord.Authorization.Subject = a.Subject
	a.DecisionRecord.Authorization.Action = a.Action
	a.DecisionRecord.Authorization.Role = a.Role
	a.DecisionDigest = a.DecisionRecord.copiedDigest()
	return AbandonRequest{Step: step(o), Key: key, Reason: "operator explicit abandonment", Authority: a}
}
func abandonStart(t *testing.T, s *Store, o Operation, key string) Operation {
	t.Helper()
	v, e := s.StartAbandon(ctx, abandonRequest(s, o, key))
	return must(t, v, e)
}
func abandonReceipts(s *Store, o Operation) (Receipt, Receipt) {
	kind := "abandon_retired"
	if o.FrozenSource == nil {
		kind = "abandon_no_source"
	}
	if o.Request.Predecessor.Kind == "abandonment" && o.FrozenSource != nil {
		kind = "abandon_already_retired"
	}
	p := receipt(s, o, kind)
	p.IntentID = o.Abandonment.IntentID
	if kind == "abandon_already_retired" {
		p.PredecessorEvidence = digest
	}
	successor := receipt(s, o, "successor_disabled")
	successor.IntentID = o.Abandonment.IntentID
	return p, successor
}
func abandonFinish(t *testing.T, s *Store, o Operation) Operation {
	t.Helper()
	p, n := abandonReceipts(s, o)
	v, e := s.FinishAbandon(ctx, step(o), p, n)
	return must(t, v, e)
}
func pendingWithPredecessor(t *testing.T, s *Store) (Operation, Operation) {
	t.Helper()
	first := committed(t, s, begin(t, s, request(register(t, s, "agent"), "first")))
	next := reserved(t, s, prepared(t, s, begin(t, s, activeRequest(t, s, "agent", "second"))))
	return first, next
}
func recoveryRequest(t *testing.T, s *Store, abandoned Operation, key string) Request {
	t.Helper()
	target, e := s.ReadTarget(ctx, abandoned.Request.TargetID)
	target = must(t, target, e)
	r := request(target, key)
	r.Predecessor = PredecessorRef{"abandonment", abandoned.Abandonment.ID}
	if abandoned.FrozenSource != nil {
		r.Intent = "recover"
		r.SourceVersionID = abandoned.FrozenSource.ID
		r.Candidate = clone(abandoned.FrozenSource.Candidate)
		r.Candidate.Qualification.ID = "fresh-q-" + key
		r.DecisionRecord.Request.Action = "recover"
		r.DecisionRecord.Authorization.Action = "recover"
	}
	return r
}
func TestAbandonAuthorityOperationBinding(t *testing.T) {
	s, _ := newStore(t)
	_, o := pendingWithPredecessor(t, s)
	r := abandonRequest(s, o, "abandon")
	for name, change := range map[string]func(*AuthorizationSnapshot){"operation": func(a *AuthorizationSnapshot) { a.OperationID = "other" }, "generation": func(a *AuthorizationSnapshot) { a.Generation++ }, "revision": func(a *AuthorizationSnapshot) { a.OperationRevision++ }, "phase": func(a *AuthorizationSnapshot) { a.Phase = "committed" }} {
		t.Run(name, func(t *testing.T) {
			bad := clone(r)
			change(&bad.Authority)
			if _, e := s.StartAbandon(ctx, bad); !errors.Is(e, ErrConflict) {
				t.Fatal("operator snapshot not bound to failed operation", e)
			}
		})
	}
}
func TestAbandonClaimErrors(t *testing.T) {
	for _, storageFailure := range []bool{false, true} {
		t.Run(fmt.Sprint(storageFailure), func(t *testing.T) {
			s, _ := newStore(t)
			_, o := pendingWithPredecessor(t, s)
			r := abandonRequest(s, o, "abandon")
			want := ErrConflict
			if storageFailure {
				want = ErrIntegrity
				if _, e := s.db.Exec(`CREATE TRIGGER fail_claim BEFORE INSERT ON decision_claims BEGIN SELECT RAISE(ABORT,'simulated storage failure'); END`); e != nil {
					t.Fatal(e)
				}
			} else {
				r.Authority.DecisionRecord.StoreID = o.Request.DecisionRecord.StoreID
				r.Authority.DecisionRecord.ID = o.Request.DecisionRecord.ID
				r.Authority.DecisionDigest = r.Authority.DecisionRecord.copiedDigest()
			}
			if _, e := s.StartAbandon(ctx, r); !errors.Is(e, want) {
				t.Fatalf("claim failure misclassified: %v want %v", e, want)
			}
		})
	}
}
func TestCommitAbandonRace(t *testing.T) {
	s, p := newStore(t)
	_, o := pendingWithPredecessor(t, s)
	o = retired(t, s, o)
	s2, e := Open(p, s.ID)
	if e != nil {
		t.Fatal(e)
	}
	defer s2.Close()
	ar := abandonRequest(s2, o, "abandon")
	a, b := raceTwo(func() error { _, e := s.Commit(ctx, step(o), receipt(s, o, "commit")); return e }, func() error { _, e := s2.StartAbandon(ctx, ar); return e })
	oneWinner(t, a, b)
	got, e := s.ReadOperation(ctx, o.ID)
	got = must(t, got, e)
	if got.Phase != "committed" && got.Phase != "abandoning" {
		t.Fatal(got.Phase)
	}
}
func TestAbandonRestartAndTombstone(t *testing.T) {
	s, p := newStore(t)
	first, o := pendingWithPredecessor(t, s)
	ar := abandonRequest(s, o, "abandon")
	old := o
	var e error
	o, e = s.StartAbandon(ctx, ar)
	if e != nil {
		t.Fatal(e)
	}
	s = reopen(t, s, p)
	if got, e := s.StartAbandon(ctx, ar); e != nil || got.Abandonment.IntentID != o.Abandonment.IntentID {
		t.Fatal("intent retry", e)
	}
	for name, call := range map[string]func() error{"retire": func() error { _, e := s.MarkRetired(ctx, step(old), receipt(s, old, "retired")); return e }, "commit": func() error { _, e := s.Commit(ctx, step(o), receipt(s, o, "commit")); return e }, "prepare": func() error { _, e := s.MarkPrepared(ctx, step(o), receipt(s, o, "prepared")); return e }} {
		t.Run(name, func(t *testing.T) {
			if e := call(); !errors.Is(e, ErrConflict) {
				t.Fatal("tombstone bypass", e)
			}
		})
	}
	o = abandonFinish(t, s, o)
	s = reopen(t, s, p)
	target, e := s.ReadTarget(ctx, "agent")
	if e != nil || target.ActiveVersionID != "" || target.OperationID != "" || target.Availability != "unavailable" {
		t.Fatal("terminal projection", e, target)
	}
	if o.FrozenSource.ID != first.Version.ID {
		t.Fatal("lost frozen predecessor")
	}
	if got := begin(t, s, old.Request); got.Phase != "abandoned-unavailable" {
		t.Fatal("terminal exact retry")
	}
	changed := ar
	changed.Reason = "changed"
	if _, e = s.StartAbandon(ctx, changed); !errors.Is(e, ErrConflict) {
		t.Fatal("terminal abandon key changed", e)
	}
	collision := recoveryRequest(t, s, o, ar.Key)
	if _, e = s.Begin(ctx, collision); !errors.Is(e, ErrConflict) {
		t.Fatal("cross-kind key collision", e)
	}
	ar2 := ar
	ar2.Key = old.Request.Key
	if _, e = s.StartAbandon(ctx, ar2); !errors.Is(e, ErrConflict) {
		t.Fatal("begin key reused by abandon", e)
	}
	reuse := request(register(t, s, "other"), "reuse")
	reuse.DecisionRecord = ar.Authority.DecisionRecord
	reuse.Subject = ar.Authority.Subject
	reuse.DecisionRecord.Request.Action = "accept"
	reuse.DecisionRecord.Authorization.Action = "accept"
	reuse.DecisionRecord.Authorization.Role = "Agent.Approver"
	if _, e = s.Begin(ctx, reuse); !errors.Is(e, ErrConflict) {
		t.Fatal("operator decision claim reused", e)
	}
}
func TestAbandonIncompleteFencing(t *testing.T) {
	s, _ := newStore(t)
	_, o := pendingWithPredecessor(t, s)
	a := abandonRequest(s, o, "bad-authority")
	a.Authority.Action = "accept"
	if _, e := s.StartAbandon(ctx, a); e == nil {
		t.Fatal("activation authority can abandon")
	}
	o = abandonStart(t, s, o, "abandon")
	p, n := abandonReceipts(s, o)
	for name, change := range map[string]func(*Receipt, *Receipt){"missing predecessor": func(p, n *Receipt) { *p = Receipt{} }, "missing successor": func(p, n *Receipt) { *n = Receipt{} }, "wrong predecessor": func(p, n *Receipt) { p.Predecessor.ID = "absent" }, "no source lie": func(p, n *Receipt) { p.Kind = "abandon_no_source" }, "unknown successor": func(p, n *Receipt) { n.EvidenceDigest = "" }, "cleanup capability": func(p, n *Receipt) { n.IntentID = "other" }, "old retirement": func(p, n *Receipt) { p.Kind = "retired" }} {
		t.Run(name, func(t *testing.T) {
			p, n := p, n
			change(&p, &n)
			if _, e := s.FinishAbandon(ctx, step(o), p, n); e == nil {
				t.Fatal("unproven fence finalized")
			}
			got, e := s.ReadOperation(ctx, o.ID)
			if e != nil || got.Phase != "abandoning" {
				t.Fatal(e, got.Phase)
			}
		})
	}
	if _, e := s.Commit(ctx, step(o), n); !errors.Is(e, ErrConflict) {
		t.Fatal("cleanup used to commit", e)
	}
	for _, phase := range []string{"preparing", "prepared", "aborting"} {
		t.Run(phase, func(t *testing.T) {
			target := register(t, s, phase)
			v := begin(t, s, request(target, "a-"+phase))
			if phase == "prepared" {
				v = prepared(t, s, v)
			}
			if phase == "aborting" {
				out, e := s.StartAbort(ctx, step(v), "cancel")
				v = must(t, out, e)
			}
			if _, e := s.StartAbandon(ctx, abandonRequest(s, v, "ab-"+phase)); !errors.Is(e, ErrConflict) {
				t.Fatal("preboundary abandon", e)
			}
		})
	}
}
func TestRecoveryExactPredecessorAndFreshIdentity(t *testing.T) {
	s, p := newStore(t)
	first, o := pendingWithPredecessor(t, s)
	o = abandonFinish(t, s, abandonStart(t, s, o, "abandon"))
	r := recoveryRequest(t, s, o, "recover")
	for name, change := range map[string]func(*Request){"candidate substitute": func(r *Request) {
		r.Candidate = o.Request.Candidate
		r.Candidate.Artifact.SuiteDigest = strings.Repeat("b", 64)
		r.Candidate.Qualification.Artifact = r.Candidate.Artifact
	}, "source": func(r *Request) { r.SourceVersionID = o.Version.ID }, "operator action": func(r *Request) { r.DecisionRecord.Authorization.Action = "abandon_activation" }, "stale Q": func(r *Request) { r.Candidate.Artifact.Runtime = "new" }, "mutated Q identity": func(r *Request) {
		r.Candidate = clone(first.Request.Candidate)
		r.Candidate.Artifact.Runtime = "new"
		r.Candidate.Qualification.Artifact = r.Candidate.Artifact
		r.Candidate.Qualification.Digest = strings.Repeat("b", 64)
	}, "fix forward": func(r *Request) {
		r.Intent = "activate"
		r.DecisionRecord.Request.Action = "accept"
		r.DecisionRecord.Authorization.Action = "accept"
	}} {
		t.Run(name, func(t *testing.T) {
			bad := clone(r)
			change(&bad)
			if _, e := s.Begin(ctx, bad); e == nil {
				t.Fatal("bad recovery accepted")
			}
		})
	}
	// Retained bytes/source stay equal; a fresh qualification may change execution context.
	r.Candidate.Artifact.Runtime = "new-runtime"
	r.Candidate.Artifact.Model = "new-model"
	r.Candidate.Artifact.BindingDigest = strings.Repeat("b", 64)
	r.Candidate.Qualification.Artifact = r.Candidate.Artifact
	r.Candidate.Qualification.Digest = strings.Repeat("b", 64)
	recovered := begin(t, s, r)
	if recovered.Version.ID == first.Version.ID || recovered.Version.ExecutionContextID == first.Version.ExecutionContextID {
		t.Fatal("reused identity")
	}
	if again := begin(t, s, r); again.ID != recovered.ID {
		t.Fatal("duplicate recovery allocated")
	}
	recovered = prepared(t, s, recovered)
	recovered = reserved(t, s, recovered)
	bad := receipt(s, recovered, "retired")
	if _, e := s.MarkRetired(ctx, step(recovered), bad); e == nil {
		t.Fatal("recovery used ordinary retirement")
	}
	bad = receipt(s, recovered, "already_retired")
	bad.PredecessorEvidence = strings.Repeat("c", 64)
	if _, e := s.MarkRetired(ctx, step(recovered), bad); e == nil {
		t.Fatal("wrong terminal proof")
	}
	recovered = retired(t, s, recovered)
	v, e := s.Commit(ctx, step(recovered), receipt(s, recovered, "commit"))
	recovered = must(t, v, e)
	s = reopen(t, s, p)
	target, e := s.ReadTarget(ctx, "agent")
	if e != nil || target.ActiveVersionID != recovered.Version.ID {
		t.Fatal(e, target)
	}
}
func TestRepeatedRecoverySource(t *testing.T) {
	s, p := newStore(t)
	first, o := pendingWithPredecessor(t, s)
	o = abandonFinish(t, s, abandonStart(t, s, o, "abandon"))
	r := begin(t, s, recoveryRequest(t, s, o, "recovery1"))
	r = reserved(t, s, prepared(t, s, r))
	r = abandonFinish(t, s, abandonStart(t, s, r, "abandon2"))
	s = reopen(t, s, p)
	again := begin(t, s, recoveryRequest(t, s, r, "recovery2"))
	if again.FrozenSource == nil || again.FrozenSource.ID != first.Version.ID {
		t.Fatal("chain lost", again)
	}
	committed(t, s, again)
}
func TestRollbackRetainedSource(t *testing.T) {
	s, p := newStore(t)
	first, second := pendingWithPredecessor(t, s)
	second = retired(t, s, second)
	v, e := s.Commit(ctx, step(second), receipt(s, second, "commit"))
	second = must(t, v, e)
	r := activeRequest(t, s, "agent", "rollback")
	r.Intent = "rollback"
	r.SourceVersionID = first.Version.ID
	r.Candidate = clone(first.Version.Candidate)
	r.DecisionRecord.Request.Action = "rollback"
	r.DecisionRecord.Authorization.Action = "rollback"
	other := committed(t, s, begin(t, s, request(register(t, s, "other"), "other")))
	for name, change := range map[string]func(*Request){"foreign": func(r *Request) { r.SourceVersionID = other.Version.ID }, "missing": func(r *Request) { r.SourceVersionID = "absent" }, "current not historical": func(r *Request) { r.SourceVersionID = second.Version.ID }, "provenance": func(r *Request) { r.Candidate.SourceDigest = strings.Repeat("b", 64) }, "cases": func(r *Request) {
		r.Candidate.Artifact.CasesDigest = strings.Repeat("b", 64)
		r.Candidate.Qualification.Artifact = r.Candidate.Artifact
	}, "Q identity": func(r *Request) {
		r.Candidate.Artifact.Runtime = "new"
		r.Candidate.Qualification.Artifact = r.Candidate.Artifact
	}} {
		t.Run(name, func(t *testing.T) {
			bad := clone(r)
			change(&bad)
			if _, e := s.Begin(ctx, bad); e == nil {
				t.Fatal("invalid rollback accepted")
			}
		})
	}
	r.Candidate.Artifact.Runtime = "fresh"
	r.Candidate.Qualification.Artifact = r.Candidate.Artifact
	r.Candidate.Qualification.ID = "fresh-rollback"
	r.Candidate.Qualification.Digest = strings.Repeat("c", 64)
	rollback := committed(t, s, begin(t, s, r))
	if rollback.FrozenSource.ID != second.Version.ID {
		t.Fatal("abandonment source must be current predecessor, not rollback candidate source")
	}
	s = reopen(t, s, p)
	var n int
	e = s.db.QueryRow("SELECT count(*) FROM links WHERE kind='source' AND from_id=? AND to_id=?", first.Version.ID, rollback.Version.ID).Scan(&n)
	if e != nil || n != 1 {
		t.Fatal("source link lost", e, n)
	}
}
func TestGenesisAbandonFreshActivate(t *testing.T) {
	s, p := newStore(t)
	o := reserved(t, s, prepared(t, s, begin(t, s, request(register(t, s, "agent"), "genesis"))))
	old := o
	o = abandonFinish(t, s, abandonStart(t, s, o, "abandon"))
	s = reopen(t, s, p)
	if o.FrozenSource != nil {
		t.Fatal("invented source")
	}
	if _, e := s.Commit(ctx, step(old), receipt(s, old, "commit")); !errors.Is(e, ErrConflict) {
		t.Fatal("old commit", e)
	}
	r := recoveryRequest(t, s, o, "fresh-initial")
	for _, intent := range []string{"recover", "rollback"} {
		bad := clone(r)
		bad.Intent = intent
		bad.DecisionRecord.Request.Action = intent
		bad.DecisionRecord.Authorization.Action = intent
		if _, e := s.Begin(ctx, bad); e == nil {
			t.Fatal("genesis recovery/rollback accepted")
		}
	}
	bad := clone(r)
	bad.Predecessor = old.Request.Predecessor
	if _, e := s.Begin(ctx, bad); e == nil {
		t.Fatal("terminal bypassed through genesis")
	}
	next := committed(t, s, begin(t, s, r))
	if next.Version.ExecutionContextID == old.Version.ExecutionContextID {
		t.Fatal("context reused")
	}
}
func TestRecoveryAbortRetry(t *testing.T) {
	s, p := newStore(t)
	_, o := pendingWithPredecessor(t, s)
	o = abandonFinish(t, s, abandonStart(t, s, o, "abandon"))
	r := recoveryRequest(t, s, o, "attempt1")
	attempt := begin(t, s, r)
	v, e := s.StartAbort(ctx, step(attempt), "cancel")
	attempt = must(t, v, e)
	v, e = s.FinishAbort(ctx, step(attempt), receipt(s, attempt, "release"), false)
	attempt = must(t, v, e)
	s = reopen(t, s, p)
	target, e := s.ReadTarget(ctx, "agent")
	if e != nil || target.Availability != "unavailable" || target.ActiveVersionID != "" {
		t.Fatal("abort thawed terminal", e, target)
	}
	again := begin(t, s, recoveryRequest(t, s, o, "attempt2"))
	if again.ID == attempt.ID {
		t.Fatal("new key not new attempt")
	}
	var n int
	e = s.db.QueryRow("SELECT count(*) FROM links WHERE kind='attempt' AND from_id=?", o.Abandonment.ID).Scan(&n)
	if e != nil || n != 2 {
		t.Fatal("attempt links overwritten", e, n)
	}
}
