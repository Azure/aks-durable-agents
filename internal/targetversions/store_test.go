package targetversions

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var ctx = context.Background()
var digest = strings.Repeat("a", 64)

func must[T any](t *testing.T, v T, err error) T {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func clone[T any](v T) T { b, _ := json.Marshal(v); var c T; _ = json.Unmarshal(b, &c); return c }
func privateTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}
func newStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := filepath.Join(privateTempDir(t), "private")
	p := filepath.Join(dir, "versions.db")
	s, e := Create(p)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return s, p
}
func register(t *testing.T, s *Store, id string) Target {
	t.Helper()
	v, e := s.RegisterTarget(ctx, id)
	return must(t, v, e)
}
func request(target Target, key string) Request {
	a := ArtifactTuple{SuiteDigest: digest, Member: "agent", Composition: "none", Platform: "linux-amd64", InventoryDigest: digest, CasesDigest: digest, Harness: "h1", Runtime: "r1", Model: "m1", ModelConfig: digest, Judge: "j1", JudgeSettings: digest, BindingDigest: digest}
	ref := SubjectRef{Workspace: "workspace", Kind: "suite_version", ID: "proposal-" + key, Generation: 1, Digest: digest}
	actor := Identity{Issuer: "issuer", Subject: "person"}
	d := DecisionRecord{ID: "decision-" + key, StoreID: "decisions", HostLineageID: "host", Request: DecideRequest{Workspace: "workspace", Key: key, Subject: ref, Action: "accept"}, RequestDigest: digest, Actor: actor, Outcome: "recorded", Authorization: &DecisionAuthorization{Actor: actor, Subject: ref, Action: "accept", Role: "Agent.Approver", PolicyVersion: "p1", GrantIDs: []string{"grant"}}, CommittedAt: time.Now().UTC().Add(-time.Minute), Mode: "non_executing_decision_v1"}
	return Request{TargetID: target.ID, Key: key, ExpectedRevision: target.Revision, Predecessor: PredecessorRef{Kind: "genesis", ID: target.GenesisID}, Intent: "activate", Candidate: Candidate{Artifact: a, SourceDigest: digest, Qualification: Qualification{ID: "q-" + key, StoreID: "qualifications", Digest: digest, EvidenceDigest: digest, JournalsDigest: digest, Artifact: a, PolicyVersion: "p1", Complete: true, Passed: true, Eligible: true}}, Subject: ref, DecisionRecord: d}
}
func begin(t *testing.T, s *Store, r Request) Operation {
	t.Helper()
	v, e := s.Begin(ctx, r)
	return must(t, v, e)
}
func TestStoreCreateOpenIntegrity(t *testing.T) {
	s, p := newStore(t)
	id := s.ID
	target := register(t, s, "agent")
	if target.Revision != 1 || target.ActiveVersionID != "" || target.Availability != "unavailable" {
		t.Fatalf("genesis: %+v", target)
	}
	if got := register(t, s, "agent"); got != target {
		t.Fatal("duplicate register changed genesis")
	}
	for i := 0; i < 2; i++ {
		if i == 1 {
			s.db.SetMaxIdleConns(0)
		}
		for pragma, want := range map[string]string{"foreign_keys": "1", "synchronous": "3", "journal_mode": "delete"} {
			var got string
			if e := s.db.QueryRow("PRAGMA " + pragma).Scan(&got); e != nil || got != want {
				t.Fatalf("replacement %d %s=%s (%v)", i, pragma, got, e)
			}
		}
	}
	s.Close()
	reopened, e := Open(p, id)
	if e != nil {
		t.Fatal(e)
	}
	reopened.Close()
	if _, e = Create(p); e == nil {
		t.Fatal("Create adopted existing file")
	}
	if _, e = Open(p, "wrong"); !errors.Is(e, ErrIntegrity) {
		t.Fatalf("lineage: %v", e)
	}
	if _, e = Open(filepath.Join(filepath.Dir(p), "missing.db"), id); e == nil {
		t.Fatal("Open created missing store")
	}
	for _, mode := range []os.FileMode{0644, 0600} {
		bad := filepath.Join(filepath.Dir(p), "bad.db")
		if e := os.WriteFile(bad, nil, mode); e != nil {
			t.Fatal(e)
		}
		if _, e = Open(bad, id); e == nil {
			t.Fatal("opened empty/unsafe file")
		}
		os.Remove(bad)
	}
	link := filepath.Join(filepath.Dir(p), "link.db")
	if e := os.Symlink(p, link); e != nil {
		t.Fatal(e)
	}
	if _, e = Open(link, id); e == nil {
		t.Fatal("followed symlink")
	}
	db, e := sql.Open("sqlite", p)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	if _, e = db.Exec("UPDATE metadata SET schema_version=2"); e != nil {
		t.Fatal(e)
	}
	if _, e = Open(p, id); !errors.Is(e, ErrUnsupported) {
		t.Fatalf("future schema: %v", e)
	}
}
func TestBeginExactKeyAndConflict(t *testing.T) {
	s, p := newStore(t)
	target := register(t, s, "agent")
	r := request(target, "a")
	op := begin(t, s, r)
	if op.ID == "" || op.Version.ID == "" || op.Version.ExecutionContextID == "" || op.Generation != 1 || op.Phase != "preparing" {
		t.Fatalf("allocation: %+v", op)
	}
	got, e := s.Begin(ctx, r)
	if e != nil || got.ID != op.ID {
		t.Fatalf("retry: %v %+v", e, got)
	}
	for name, change := range map[string]func(*Request){"tuple": func(r *Request) { r.Candidate.Artifact.Runtime = "changed" }, "Q": func(r *Request) { r.Candidate.Qualification.Digest = strings.Repeat("b", 64) }, "E": func(r *Request) { r.DecisionRecord.ID = "other" }, "actor": func(r *Request) { r.DecisionRecord.Actor.Subject = "other" }, "predecessor": func(r *Request) { r.Predecessor.ID = "other" }, "intent": func(r *Request) { r.Intent = "recover" }, "source": func(r *Request) { r.SourceVersionID = "other" }, "subject": func(r *Request) { r.Subject.ID = "other" }} {
		t.Run(name, func(t *testing.T) {
			c := clone(r)
			change(&c)
			if _, e = s.Begin(ctx, c); !errors.Is(e, ErrConflict) {
				t.Fatalf("changed exact key: %v", e)
			}
		})
	}
	s.Close()
	s2, e := Open(p, s.ID)
	if e != nil {
		t.Fatal(e)
	}
	defer s2.Close()
	if got := begin(t, s2, r); got.ID != op.ID {
		t.Fatal("restart allocated another op")
	}
}
func TestBeginTargetCASAndOccupied(t *testing.T) {
	s, _ := newStore(t)
	target := register(t, s, "agent")
	stale := request(target, "stale")
	stale.ExpectedRevision++
	if _, e := s.Begin(ctx, stale); !errors.Is(e, ErrConflict) {
		t.Fatalf("CAS: %v", e)
	}
	r := request(target, "a")
	begin(t, s, r)
	if _, e := s.Begin(ctx, request(target, "b")); !errors.Is(e, ErrOccupied) {
		t.Fatalf("occupied: %v", e)
	}
	other := register(t, s, "other")
	reuse := request(other, "c")
	reuse.DecisionRecord = r.DecisionRecord
	reuse.Subject = r.Subject
	if _, e := s.Begin(ctx, reuse); !errors.Is(e, ErrConflict) {
		t.Fatalf("cross-target decision claim: %v", e)
	}
	for name, change := range map[string]func(*Request){"empty": func(r *Request) { r.Candidate.Artifact.Composition = "" }, "digest": func(r *Request) { r.Candidate.Artifact.SuiteDigest = "bad" }, "key": func(r *Request) { r.Key = strings.Repeat("x", 129) }, "Q mismatch": func(r *Request) { r.Candidate.Qualification.Artifact.Runtime = "other" }, "denied": func(r *Request) { r.DecisionRecord.Outcome = "refused" }} {
		t.Run(name, func(t *testing.T) {
			r := request(other, strings.ReplaceAll(name, " ", "-"))
			change(&r)
			if _, e := s.Begin(ctx, r); !errors.Is(e, ErrInvalid) {
				t.Fatal("wrong invalid request classification", e)
			}
		})
	}
}
