package qualification

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func digest(c string) string { return "sha256:" + strings.Repeat(c, 64) }
func testPlan() Plan {
	return Plan{Subject: Subject{Workspace: "workspace", Target: "target", SuiteDigest: digest("a"), BindingDigest: digest("b"), ProfileDigest: digest("c"), ModelDigest: digest("d"), JudgeDigest: digest("e"), PolicyDigest: digest("f")}, Members: []Member{{ID: "agent", Digest: digest("1")}}, MemberID: "agent", CompositionDigest: digest("2"), Platform: "linux/amd64", IndexDigest: digest("3"), ExpiresAt: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC), Cases: []Case{{ID: "case", Digest: digest("4"), InputDigest: hashBytes([]byte("question")), Runs: 1, MinPasses: 1, Assertions: []Assertion{{ID: "answer", Kind: "contains", Value: "hello"}}}}}
}
func privateTestDir(t *testing.T) string {
	t.Helper()
	// Model operator-prepared private storage rather than inheriting the
	// process umask applied to testing.TempDir's numbered directories.
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}
func testStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := filepath.Join(privateTestDir(t), "qualification")
	s, err := Create(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, dir
}
func admit(t *testing.T, s *Store) Record {
	t.Helper()
	r, err := s.Admit(context.Background(), Request{Key: "key", Requester: "caller", Plan: testPlan()})
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func TestAdmissionExactKey(t *testing.T) {
	s, dir := testStore(t)
	ctx := context.Background()
	r := admit(t, s)
	r.Request.Plan.Cases[0].ID = "caller-mutated-copy"
	got, err := s.Read(ctx, r.ID)
	if err != nil || got.Request.Plan.Cases[0].ID != "case" {
		t.Fatalf("read mutated: %+v %v", got, err)
	}
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			same, e := s.Admit(ctx, Request{Key: "key", Requester: "caller", Plan: testPlan()})
			if e != nil || same.ID != r.ID {
				t.Errorf("duplicate: %s %v", same.ID, e)
			}
		})
	}
	wg.Wait()
	for name, change := range map[string]func(*Request){"requester": func(r *Request) { r.Requester = "other" }, "suite": func(r *Request) { r.Plan.Subject.SuiteDigest = digest("9") }, "binding": func(r *Request) { r.Plan.Subject.BindingDigest = digest("9") }, "case": func(r *Request) { r.Plan.Cases[0].Digest = digest("9") }} {
		t.Run(name, func(t *testing.T) {
			req := Request{Key: "key", Requester: "caller", Plan: testPlan()}
			change(&req)
			_, e := s.Admit(ctx, req)
			if !errors.Is(e, ErrConflict) {
				t.Fatalf("want conflict, got %v", e)
			}
		})
	}
	lineage := s.Lineage()
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(dir, lineage)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	same, err := s.Admit(ctx, Request{Key: "key", Requester: "caller", Plan: testPlan()})
	if err != nil || same.ID != r.ID {
		t.Fatalf("restart duplicate: %+v %v", same, err)
	}
}
func TestStoreLifecycleStorage(t *testing.T) {
	s, dir := testStore(t)
	ctx := context.Background()
	r := admit(t, s)
	if _, err := Open(dir, s.Lineage()); !errors.Is(err, ErrBusy) {
		t.Fatalf("second writer: %v", err)
	}
	l, err := s.start(ctx, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	stopped, err := s.interrupt(ctx, l)
	if err != nil || stopped.State != Incomplete || stopped.Generation <= l.Generation {
		t.Fatalf("interrupt: %+v %v", stopped, err)
	}
	again, err := s.interrupt(ctx, l)
	if err != nil || again.Digest != stopped.Digest {
		t.Fatalf("interrupt retry: %+v %v", again, err)
	}
	if _, err = s.start(ctx, r.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("restart terminal: %v", err)
	}
	lineage := s.Lineage()
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(dir, "records.db"))
	for _, wrong := range []string{"", "wrong-lineage"} {
		if _, e := Open(dir, wrong); !errors.Is(e, ErrIntegrity) {
			t.Fatalf("wrong lineage: %v", e)
		}
	}
	after, _ := os.ReadFile(filepath.Join(dir, "records.db"))
	if !reflect.DeepEqual(before, after) {
		t.Fatal("refused Open changed database")
	}
	s, err = Open(dir, lineage)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	saved, err := s.Read(ctx, r.ID)
	if err != nil || saved.Digest != stopped.Digest {
		t.Fatalf("readback: %+v %v", saved, err)
	}
}
func TestAdmissionBounds(t *testing.T) {
	s, _ := testStore(t)
	for name, change := range map[string]func(*Plan){"empty": func(p *Plan) { p.Cases = nil }, "duplicate": func(p *Plan) { p.Cases = append(p.Cases, p.Cases[0]) }, "slots": func(p *Plan) { p.Cases[0].Runs = 65 }, "unknown": func(p *Plan) { p.Cases[0].Assertions[0].Kind = "extension" }, "regex": func(p *Plan) { p.Cases[0].Assertions[0] = Assertion{ID: "answer", Kind: "regex", Value: "["} }, "selection": func(p *Plan) { p.MemberID = "missing" }, "digest": func(p *Plan) { p.Subject.BindingDigest = "fake" }} {
		t.Run(name, func(t *testing.T) {
			p := testPlan()
			change(&p)
			_, err := s.Admit(context.Background(), Request{Key: name, Requester: "caller", Plan: p})
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("want invalid, got %v", err)
			}
		})
	}
}
