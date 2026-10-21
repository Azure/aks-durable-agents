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
	"github.com/agent-primitives/sessions/api"
	"github.com/agent-primitives/sessions/authn"
)

type humanKey struct{}
type requestVerifier struct{}

func (requestVerifier) VerifyHuman(ctx context.Context) (entraauth.VerifiedHuman, error) {
	h, ok := ctx.Value(humanKey{}).(entraauth.VerifiedHuman)
	if !ok {
		return h, ErrUnauthenticated
	}
	return h, nil
}
func humanContext(name string, until time.Time) context.Context {
	return context.WithValue(context.Background(), humanKey{}, entraauth.VerifiedHuman{Caller: authn.VerifiedCaller{Identity: api.CallerIdentity{Issuer: "issuer", Subject: name}, ValidUntil: until}, Roles: []string{"Approver"}})
}

type testPolicy struct {
	mu                 sync.Mutex
	denied, readDenied bool
	before             func()
	corrupt            bool
}

func (p *testPolicy) AuthorizeRead(_ context.Context, _ entraauth.VerifiedHuman, s Subject) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.readDenied || s.Workspace != "workspace" || s.Resource != "target" {
		return ErrDenied
	}
	return nil
}
func (p *testPolicy) WithDecision(_ context.Context, h entraauth.VerifiedHuman, s Subject, a Action, commit func(Authorization) error) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.before != nil {
		p.before()
	}
	if p.denied {
		return ErrDenied
	}
	ref, _ := s.Reference()
	auth := Authorization{Actor: h.Caller.Identity, Subject: ref, Action: a, Role: "Approver", PolicyVersion: "policy1", GrantIDs: []string{"grant"}}
	if p.corrupt {
		auth.Subject.Digest = testDigest
	}
	return commit(auth)
}
func serviceFixture(t *testing.T) (*Store, *Service, *testPolicy, DecideRequest) {
	t.Helper()
	s := newTestStore(t)
	p := &testPolicy{}
	svc, err := NewService(s, requestVerifier{}, p)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := s.RegisterSubject(context.Background(), suiteSubject())
	if err != nil {
		t.Fatal(err)
	}
	return s, svc, p, DecideRequest{Workspace: ref.Workspace, Key: "key", Subject: ref, Action: Accept}
}
func TestServiceRequestNamespacesAndReadPolicy(t *testing.T) {
	_, svc, p, r := serviceFixture(t)
	a := humanContext("alice", time.Now().Add(time.Hour))
	b := humanContext("bob", time.Now().Add(time.Hour))
	p.denied = true
	rb, err := svc.Decide(b, r)
	if err != nil || rb.Outcome != "refused" {
		t.Fatalf("refusal: %+v %v", rb, err)
	}
	p.denied = false
	ra, err := svc.Decide(a, r)
	if err != nil || ra.Outcome != "recorded" || ra.Actor.Subject != "alice" || ra.ID == rb.ID {
		t.Fatalf("poisoned key: %+v %v", ra, err)
	}
	for _, ctx := range []context.Context{a, b} {
		got, err := svc.Get(ctx, r.Workspace, r.Key)
		if err != nil || got.Actor != ctx.Value(humanKey{}).(entraauth.VerifiedHuman).Caller.Identity {
			t.Fatalf("foreign disclosure: %+v %v", got, err)
		}
	}
	r.Feedback = "changed"
	if _, err := svc.Decide(a, r); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed payload: %v", err)
	}
	p.readDenied = true
	if _, err := svc.Get(a, r.Workspace, r.Key); !errors.Is(err, ErrDenied) {
		t.Fatalf("revoked read: %v", err)
	}
	if _, err := svc.Get(context.Background(), r.Workspace, r.Key); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("missing identity: %v", err)
	}
}
func TestConcurrentHumanDecisionCAS(t *testing.T) {
	_, svc, _, r := serviceFixture(t)
	start := make(chan struct{})
	var recorded, refused atomic.Int32
	var wg sync.WaitGroup
	for _, name := range []string{"alice", "bob"} {
		wg.Go(func() {
			<-start
			req := r
			req.Key = name
			if name == "bob" {
				req.Action = Reject
			}
			out, err := svc.Decide(humanContext(name, time.Now().Add(time.Hour)), req)
			if err != nil {
				t.Errorf("decide: %v", err)
				return
			}
			if out.Outcome == "recorded" {
				recorded.Add(1)
			} else if out.RefusalCode == "subject_closed" {
				refused.Add(1)
			}
		})
	}
	close(start)
	wg.Wait()
	if recorded.Load() != 1 || refused.Load() != 1 {
		t.Fatalf("contradictory decisions: recorded=%d refused=%d", recorded.Load(), refused.Load())
	}
}
func TestHumanRejectionIsNotHostRefusal(t *testing.T) {
	for _, action := range []Action{Reject, RequestChanges} {
		t.Run(string(action), func(t *testing.T) {
			_, svc, _, r := serviceFixture(t)
			r.Action = action
			out, err := svc.Decide(humanContext("alice", time.Now().Add(time.Hour)), r)
			if err != nil || out.Outcome != "recorded" || out.Request.Action != action || out.RefusalCode != "" {
				t.Fatalf("rejection: %+v %v", out, err)
			}
		})
	}
	for _, action := range []Action{Approve, Deny} {
		t.Run(string(action), func(t *testing.T) {
			s := newTestStore(t)
			ref, _ := s.RegisterSubject(context.Background(), effectSubject())
			svc, _ := NewService(s, requestVerifier{}, &testPolicy{})
			out, err := svc.Decide(humanContext("alice", time.Now().Add(time.Hour)), DecideRequest{Workspace: ref.Workspace, Key: "key", Subject: ref, Action: action})
			if err != nil || out.Outcome != "recorded" {
				t.Fatalf("effect: %+v %v", out, err)
			}
		})
	}
}
func TestServiceExpiryAfterPolicyAndDatabaseWaits(t *testing.T) {
	for _, wait := range []string{"policy", "database"} {
		t.Run(wait, func(t *testing.T) {
			s, svc, p, r := serviceFixture(t)
			var now atomic.Int64
			now.Store(time.Date(2029, 1, 1, 0, 0, 0, 0, time.UTC).Unix())
			s.now = func() time.Time { return time.Unix(now.Load(), 0) }
			until := s.now().Add(time.Second)
			ctx := humanContext("alice", until)
			entered, release := make(chan struct{}), make(chan struct{})
			p.before = func() { close(entered); <-release }
			var held *sql.Conn
			waits := s.db.Stats().WaitCount
			if wait == "database" {
				p.before = func() {
					var err error
					held, err = s.db.Conn(context.Background())
					if err != nil {
						t.Error(err)
					}
					close(entered)
					<-release
				}
			}
			done := make(chan error, 1)
			go func() { _, err := svc.Decide(ctx, r); done <- err }()
			// Both initial credential and visibility checks have completed.
			<-entered
			if wait == "database" {
				if held == nil {
					t.Fatal("no held connection")
				}
				defer held.Close()
				close(release)
				deadline := time.NewTimer(5 * time.Second)
				defer deadline.Stop()
				for s.db.Stats().WaitCount == waits {
					select {
					case <-deadline.C:
						t.Fatal("decision never waited for DB connection")
					default:
						runtime.Gosched()
					}
				}
				now.Add(2)
				held.Close()
			} else {
				now.Add(2)
				close(release)
			}
			if err := <-done; !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("expired request: %v", err)
			}
			if _, err := s.lookup(context.Background(), ctx.Value(humanKey{}).(entraauth.VerifiedHuman).Caller.Identity, r.Workspace, r.Key); !errors.Is(err, ErrNotFound) {
				t.Fatalf("expiry wrote record: %v", err)
			}
		})
	}
}
func TestPolicySnapshotCannotWidenAuthority(t *testing.T) {
	_, svc, p, r := serviceFixture(t)
	p.corrupt = true
	if _, err := svc.Decide(humanContext("alice", time.Now().Add(time.Hour)), r); !errors.Is(err, ErrDenied) {
		t.Fatalf("forged snapshot: %v", err)
	}
	p.corrupt = false
	r.Action = "continue"
	out, err := svc.Decide(humanContext("alice", time.Now().Add(time.Hour)), r)
	if err != nil || out.RefusalCode != "invalid_action" {
		t.Fatalf("Continue accepted: %+v %v", out, err)
	}
}
func TestInvisibleSubjectsDoNotExposeExistence(t *testing.T) {
	_, svc, p, r := serviceFixture(t)
	p.readDenied = true
	ctx := humanContext("alice", time.Now().Add(time.Hour))
	for _, change := range []func(*DecideRequest){func(*DecideRequest) {}, func(r *DecideRequest) { r.Subject.ID = "missing" }, func(r *DecideRequest) { r.Subject.Digest = testDigest }} {
		req := r
		change(&req)
		if _, err := svc.Decide(ctx, req); !errors.Is(err, ErrDenied) {
			t.Fatalf("subject existence disclosed: %v", err)
		}
	}
}

func TestCancelledRequestAndExpiredSubject(t *testing.T) {
	s, svc, _, r := serviceFixture(t)
	ctx, cancel := context.WithCancel(humanContext("alice", time.Now().Add(time.Hour)))
	cancel()
	if _, err := svc.Decide(ctx, r); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled: %v", err)
	}
	now := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	out, err := svc.Decide(humanContext("alice", now.Add(time.Hour)), r)
	if err != nil || out.RefusalCode != "subject_expired" {
		t.Fatalf("expired subject: %+v %v", out, err)
	}
}
