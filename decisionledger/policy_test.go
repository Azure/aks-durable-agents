package decisionledger

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Azure/aks-durable-agents/entraauth"
)

type callbackPolicy struct {
	read   func() error
	decide func(entraauth.VerifiedHuman, Subject, Action, func(Authorization) error) error
}

func (p callbackPolicy) AuthorizeRead(context.Context, entraauth.VerifiedHuman, Subject) error {
	if p.read != nil {
		return p.read()
	}
	return nil
}
func (p callbackPolicy) WithDecision(_ context.Context, h entraauth.VerifiedHuman, s Subject, a Action, fn func(Authorization) error) error {
	return p.decide(h, s, a, fn)
}
func snapshot(h entraauth.VerifiedHuman, s Subject, a Action) Authorization {
	ref, _ := s.Reference()
	return Authorization{Actor: h.Caller.Identity, Subject: ref, Action: a, Role: "Approver", PolicyVersion: "policy", GrantIDs: []string{"grant"}}
}

func TestPostCommitReadFailureIsUncertain(t *testing.T) {
	for _, reason := range []string{"revocation", "expiry", "outage"} {
		t.Run(reason, func(t *testing.T) {
			s, _, _, r := serviceFixture(t)
			now := time.Date(2029, 1, 1, 0, 0, 0, 0, time.UTC)
			s.now = func() time.Time { return now }
			until := now.Add(time.Hour)
			ctx := humanContext("alice", until)
			reads := 0
			policy := callbackPolicy{read: func() error {
				reads++
				if reads == 2 {
					switch reason {
					case "expiry":
						now = until
					case "revocation":
						return ErrDenied
					case "outage":
						return errors.New("private policy error")
					}
				}
				return nil
			}, decide: func(h entraauth.VerifiedHuman, s Subject, a Action, fn func(Authorization) error) error {
				return fn(snapshot(h, s, a))
			}}
			svc, _ := NewService(s, requestVerifier{}, policy)
			if _, err := svc.Decide(ctx, r); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("post-commit %s looked definitive: %v", reason, err)
			}
			got, err := s.lookup(context.Background(), ctx.Value(humanKey{}).(entraauth.VerifiedHuman).Caller.Identity, r.Workspace, r.Key)
			if err != nil || got.Outcome != "recorded" {
				t.Fatalf("decision lost: %+v %v", got, err)
			}
		})
	}
}
func TestReadPolicyOutageIsNotDenial(t *testing.T) {
	_, svc, _, r := serviceFixture(t)
	ctx := humanContext("alice", time.Now().Add(time.Hour))
	if _, err := svc.Decide(ctx, r); err != nil {
		t.Fatal(err)
	}
	svc.policy = callbackPolicy{read: func() error { return errors.New("private network diagnostic") }}
	if _, err := svc.Get(ctx, r.Workspace, r.Key); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("outage: %v", err)
	}
}
func TestPolicyCallbackContract(t *testing.T) {
	for _, mode := range []string{"no callback", "policy outage", "after return", "twice", "hidden commit failure"} {
		t.Run(mode, func(t *testing.T) {
			s, _, _, r := serviceFixture(t)
			ctx := humanContext("alice", time.Now().Add(time.Hour))
			var later func(Authorization) error
			var auth Authorization
			policy := callbackPolicy{decide: func(h entraauth.VerifiedHuman, subject Subject, a Action, fn func(Authorization) error) error {
				auth = snapshot(h, subject, a)
				switch mode {
				case "no callback":
					return nil
				case "policy outage":
					return errors.New("private service error")
				case "after return":
					later = fn
					return nil
				case "twice":
					if err := fn(auth); err != nil {
						return err
					}
					return fn(auth)
				case "hidden commit failure":
					bad := auth
					bad.Actor.Subject = "forged"
					_ = fn(bad)
					return nil
				}
				panic("mode")
			}}
			svc, _ := NewService(s, requestVerifier{}, policy)
			_, err := svc.Decide(ctx, r)
			want := ErrUnavailable
			if mode == "hidden commit failure" {
				want = ErrDenied
			}
			if !errors.Is(err, want) {
				t.Fatalf("callback contract: %v", err)
			}
			if later != nil {
				if err := later(auth); !errors.Is(err, ErrUnavailable) {
					t.Fatalf("escaped callback: %v", err)
				}
			}
			out, err := s.lookup(context.Background(), ctx.Value(humanKey{}).(entraauth.VerifiedHuman).Caller.Identity, r.Workspace, r.Key)
			if mode == "twice" {
				if err != nil || out.Outcome != "recorded" {
					t.Fatalf("original decision lost: %v", err)
				}
			} else if !errors.Is(err, ErrNotFound) {
				t.Fatalf("unexpected decision: %+v %v", out, err)
			}
		})
	}
}
func TestSnapshotCannotChangeActorActionRoleOrGrants(t *testing.T) {
	for name, change := range map[string]func(*Authorization){
		"actor":            func(a *Authorization) { a.Actor.Subject = "bob" },
		"action":           func(a *Authorization) { a.Action = Reject },
		"role":             func(a *Authorization) { a.Role = "Operator" },
		"duplicate grants": func(a *Authorization) { a.GrantIDs = []string{"grant", "grant"} },
		"unsorted grants":  func(a *Authorization) { a.GrantIDs = []string{"z", "a"} },
		"empty grants":     func(a *Authorization) { a.GrantIDs = nil },
		"workspace":        func(a *Authorization) { a.Subject.Workspace = "other" },
	} {
		t.Run(name, func(t *testing.T) {
			s, _, _, r := serviceFixture(t)
			policy := callbackPolicy{decide: func(h entraauth.VerifiedHuman, subject Subject, a Action, fn func(Authorization) error) error {
				auth := snapshot(h, subject, a)
				change(&auth)
				return fn(auth)
			}}
			svc, _ := NewService(s, requestVerifier{}, policy)
			ctx := humanContext("alice", time.Now().Add(time.Hour))
			if _, err := svc.Decide(ctx, r); !errors.Is(err, ErrDenied) {
				t.Fatalf("widened authorization: %v", err)
			}
			if _, err := s.lookup(context.Background(), ctx.Value(humanKey{}).(entraauth.VerifiedHuman).Caller.Identity, r.Workspace, r.Key); !errors.Is(err, ErrNotFound) {
				t.Fatalf("forged snapshot wrote record: %v", err)
			}
		})
	}
}
