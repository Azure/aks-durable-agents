package host

import (
	"context"
	"testing"
	"time"

	"github.com/agent-primitives/sessions/api"
	v1 "github.com/agent-primitives/sessions/api/genpb"
	"github.com/agent-primitives/sessions/authn"
	"github.com/agent-primitives/sessions/session"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type testVerifier struct{ caller api.CallerIdentity }

func (v testVerifier) Verify(context.Context) (authn.VerifiedCaller, error) {
	return authn.VerifiedCaller{Identity: v.caller, ValidUntil: time.Now().Add(time.Hour)}, nil
}

func TestApprovalIsSeparateFromOwnership(t *testing.T) {
	owner := api.CallerIdentity{Issuer: "issuer", Subject: "owner"}
	approver := api.CallerIdentity{Issuer: "issuer", Subject: "approver"}
	policy := newApprovalPolicy([]api.CallerIdentity{approver})
	for _, tc := range []struct {
		name           string
		caller, stored api.CallerIdentity
		action         api.Action
		want           bool
	}{
		{"owner can read", owner, owner, api.ActionRead, true},
		{"owner cannot approve", owner, owner, api.ActionApprove, false},
		{"non-owner approver", approver, owner, api.ActionApprove, true},
		{"approver can read", approver, owner, api.ActionRead, true},
		{"ownerless read", approver, api.CallerIdentity{}, api.ActionRead, false},
		{"ownerless approval", approver, api.CallerIdentity{}, api.ActionApprove, false},
		{"foreign issuer", api.CallerIdentity{Issuer: "other", Subject: "approver"}, owner, api.ActionApprove, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := policy.Authorize(context.Background(), api.AuthorizationRequest{Caller: tc.caller, Owner: tc.stored, Action: tc.action, SessionUID: "session"})
			if (err == nil) != tc.want {
				t.Fatalf("authorized=%v want=%v", err == nil, tc.want)
			}
		})
	}
	// Mutating operator input cannot expand a running policy.
	list := []api.CallerIdentity{approver}
	copied := newApprovalPolicy(list)
	list[0] = owner
	if copied.Authorize(context.Background(), api.AuthorizationRequest{Caller: owner, Owner: owner, Action: api.ActionApprove, SessionUID: "session"}) == nil {
		t.Fatal("allowlist mutation expanded authority")
	}
}

func TestSessionAuthorizationActions(t *testing.T) {
	owner := api.CallerIdentity{Issuer: "issuer", Subject: "owner"}
	approver := api.CallerIdentity{Issuer: "issuer", Subject: "approver"}
	p := newApprovalPolicy([]api.CallerIdentity{approver})
	for _, action := range []api.Action{api.ActionRead, api.ActionExec, api.ActionFork, api.ActionSuspend, api.ActionResume, api.ActionDelete, api.ActionCancel, api.ActionApprove, api.ActionMint, api.ActionRegistryRead, api.Action("future")} {
		for _, tc := range []struct {
			name   string
			caller api.CallerIdentity
			want   bool
		}{
			{"owner", owner, action != api.ActionApprove && action != api.ActionMint && action != api.ActionRegistryRead && action != api.Action("future")},
			{"approver", approver, action == api.ActionRead || action == api.ActionApprove},
			{"missing caller", api.CallerIdentity{}, false},
		} {
			t.Run(string(action)+"/"+tc.name, func(t *testing.T) {
				err := p.Authorize(t.Context(), api.AuthorizationRequest{Caller: tc.caller, Owner: owner, SessionUID: "s", Action: action})
				if (err == nil) != tc.want {
					t.Fatalf("authorized=%v want=%v", err == nil, tc.want)
				}
			})
		}
	}
	for _, action := range []api.Action{api.ActionCreate, api.ActionList} {
		if err := p.Authorize(t.Context(), api.AuthorizationRequest{Caller: owner, Action: action}); err != nil {
			t.Fatalf("global %s: %v", action, err)
		}
		for _, r := range []api.AuthorizationRequest{
			{Action: action},
			{Caller: owner, SessionUID: "s", Action: action},
			{Caller: owner, Owner: owner, Action: action},
		} {
			if p.Authorize(t.Context(), r) == nil {
				t.Fatalf("invalid global %s authorized", action)
			}
		}
	}
}

func TestSessionAuthorizationRequiresCaller(t *testing.T) {
	// Caller authentication must precede even a store or registry access.
	svc := session.NewService(nil, nil, session.WithAuthorization(newApprovalPolicy(nil)))
	if _, err := svc.GetSession(t.Context(), &v1.GetSessionRequest{Uid: "s"}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("direct read without identity: %v", err)
	}
	if _, err := svc.CreateSession(t.Context(), &v1.CreateSessionRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("direct create without identity: %v", err)
	}
}
