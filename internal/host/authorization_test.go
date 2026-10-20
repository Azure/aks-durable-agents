package host

import (
	"context"
	"testing"
	"time"

	"github.com/agent-primitives/sessions/api"
	v1 "github.com/agent-primitives/sessions/api/genpb"
	"github.com/agent-primitives/sessions/authn"
	"google.golang.org/grpc"
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
		{"approver not owner", approver, owner, api.ActionRead, false},
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
	if copied.Authorize(context.Background(), api.AuthorizationRequest{Caller: owner, Action: api.ActionApprove, SessionUID: "session"}) == nil {
		t.Fatal("allowlist mutation expanded authority")
	}
}

func TestApprovalGateBeforeHandler(t *testing.T) {
	owner := api.CallerIdentity{Issuer: "issuer", Subject: "owner"}
	unary, _, err := authn.NewInterceptors(authn.Required, testVerifier{owner})
	if err != nil {
		t.Fatal(err)
	}
	gate := approvalGate(newApprovalPolicy(nil))
	calls := 0
	_, err = unary(context.Background(), &v1.ApproveRequest{Session: "session"}, &grpc.UnaryServerInfo{FullMethod: v1.Sessions_Approve_FullMethodName}, func(ctx context.Context, req any) (any, error) {
		return gate(ctx, req, &grpc.UnaryServerInfo{FullMethod: v1.Sessions_Approve_FullMethodName}, func(context.Context, any) (any, error) { calls++; return nil, nil })
	})
	if status.Code(err) != codes.PermissionDenied || calls != 0 {
		t.Fatalf("code=%v handler calls=%d", status.Code(err), calls)
	}
}
