package host

import (
	"context"

	"github.com/agent-primitives/sessions/api"
	v1 "github.com/agent-primitives/sessions/api/genpb"
	"github.com/agent-primitives/sessions/authn"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type approvalPolicy struct{ approvers map[api.CallerIdentity]bool }

func newApprovalPolicy(callers []api.CallerIdentity) *approvalPolicy {
	p := &approvalPolicy{approvers: make(map[api.CallerIdentity]bool, len(callers))}
	for _, caller := range callers {
		if caller.Valid() {
			p.approvers[caller] = true
		}
	}
	return p
}

// Approval is separate from ownership. Ordinary owner checks are supplied by
// sessions, but its RPC handlers do not call this policy yet (upstream c1).
func (p *approvalPolicy) Authorize(ctx context.Context, r api.AuthorizationRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.Action == api.ActionApprove {
		if r.SessionUID != "" && r.Caller.Valid() && p.approvers[r.Caller] {
			return nil
		}
		return api.ErrPermissionDenied
	}
	return (api.OwnerAuthorizer{}).Authorize(ctx, r)
}

func approvalGate(policy api.Authorizer) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
		if info.FullMethod != v1.Sessions_Approve_FullMethodName {
			return next(ctx, req)
		}
		caller, ok := authn.Caller(ctx)
		approval, valid := req.(*v1.ApproveRequest)
		if !ok || !valid || policy.Authorize(ctx, api.AuthorizationRequest{Caller: caller, Action: api.ActionApprove, SessionUID: approval.GetSession()}) != nil {
			return nil, status.Error(codes.PermissionDenied, "approval not permitted")
		}
		return next(ctx, req)
	}
}
