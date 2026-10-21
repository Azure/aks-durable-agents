package host

import (
	"context"
	"errors"
	"time"

	"github.com/agent-primitives/sessions/api"
	v1 "github.com/agent-primitives/sessions/api/genpb"
	"github.com/agent-primitives/sessions/authn"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type approvalPolicy struct {
	approvers      map[api.CallerIdentity]bool
	verifyApproval func(context.Context) (authn.VerifiedCaller, bool, error)
}

var errApprovalRolesMissing = errors.New("approval requires a nonempty roles claim; configure API app role assignments")
var errApprovalRolesInvalid = errors.New("approval requires a valid roles claim")

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
		if r.SessionUID == "" || !r.Caller.Valid() {
			return api.ErrPermissionDenied
		}
		role := false
		if p.verifyApproval != nil {
			verified, match, err := p.verifyApproval(ctx)
			if err != nil {
				switch debugReason(err) {
				case "roles_missing":
					return errApprovalRolesMissing
				case "roles_invalid":
					return errApprovalRolesInvalid
				}
				return api.ErrPermissionDenied
			}
			if verified.Identity != r.Caller || !verified.ValidUntil.After(time.Now()) {
				return api.ErrPermissionDenied
			}
			role = match
		}
		if p.approvers[r.Caller] || role {
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
		if !ok || !valid {
			return nil, status.Error(codes.PermissionDenied, "approval not permitted")
		}
		if err := policy.Authorize(ctx, api.AuthorizationRequest{Caller: caller, Action: api.ActionApprove, SessionUID: approval.GetSession()}); err != nil {
			if errors.Is(err, errApprovalRolesMissing) {
				return nil, status.Error(codes.PermissionDenied, errApprovalRolesMissing.Error())
			}
			if errors.Is(err, errApprovalRolesInvalid) {
				return nil, status.Error(codes.PermissionDenied, errApprovalRolesInvalid.Error())
			}
			return nil, status.Error(codes.PermissionDenied, "approval not permitted")
		}
		return next(ctx, req)
	}
}
