package host

import (
	"context"
	"time"

	"github.com/agent-primitives/sessions/api"
	"github.com/agent-primitives/sessions/authn"
)

type approvalPolicy struct {
	approvers      map[api.CallerIdentity]bool
	verifyApproval func(context.Context) (authn.VerifiedCaller, bool, error)
}

func newApprovalPolicy(callers []api.CallerIdentity) *approvalPolicy {
	p := &approvalPolicy{approvers: make(map[api.CallerIdentity]bool, len(callers))}
	for _, caller := range callers {
		if caller.Valid() {
			p.approvers[caller] = true
		}
	}
	return p
}

// Ownership grants ordinary operations, not approval. Approvers may inspect the
// full session before deciding, but receive no authority to execute it.
func (p *approvalPolicy) Authorize(ctx context.Context, r api.AuthorizationRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !r.Caller.Valid() {
		return api.ErrPermissionDenied
	}
	switch r.Action {
	case api.ActionCreate, api.ActionList:
		if r.SessionUID == "" && r.Owner == (api.CallerIdentity{}) {
			return nil
		}
		return api.ErrPermissionDenied
	case api.ActionRead, api.ActionApprove, api.ActionExec, api.ActionResume,
		api.ActionSuspend, api.ActionDelete, api.ActionCancel, api.ActionFork:
		// Legacy unbound history is never claimed or exposed, even to approvers.
		if r.SessionUID == "" || !r.Owner.Valid() {
			return api.ErrPermissionDenied
		}
	default:
		return api.ErrPermissionDenied
	}
	if r.Action == api.ActionApprove || (r.Action == api.ActionRead && r.Caller != r.Owner) {
		return p.authorizeApprover(ctx, r.Caller)
	}
	return (api.OwnerAuthorizer{}).Authorize(ctx, r)
}

func (p *approvalPolicy) authorizeApprover(ctx context.Context, caller api.CallerIdentity) error {
	role := false
	if p.verifyApproval != nil {
		verified, match, err := p.verifyApproval(ctx)
		// Unusable configured role evidence must not fall back to a listed subject.
		if err != nil || verified.Identity != caller || !verified.ValidUntil.After(time.Now()) {
			return api.ErrPermissionDenied
		}
		role = match
	}
	if p.approvers[caller] || role {
		return nil
	}
	return api.ErrPermissionDenied
}
