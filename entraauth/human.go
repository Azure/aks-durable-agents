package entraauth

import (
	"context"
	"github.com/agent-primitives/sessions/authn"
	"github.com/golang-jwt/jwt/v5"
)

// VerifiedHuman contains only request-local verified identity and role evidence.
// It is not a scoped grant. Trusted host code must authorize each subject/action.
type VerifiedHuman struct {
	Caller authn.VerifiedCaller
	Roles  []string
}

// VerifyHuman verifies the exact incoming delegated credential. Human decision
// attribution requires oid; a verifier configured for sub cannot supply it.
// Existing Verify and VerifyApproval retain their compatibility semantics.
func (v *Verifier) VerifyHuman(ctx context.Context) (VerifiedHuman, error) {
	if v.config.SubjectClaim != "oid" {
		return VerifiedHuman{}, failure("human_oid_required")
	}
	var roles []string
	caller, err := v.verify(ctx, func(c jwt.MapClaims) error {
		if err := v.admit(c); err != nil {
			return err
		}
		var err error
		roles, err = claimList(c, "roles", false)
		return err
	})
	if err != nil {
		return VerifiedHuman{}, err
	}
	return VerifiedHuman{Caller: caller, Roles: roles}, nil
}
