package entraauth

import (
	"context"
	"encoding/json"
	"slices"

	"github.com/agent-primitives/sessions/authn"
	"github.com/golang-jwt/jwt/v5"
)

func (c *Config) copyPolicy() error {
	for _, list := range []struct {
		values *[]string
		group  bool
	}{{&c.RequiredRoles, false}, {&c.ApproverRoles, false}, {&c.RequiredGroups, true}} {
		seen := make(map[string]bool)
		for _, s := range *list.values {
			if !plainWord(s) || (list.group && !guid.MatchString(s)) || seen[s] {
				return failure("config")
			}
			seen[s] = true
		}
		*list.values = slices.Clone(*list.values)
	}
	return nil
}

// VerifyApproval re-verifies the incoming credential, including ordinary admission,
// and reports whether any configured approver role matches. A configured role
// source requires a nonempty, well-formed roles claim even when a host also lists
// the subject. No match is distinct from unusable claims: only the former may be
// combined with a subject allowlist. No claims or authority are cached by identity.
func (v *Verifier) VerifyApproval(ctx context.Context) (authn.VerifiedCaller, bool, error) {
	match := false
	caller, err := v.verify(ctx, func(claims jwt.MapClaims) error {
		if err := v.admit(claims); err != nil {
			return err
		}
		if len(v.config.ApproverRoles) == 0 {
			return nil
		}
		roles, err := claimList(claims, "roles", false)
		if err != nil {
			return err
		}
		match = anyMatch(roles, v.config.ApproverRoles)
		return nil
	})
	return caller, match && err == nil, err
}

func (v *Verifier) admit(claims jwt.MapClaims) error {
	if v.config.MemberOnly && claims["acct"] != json.Number("0") {
		return failure("member_required")
	}
	if len(v.config.RequiredRoles) > 0 {
		roles, err := claimList(claims, "roles", false)
		if err != nil {
			return err
		}
		if !anyMatch(roles, v.config.RequiredRoles) {
			return failure("role_required")
		}
	}
	if len(v.config.RequiredGroups) > 0 {
		// Presence of overage/distributed indicators makes a supplied list ambiguous.
		// Never follow token-supplied claim-source URLs or call Graph.
		if _, ok := claims["hasgroups"]; ok {
			return failure("groups_overage")
		}
		if names, ok := claims["_claim_names"]; ok {
			m, valid := names.(map[string]any)
			if !valid {
				return failure("groups_invalid")
			}
			if _, overage := m["groups"]; overage {
				return failure("groups_overage")
			}
		}
		groups, err := claimList(claims, "groups", true)
		if err != nil {
			return err
		}
		for _, required := range v.config.RequiredGroups {
			if !slices.Contains(groups, required) {
				return failure("group_required")
			}
		}
	}
	return nil
}

func claimList(claims jwt.MapClaims, name string, group bool) ([]string, error) {
	value, present := claims[name]
	if !present {
		return nil, failure(name + "_missing")
	}
	values, ok := value.([]any)
	if !ok {
		return nil, failure(name + "_invalid")
	}
	if len(values) == 0 {
		return nil, failure(name + "_missing")
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		s, ok := value.(string)
		if !ok || !plainWord(s) || (group && !guid.MatchString(s)) {
			return nil, failure(name + "_invalid")
		}
		result = append(result, s)
	}
	return result, nil
}

func anyMatch(have, want []string) bool {
	for _, s := range want {
		if slices.Contains(have, s) {
			return true
		}
	}
	return false
}
