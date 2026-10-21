package entraauth

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestOptionalAdmission(t *testing.T) {
	f := fixture(t)
	key, _ := testKeys(t)
	for _, tc := range []struct {
		name   string
		config func(*Config)
		change func(jwt.MapClaims)
		reason string
	}{
		{"disabled ignores malformed optional claims", func(c *Config) {}, func(c jwt.MapClaims) { c["roles"] = 12; c["groups"] = false; c["acct"] = "guest" }, ""},
		{"any required role plus extra", func(c *Config) { c.RequiredRoles = []string{"Reviewer", "Approver"} }, func(c jwt.MapClaims) { c["roles"] = []string{"extra", "Approver"} }, ""},
		{"roles missing", func(c *Config) { c.RequiredRoles = []string{"Reviewer"} }, func(c jwt.MapClaims) {}, "roles_missing"},
		{"roles scalar", func(c *Config) { c.RequiredRoles = []string{"Reviewer"} }, func(c jwt.MapClaims) { c["roles"] = "Reviewer" }, "roles_invalid"},
		{"roles mixed", func(c *Config) { c.RequiredRoles = []string{"Reviewer"} }, func(c jwt.MapClaims) { c["roles"] = []any{"Reviewer", 12} }, "roles_invalid"},
		{"roles case exact", func(c *Config) { c.RequiredRoles = []string{"Reviewer"} }, func(c jwt.MapClaims) { c["roles"] = []string{"reviewer"} }, "role_required"},
		{"roles null", func(c *Config) { c.RequiredRoles = []string{"Reviewer"} }, func(c jwt.MapClaims) { c["roles"] = nil }, "roles_invalid"},
		{"roles empty", func(c *Config) { c.RequiredRoles = []string{"Reviewer"} }, func(c jwt.MapClaims) { c["roles"] = []string{} }, "roles_missing"},
		{"all groups with extra", func(c *Config) { c.RequiredGroups = []string{tenant, audience} }, func(c jwt.MapClaims) { c["groups"] = []string{audience, clientID, tenant} }, ""},
		{"group missing", func(c *Config) { c.RequiredGroups = []string{tenant} }, func(c jwt.MapClaims) {}, "groups_missing"},
		{"group incomplete", func(c *Config) { c.RequiredGroups = []string{tenant, audience} }, func(c jwt.MapClaims) { c["groups"] = []string{tenant} }, "group_required"},
		{"group names", func(c *Config) { c.RequiredGroups = []string{tenant} }, func(c jwt.MapClaims) { c["groups"] = []string{tenant, "admins"} }, "groups_invalid"},
		{"group scalar", func(c *Config) { c.RequiredGroups = []string{tenant} }, func(c jwt.MapClaims) { c["groups"] = tenant }, "groups_invalid"},
		{"hasgroups even with list", func(c *Config) { c.RequiredGroups = []string{tenant} }, func(c jwt.MapClaims) { c["groups"] = []string{tenant}; c["hasgroups"] = false }, "groups_overage"},
		{"distributed groups even with list", func(c *Config) { c.RequiredGroups = []string{tenant} }, func(c jwt.MapClaims) {
			c["groups"] = []string{tenant}
			c["_claim_names"] = map[string]any{"groups": "src1"}
			c["_claim_sources"] = map[string]any{"src1": map[string]any{"endpoint": "https://never-fetch.invalid"}}
		}, "groups_overage"},
		{"malformed distributed marker", func(c *Config) { c.RequiredGroups = []string{tenant} }, func(c jwt.MapClaims) { c["groups"] = []string{tenant}; c["_claim_names"] = false }, "groups_invalid"},
		{"member", func(c *Config) { c.MemberOnly = true }, func(c jwt.MapClaims) { c["acct"] = 0 }, ""},
		{"guest", func(c *Config) { c.MemberOnly = true }, func(c jwt.MapClaims) { c["acct"] = 1 }, "member_required"},
		{"member missing", func(c *Config) { c.MemberOnly = true }, func(c jwt.MapClaims) {}, "member_required"},
		{"member string", func(c *Config) { c.MemberOnly = true }, func(c jwt.MapClaims) { c["acct"] = "0" }, "member_required"},
		{"member float", func(c *Config) { c.MemberOnly = true }, func(c jwt.MapClaims) { c["acct"] = json.Number("0.0") }, "member_required"},
		{"member negative zero", func(c *Config) { c.MemberOnly = true }, func(c jwt.MapClaims) { c["acct"] = json.Number("-0") }, "member_required"},
		{"member null", func(c *Config) { c.MemberOnly = true }, func(c jwt.MapClaims) { c["acct"] = nil }, "member_required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := f.verifier(t, tc.config)
			c := claims(f.clock())
			tc.change(c)
			_, err := v.Verify(incoming(signed(t, c, "initial", key, nil)))
			if tc.reason == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			safeFailure(t, err)
			if got := err.(interface{ DebugReason() string }).DebugReason(); got != tc.reason {
				t.Fatalf("reason=%s want=%s", got, tc.reason)
			}
		})
	}
	if f.offPin.Load() != 0 {
		t.Fatal("attempted external claim URL")
	}
}

func TestApprovalRoleVerification(t *testing.T) {
	f := fixture(t)
	key, other := testKeys(t)
	v := f.verifier(t, func(c *Config) {
		c.ApproverRoles = []string{"Approver"}
		c.MemberOnly = true
		c.RequiredGroups = []string{tenant}
	})
	for _, tc := range []struct {
		name    string
		roles   any
		present bool
		match   bool
		reason  string
	}{
		{"match", []string{"Approver", "Other"}, true, true, ""},
		{"valid other role allows subject route", []string{"Reader"}, true, false, ""},
		{"case mismatch", []string{"approver"}, true, false, ""},
		{"missing", nil, false, false, "roles_missing"},
		{"null", nil, true, false, "roles_invalid"},
		{"empty", []string{}, true, false, "roles_missing"},
		{"malformed", []any{"Approver", false}, true, false, "roles_invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := claims(f.clock())
			c["acct"] = 0
			c["groups"] = []string{tenant}
			if tc.present {
				c["roles"] = tc.roles
			}
			ctx := incoming(signed(t, c, "initial", key, nil))
			if _, err := v.Verify(ctx); err != nil {
				t.Fatal("approver-only role policy changed ordinary admission")
			}
			caller, match, err := v.VerifyApproval(ctx)
			if tc.reason != "" {
				safeFailure(t, err)
				if err.(interface{ DebugReason() string }).DebugReason() != tc.reason {
					t.Fatal("wrong diagnostic")
				}
				return
			}
			if err != nil || match != tc.match || caller.Identity.Subject != objectID {
				t.Fatalf("match=%v error=%v", match, err)
			}
		})
	}
	c := claims(f.clock())
	c["roles"] = []string{"Approver"}
	c["acct"] = 0
	c["groups"] = []string{tenant}
	for _, change := range []func(jwt.MapClaims){func(c jwt.MapClaims) { c["acct"] = 1 }, func(c jwt.MapClaims) { delete(c, "groups") }, func(c jwt.MapClaims) { c["exp"] = f.clock().Unix() }} {
		bad := jwt.MapClaims{}
		for k, v := range c {
			bad[k] = v
		}
		change(bad)
		_, _, err := v.VerifyApproval(incoming(signed(t, bad, "initial", key, nil)))
		safeFailure(t, err)
	}
	_, _, err := v.VerifyApproval(incoming(signed(t, c, "initial", other, nil)))
	safeFailure(t, err)
}

func TestPolicyConfigValidationAndCopy(t *testing.T) {
	f := fixture(t)
	for _, change := range []func(*Config){
		func(c *Config) { c.RequiredRoles = []string{""} }, func(c *Config) { c.ApproverRoles = []string{"bad role"} },
		func(c *Config) { c.RequiredGroups = []string{"name"} }, func(c *Config) { c.RequiredRoles = []string{"Reader", "Reader"} },
	} {
		c := f.config()
		change(&c)
		_, err := newVerifier(context.Background(), c, options{now: f.clock})
		safeFailure(t, err)
	}
	roles, groups, approvers := []string{"Reader"}, []string{tenant}, []string{"Approver"}
	v := f.verifier(t, func(c *Config) { c.RequiredRoles = roles; c.RequiredGroups = groups; c.ApproverRoles = approvers })
	roles[0] = "Other"
	groups[0] = audience
	approvers[0] = "Reader"
	c := claims(f.clock())
	c["roles"] = []string{"Reader", "Approver"}
	c["groups"] = []string{tenant}
	key, _ := testKeys(t)
	_, match, err := v.VerifyApproval(incoming(signed(t, c, "initial", key, nil)))
	if err != nil || !match {
		t.Fatal("operator slices mutated active policy")
	}
}
