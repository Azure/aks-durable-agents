package entraauth

import (
	"github.com/golang-jwt/jwt/v5"
	"sync"
	"testing"
)

// Dropping request-local role extraction or oid-only mapping breaks these tests.
func TestVerifyHuman(t *testing.T) {
	f := fixture(t)
	key, _ := testKeys(t)
	for _, tc := range []struct {
		name   string
		config func(*Config)
		change func(jwt.MapClaims)
		reason string
	}{
		{"valid", func(*Config) {}, func(jwt.MapClaims) {}, ""},
		{"missing roles", func(*Config) {}, func(c jwt.MapClaims) { delete(c, "roles") }, "roles_missing"},
		{"mixed roles", func(*Config) {}, func(c jwt.MapClaims) { c["roles"] = []any{"Agent.Approver", false} }, "roles_invalid"},
		{"app only", func(*Config) {}, func(c jwt.MapClaims) { delete(c, "scp"); c["idtyp"] = "app" }, "claims"},
		{"wrong audience", func(*Config) {}, func(c jwt.MapClaims) { c["aud"] = "other" }, "claims"},
		{"expired", func(*Config) {}, func(c jwt.MapClaims) { c["exp"] = f.clock().Unix() }, "claims"},
		{"sub configured", func(c *Config) { c.SubjectClaim = "sub" }, func(c jwt.MapClaims) { c["sub"] = "other" }, "human_oid_required"},
		{"overage", func(c *Config) { c.RequiredGroups = []string{tenant} }, func(c jwt.MapClaims) { c["groups"] = []string{tenant}; c["hasgroups"] = true }, "groups_overage"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := f.verifier(t, tc.config)
			c := claims(f.clock())
			c["roles"] = []string{"Agent.Approver", "Reader"}
			tc.change(c)
			h, err := v.VerifyHuman(incoming(signed(t, c, "initial", key, nil)))
			if tc.reason != "" {
				safeFailure(t, err)
				if err.(interface{ DebugReason() string }).DebugReason() != tc.reason {
					t.Fatalf("wrong reason: %v", err)
				}
				if len(h.Roles) != 0 || h.Caller.Identity.Subject != "" {
					t.Fatal("authority on failure")
				}
				return
			}
			if err != nil || h.Caller.Identity.Subject != objectID || len(h.Roles) != 2 || h.Roles[0] != "Agent.Approver" {
				t.Fatalf("bad human: %+v %v", h, err)
			}
		})
	}
}

func TestHumanCredentialsStayRequestLocal(t *testing.T) {
	f := fixture(t)
	key, _ := testKeys(t)
	v := f.verifier(t, func(*Config) {})
	var wg sync.WaitGroup
	for _, subject := range []string{objectID, audience} {
		c := claims(f.clock())
		c["oid"] = subject
		c["roles"] = []string{subject}
		ctx := incoming(signed(t, c, "initial", key, nil))
		wg.Go(func() {
			h, err := v.VerifyHuman(ctx)
			if err != nil || h.Caller.Identity.Subject != subject || len(h.Roles) != 1 || h.Roles[0] != subject {
				t.Errorf("request identity leaked: %+v %v", h, err)
			}
		})
	}
	wg.Wait()
}
