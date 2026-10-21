package host

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/agent-primitives/sessions/api"
	"github.com/agent-primitives/sessions/authn"
	"github.com/agent-primitives/sessions/client"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The actual assembled server proves metadata survives authn, role authority is
// request-specific, and rejection precedes approval journal writes and effects.
func TestApprovalSourcesORAndRequiredClaims(t *testing.T) {
	for _, tc := range []struct {
		name    string
		listed  bool
		roles   any
		acct    any
		groups  any
		want    codes.Code
		message string
	}{
		{"role only", false, []string{"Approver"}, 0, []string{ownerOID}, codes.OK, ""},
		{"listed other role", true, []string{"Reader"}, 0, []string{ownerOID}, codes.OK, ""},
		{"both", true, []string{"Approver"}, 0, []string{ownerOID}, codes.OK, ""},
		{"neither", false, []string{"Reader"}, 0, []string{ownerOID}, codes.PermissionDenied, "approval not permitted"},
		{"listed missing roles", true, nil, 0, []string{ownerOID}, codes.PermissionDenied, "approval requires a nonempty roles claim; configure API app role assignments"},
		{"listed malformed roles", true, "Approver", 0, []string{ownerOID}, codes.PermissionDenied, "approval requires a valid roles claim"},
		{"guest listed role", true, []string{"Approver"}, 1, []string{ownerOID}, codes.Unauthenticated, "authentication required"},
		{"missing group listed role", true, []string{"Approver"}, 0, nil, codes.Unauthenticated, "authentication required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newHostFixture(t)
			identity, sign := entraFixture(t, func(c jwt.MapClaims) {
				c["roles"] = []string{"Reader"}
				c["acct"] = 0
				c["groups"] = []string{ownerOID}
				if c["oid"] != ownerOID {
					delete(c, "roles")
					if tc.roles != nil {
						c["roles"] = tc.roles
					}
					c["acct"] = tc.acct
					c["groups"] = tc.groups
				}
			})
			identity.ApproverRoles = []string{"Approver"}
			identity.MemberOnly = true
			identity.RequiredGroups = []string{ownerOID}
			f.config.Mode, f.config.Identity = authn.Required, identity
			const approverOID = "0b0b0b0b-0000-4000-8000-000000000002"
			if tc.listed {
				f.config.Approvers = []api.CallerIdentity{{Issuer: fixtureIssuer, Subject: approverOID}}
			}
			sink := newLogSink()
			app, c, _ := f.startWith(t, t.Context(), sink.logger())
			ctx := bearer(t.Context(), "Bearer "+sign(ownerOID))
			turn, err := c.Exec(ctx, client.ExecOptions{Harness: "release-notes", Inputs: []string{"proposal"}})
			if err != nil {
				t.Fatal(err)
			}
			uid := turn.Session.GetMetadata().GetUid()
			token := sign(approverOID)
			_, err = c.Approve(bearer(t.Context(), "Bearer "+token), uid, decision(t, turn.Session, true))
			if status.Code(err) != tc.want {
				t.Fatalf("code=%v want=%v error=%v", status.Code(err), tc.want, err)
			}
			if tc.message != "" && status.Convert(err).Message() != tc.message {
				t.Fatalf("message=%q", status.Convert(err).Message())
			}
			if tc.want != codes.OK {
				stored, e := app.store.Session(uid).Read(1)
				if e != nil {
					t.Fatal(e)
				}
				if len(stored) != int(turn.Session.GetLastSeq()) {
					t.Fatal("denied approval changed journal")
				}
			}
			if f.sockets.Load() != 0 {
				t.Fatal("approval executed an effect")
			}
			log := sink.String()
			if !strings.Contains(log, `msg="approval sources active"`) || !strings.Contains(log, `app_roles=[Approver]`) {
				t.Fatal("missing startup sources")
			}
			if strings.Contains(log, token) || strings.Contains(log, approverOID) || strings.Contains(log, ownerOID) {
				t.Fatal("claim values reached logs")
			}
			if tc.roles == nil && (!strings.Contains(log, `msg="approval verification failed" reason=roles_missing`) || strings.Contains(log, `msg="caller authentication failed"`)) {
				t.Fatal("missing approval roles logged as authentication failure")
			}
		})
	}
}

func TestAdmissionPolicyStartupLog(t *testing.T) {
	f := newHostFixture(t)
	identity, _ := entraFixture(t)
	identity.MemberOnly = true
	identity.RequiredRoles = []string{"Reviewer", "Approver"}
	identity.RequiredGroups = []string{ownerOID}
	f.config.Mode, f.config.Identity = authn.Required, identity
	sink := newLogSink()
	f.startWith(t, t.Context(), sink.logger())
	log := sink.String()
	for _, field := range []string{`member_only=true`, `required_roles="[Reviewer Approver]"`, `required_group_count=1`} {
		if !strings.Contains(log, field) {
			t.Fatalf("missing configured admission restriction %s", field)
		}
	}
	if strings.Contains(log, ownerOID) {
		t.Fatal("group IDs reached startup log")
	}
}

func TestPolicyRequiresAuth(t *testing.T) {
	for _, change := range []func(*Config){
		func(c *Config) { c.Identity.MemberOnly = true }, func(c *Config) { c.Identity.RequiredRoles = []string{"Reader"} },
		func(c *Config) { c.Identity.RequiredGroups = []string{ownerOID} }, func(c *Config) { c.Identity.ApproverRoles = []string{"Approver"} },
	} {
		f := newHostFixture(t)
		change(&f.config)
		if err := f.config.validate(); err == nil {
			t.Fatal("policy silently ignored in off mode")
		}
	}
}

func TestApprovalRoleIdentityBinding(t *testing.T) {
	caller := api.CallerIdentity{Issuer: "issuer", Subject: "listed"}
	p := newApprovalPolicy([]api.CallerIdentity{caller})
	p.verifyApproval = func(ctx context.Context) (authn.VerifiedCaller, bool, error) {
		return authn.VerifiedCaller{Identity: api.CallerIdentity{Issuer: "other", Subject: "listed"}, ValidUntil: time.Now().Add(time.Hour)}, true, nil
	}
	if p.Authorize(t.Context(), api.AuthorizationRequest{Caller: caller, Action: api.ActionApprove, SessionUID: "s"}) == nil {
		t.Fatal("role result for different caller accepted")
	}
	p.verifyApproval = func(ctx context.Context) (authn.VerifiedCaller, bool, error) {
		return authn.VerifiedCaller{Identity: caller, ValidUntil: time.Now().Add(-time.Minute)}, true, nil
	}
	if p.Authorize(t.Context(), api.AuthorizationRequest{Caller: caller, Action: api.ActionApprove, SessionUID: "s"}) == nil {
		t.Fatal("expired role result accepted for matching listed caller")
	}
}
