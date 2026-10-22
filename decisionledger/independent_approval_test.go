package decisionledger

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Azure/aks-durable-agents/decisionrecord"
	"github.com/Azure/aks-durable-agents/entraauth"
	"github.com/agent-primitives/sessions/api"
)

func TestIndependentVersionApproval(t *testing.T) {
	for _, tc := range []struct {
		name, issuer, person string
		action               Action
		outcome, code        string
	}{
		{"proposer cannot accept", "issuer", testProposerOID, Accept, "refused", "policy_denied"},
		{"independent person", "issuer", testReviewerOID, Accept, "recorded", ""},
		{"same oid other issuer", "other-issuer", testProposerOID, Accept, "refused", "policy_denied"},
		{"other oid other issuer", "other-issuer", testReviewerOID, Accept, "refused", "policy_denied"},
		{"proposer may reject if policy permits", "issuer", testProposerOID, Reject, "recorded", ""},
		{"proposer may request changes if policy permits", "issuer", testProposerOID, RequestChanges, "recorded", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestStore(t)
			subject := suiteSubject()
			subject.Suite.ProposedBy = api.CallerIdentity{Issuer: "issuer", Subject: testProposerOID}
			ref, err := s.RegisterSubject(context.Background(), subject)
			if err != nil {
				t.Fatal(err)
			}
			svc, err := NewService(s, requestVerifier{}, &testPolicy{})
			if err != nil {
				t.Fatal(err)
			}
			ctx := humanContext(tc.person, time.Now().Add(time.Hour))
			h := ctx.Value(humanKey{}).(entraauth.VerifiedHuman)
			h.Caller.Identity.Issuer = tc.issuer
			ctx = context.WithValue(ctx, humanKey{}, h)
			r := DecideRequest{Workspace: ref.Workspace, Key: "approval", Subject: ref, Action: tc.action}
			// This assignment requires the producer to return the shared record itself,
			// not another structurally similar type requiring JSON translation.
			var out decisionrecord.DecisionRecord
			out, err = svc.Decide(ctx, r)
			if err != nil || out.Outcome != tc.outcome || out.RefusalCode != tc.code {
				t.Fatalf("decision=%+v err=%v", out, err)
			}
			got, err := svc.Get(ctx, r.Workspace, r.Key)
			if err != nil || got.ID != out.ID {
				t.Fatalf("readback=%+v err=%v", got, err)
			}
			retry, err := svc.Decide(ctx, r)
			if err != nil || retry.ID != out.ID {
				t.Fatalf("retry=%+v err=%v", retry, err)
			}
			if tc.outcome == "refused" {
				_, state, err := s.subject(ctx, ref)
				if err != nil || state != "open" || out.Authorization != nil {
					t.Fatalf("self-approval consumed subject: state=%s err=%v", state, err)
				}
				independent, err := svc.Decide(humanContext(testReviewerOID, time.Now().Add(time.Hour)), r)
				if err != nil || independent.Outcome != "recorded" || independent.ID == out.ID {
					t.Fatalf("denial poisoned independent approval: %+v %v", independent, err)
				}
			}
		})
	}
}
func TestProposerIdentityRequiredAndImmutable(t *testing.T) {
	s := newTestStore(t)
	subject := suiteSubject()
	subject.Suite.ProposedBy = api.CallerIdentity{}
	if _, err := s.RegisterSubject(context.Background(), subject); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown proposer accepted: %v", err)
	}
	subject.Suite.ProposedBy = api.CallerIdentity{Issuer: "issuer", Subject: testProposerOID}
	ref, err := s.RegisterSubject(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	subject.Suite.ProposedBy.Subject = testReviewerOID
	changed, err := subject.Reference()
	if err != nil || changed.Digest == ref.Digest {
		t.Fatalf("proposer not bound: %+v %v", changed, err)
	}
	if _, err = s.RegisterSubject(context.Background(), subject); !errors.Is(err, ErrConflict) {
		t.Fatalf("proposer replaced: %v", err)
	}
}
func TestRegisterSubjectRejectsNonOIDProposer(t *testing.T) {
	for name, value := range map[string]string{
		"pairwise sub":  "pairwise-subject",
		"uppercase oid": strings.ToUpper("abcdefab-cdef-4abc-8def-abcdefabcdef"),
		"braced oid":    "{" + testProposerOID + "}",
	} {
		t.Run(name, func(t *testing.T) {
			s := newTestStore(t)
			subject := suiteSubject()
			subject.Suite.ProposedBy.Subject = value
			if _, err := s.RegisterSubject(context.Background(), subject); !errors.Is(err, ErrInvalid) {
				t.Fatalf("non-oid proposer admitted: %v", err)
			}
		})
	}
}

func TestIndependentApprovalPreservesReadAndStatePriority(t *testing.T) {
	s, svc, policy, r := serviceFixture(t)
	subject := suiteSubject()
	subject.ID = "owned"
	subject.Suite.ProposedBy = api.CallerIdentity{Issuer: "issuer", Subject: testProposerOID}
	ref, err := s.RegisterSubject(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	r.Subject = ref
	author := humanContext(testProposerOID, time.Now().Add(time.Hour))
	policy.readDenied = true
	if out, err := svc.Decide(author, r); !errors.Is(err, ErrDenied) || out.ID != "" {
		t.Fatalf("read denial changed: %+v %v", out, err)
	}
	if _, err = s.lookup(author, api.CallerIdentity{Issuer: "issuer", Subject: testProposerOID}, r.Workspace, r.Key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("invisible self-approval persisted: %v", err)
	}
	policy.readDenied = false
	if out, err := svc.Decide(humanContext(testReviewerOID, time.Now().Add(time.Hour)), r); err != nil || out.Outcome != "recorded" {
		t.Fatalf("independent approval: %+v %v", out, err)
	}
	if out, err := svc.Decide(author, r); err != nil || out.RefusalCode != "subject_closed" {
		t.Fatalf("closed precedence: %+v %v", out, err)
	}
}
