package decisionledger

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/agent-primitives/sessions/api"
)

var testDigest = strings.Repeat("a", 64)

const (
	testProposerOID = "11111111-1111-4111-8111-111111111111"
	testReviewerOID = "22222222-2222-4222-8222-222222222222"
)

func suiteSubject() Subject {
	return Subject{Workspace: "workspace", Kind: SuiteKind, ID: "proposal", Generation: 1, Resource: "target", ExpiresAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), Source: "host-fixture", Suite: &SuiteProposal{ProposedBy: api.CallerIdentity{Issuer: "issuer", Subject: testProposerOID}, ProposalID: "proposal", TargetID: "target", ExpectedVersion: "version1", ExpectedRevision: 1, Intent: "activate", OperationKey: "activation-key", PredecessorDigest: testDigest, SuiteDigest: testDigest, Member: "main", Composition: "none", Platform: "linux/amd64", InventoryDigest: testDigest, CasesDigest: testDigest, BindingDigest: testDigest, QualificationID: "qualification", EvidenceDigest: testDigest, SourceDigest: testDigest}}
}
func effectSubject() Subject {
	s := suiteSubject()
	s.Kind = EffectKind
	s.Suite = nil
	s.Effect = &EffectApproval{SessionID: "session", ExecutionID: "execution", RequestSequence: 1, ToolCallID: "tool", OperationID: "operation", VersionID: "version1", InputRevision: "input", InputDigest: testDigest, ArgumentsDigest: testDigest}
	return s
}

func TestSubjectBinding(t *testing.T) {
	s := suiteSubject()
	ref, err := s.Reference()
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Subject){func(s *Subject) { s.Workspace = "other" }, func(s *Subject) { s.Generation++ }, func(s *Subject) { s.Suite.ExpectedRevision++ }, func(s *Subject) { s.Suite.OperationKey = "other" }, func(s *Subject) { s.Suite.CasesDigest = strings.Repeat("b", 64) }} {
		s := suiteSubject()
		change(&s)
		got, err := s.Reference()
		if err != nil || got.Digest == ref.Digest {
			t.Fatalf("binding omitted: %+v %v", got, err)
		}
	}
	for _, change := range []func(*Subject){func(s *Subject) { s.Kind = "document" }, func(s *Subject) { s.Effect = effectSubject().Effect }, func(s *Subject) { s.Suite.SuiteDigest = "SHA256:bad" }, func(s *Subject) { s.Generation = 0 }, func(s *Subject) { s.Workspace = "bad\x00" }, func(s *Subject) { s.Suite.Intent = "rollback" }, func(s *Subject) { s.Suite.TargetID = "other" }, func(s *Subject) { s.Source = strings.Repeat("x", 257) }} {
		s := suiteSubject()
		change(&s)
		if _, err := s.Reference(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("accepted invalid subject: %v", err)
		}
	}
	if _, err := effectSubject().Reference(); err != nil {
		t.Fatal(err)
	}
}
func TestActionsAndRequestBounds(t *testing.T) {
	for _, tc := range []struct {
		k  Kind
		a  Action
		ok bool
	}{{SuiteKind, Accept, true}, {SuiteKind, Reject, true}, {SuiteKind, RequestChanges, true}, {EffectKind, Approve, true}, {EffectKind, Deny, true}, {SuiteKind, Approve, false}, {EffectKind, Accept, false}, {EffectKind, "continue", false}, {SuiteKind, "abandon", false}} {
		if validAction(tc.k, tc.a) != tc.ok {
			t.Errorf("action %s/%s", tc.k, tc.a)
		}
	}
	ref, _ := suiteSubject().Reference()
	r := DecideRequest{Workspace: "workspace", Key: "key", Subject: ref, Action: Accept}
	h, err := requestFingerprint(r)
	if err != nil {
		t.Fatal(err)
	}
	r.Feedback = "please revise"
	h2, _ := requestFingerprint(r)
	if h == h2 {
		t.Fatal("feedback omitted")
	}
	for _, change := range []func(*DecideRequest){func(r *DecideRequest) { r.Key = strings.Repeat("x", 129) }, func(r *DecideRequest) { r.Key = "key space" }, func(r *DecideRequest) { r.Feedback = strings.Repeat("x", 2049) }, func(r *DecideRequest) { r.Feedback = "\x00" }, func(r *DecideRequest) { r.Workspace = "other" }} {
		r := DecideRequest{Workspace: "workspace", Key: "key", Subject: ref, Action: Accept}
		change(&r)
		if _, err := requestFingerprint(r); !errors.Is(err, ErrInvalid) {
			t.Fatalf("accepted invalid request: %v", err)
		}
	}
}
