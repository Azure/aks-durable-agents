package decisionledger

import (
	"strings"
	"testing"
	"time"
)

// Every independently variable, valid field must affect the retained identity.
// Invalid syntax tests alone cannot catch a valid digest omitted from encoding.
func TestSuiteSubjectFieldBindings(t *testing.T) {
	otherDigest := strings.Repeat("b", 64)
	for name, change := range map[string]func(*Subject){
		"workspace":          func(s *Subject) { s.Workspace = "other" },
		"id":                 func(s *Subject) { s.ID = "other" },
		"generation":         func(s *Subject) { s.Generation++ },
		"expiry":             func(s *Subject) { s.ExpiresAt = s.ExpiresAt.Add(time.Second) },
		"source":             func(s *Subject) { s.Source = "other" },
		"proposal":           func(s *Subject) { s.Suite.ProposalID = "other" },
		"proposer issuer":    func(s *Subject) { s.Suite.ProposedBy.Issuer = "other" },
		"proposer subject":   func(s *Subject) { s.Suite.ProposedBy.Subject = testReviewerOID },
		"target":             func(s *Subject) { s.Resource = "other"; s.Suite.TargetID = "other" },
		"expected version":   func(s *Subject) { s.Suite.ExpectedVersion = "other" },
		"expected revision":  func(s *Subject) { s.Suite.ExpectedRevision++ },
		"operation key":      func(s *Subject) { s.Suite.OperationKey = "other" },
		"predecessor digest": func(s *Subject) { s.Suite.PredecessorDigest = otherDigest },
		"suite digest":       func(s *Subject) { s.Suite.SuiteDigest = otherDigest },
		"member":             func(s *Subject) { s.Suite.Member = "other" },
		"composition":        func(s *Subject) { s.Suite.Composition = "other" },
		"platform":           func(s *Subject) { s.Suite.Platform = "other" },
		"inventory digest":   func(s *Subject) { s.Suite.InventoryDigest = otherDigest },
		"cases digest":       func(s *Subject) { s.Suite.CasesDigest = otherDigest },
		"binding digest":     func(s *Subject) { s.Suite.BindingDigest = otherDigest },
		"qualification":      func(s *Subject) { s.Suite.QualificationID = "other" },
		"evidence digest":    func(s *Subject) { s.Suite.EvidenceDigest = otherDigest },
		"source digest":      func(s *Subject) { s.Suite.SourceDigest = otherDigest },
	} {
		t.Run(name, func(t *testing.T) {
			subject := suiteSubject()
			before, err := subject.Reference()
			if err != nil {
				t.Fatal(err)
			}
			change(&subject)
			after, err := subject.Reference()
			if err != nil {
				t.Fatal(err)
			}
			if before.Digest == after.Digest {
				t.Fatal("valid field omitted from suite identity")
			}
		})
	}
}
func TestEffectSubjectFieldBindings(t *testing.T) {
	otherDigest := strings.Repeat("b", 64)
	for name, change := range map[string]func(*Subject){
		"workspace":        func(s *Subject) { s.Workspace = "other" },
		"id":               func(s *Subject) { s.ID = "other" },
		"generation":       func(s *Subject) { s.Generation++ },
		"resource":         func(s *Subject) { s.Resource = "other" },
		"expiry":           func(s *Subject) { s.ExpiresAt = s.ExpiresAt.Add(time.Second) },
		"source":           func(s *Subject) { s.Source = "other" },
		"session":          func(s *Subject) { s.Effect.SessionID = "other" },
		"execution":        func(s *Subject) { s.Effect.ExecutionID = "other" },
		"request sequence": func(s *Subject) { s.Effect.RequestSequence++ },
		"tool call":        func(s *Subject) { s.Effect.ToolCallID = "other" },
		"operation":        func(s *Subject) { s.Effect.OperationID = "other" },
		"version":          func(s *Subject) { s.Effect.VersionID = "other" },
		"input revision":   func(s *Subject) { s.Effect.InputRevision = "other" },
		"input digest":     func(s *Subject) { s.Effect.InputDigest = otherDigest },
		"argument digest":  func(s *Subject) { s.Effect.ArgumentsDigest = otherDigest },
	} {
		t.Run(name, func(t *testing.T) {
			subject := effectSubject()
			before, err := subject.Reference()
			if err != nil {
				t.Fatal(err)
			}
			change(&subject)
			after, err := subject.Reference()
			if err != nil {
				t.Fatal(err)
			}
			if before.Digest == after.Digest {
				t.Fatal("valid field omitted from effect identity")
			}
		})
	}
	suite, _ := suiteSubject().Reference()
	effect, _ := effectSubject().Reference()
	if suite.Digest == effect.Digest {
		t.Fatal("subject kind omitted from identity")
	}
}
