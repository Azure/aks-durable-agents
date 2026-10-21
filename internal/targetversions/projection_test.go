package targetversions

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/Azure/aks-durable-agents/decisionrecord"
)

// Shared DTOs must cross the real store boundary without conversion or rewriting
// historical evidence. They do not authenticate the subject or current authority.
func TestSharedDecisionRecordStoreRoundTrip(t *testing.T) {
	s, path := newStore(t)
	r := request(register(t, s, "agent"), "shared")
	ref := decisionrecord.SubjectRef{Workspace: "workspace-東京", Kind: decisionrecord.SuiteKind, ID: "proposal-shared", Generation: 1, Digest: digest}
	actor := decisionrecord.Identity{Issuer: "issuer", Subject: "reviewer"}
	record := decisionrecord.DecisionRecord{
		ID: "decision-shared", StoreID: "decisions", HostLineageID: "host",
		Request:       decisionrecord.DecideRequest{Workspace: ref.Workspace, Key: "shared", Subject: ref, Action: decisionrecord.Accept, Feedback: "reviewed\nready"},
		RequestDigest: digest, Actor: actor, Outcome: "recorded",
		Authorization: &decisionrecord.Authorization{Actor: actor, Subject: ref, Action: decisionrecord.Accept, Role: "Custom.Reviewer", PolicyVersion: "policy-東京", GrantIDs: []string{"grant"}},
		CommittedAt:   time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC), Mode: decisionrecord.NonExecutingMode,
	}
	r.Subject = ref
	r.DecisionRecord = record
	o := committed(t, s, begin(t, s, r))
	s = reopen(t, s, path)
	saved, err := s.ReadOperation(ctx, o.ID)
	if err != nil {
		t.Fatal(err)
	}
	var got decisionrecord.DecisionRecord = saved.Request.DecisionRecord
	var reserved decisionrecord.DecisionRecord = saved.Reserved.DecisionRecord
	if saved.Phase != "committed" || !reflect.DeepEqual(got, record) || !reflect.DeepEqual(reserved, record) {
		t.Fatal("shared historical decision evidence changed across commit/reopen")
	}
	target, err := s.ReadTarget(ctx, r.TargetID)
	if err != nil || target.ActiveVersionID != saved.Version.ID || target.Availability != "ready" {
		t.Fatal("shared decision did not commit target", target, err)
	}
}

func TestSharedEffectDecisionCannotBegin(t *testing.T) {
	s, _ := newStore(t)
	r := request(register(t, s, "agent"), "effect")
	r.Subject.Kind = decisionrecord.EffectKind
	r.DecisionRecord.Request.Subject = r.Subject
	r.DecisionRecord.Authorization.Subject = r.Subject
	if _, err := s.Begin(ctx, r); !errors.Is(err, ErrInvalid) {
		t.Fatal("shared effect kind broadened G1's suite-only boundary", err)
	}
}
