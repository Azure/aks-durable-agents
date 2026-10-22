//go:build qualification_workspace_conformance

package qualification

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	dl "github.com/Azure/aks-durable-agents/decisionledger"
	"github.com/Azure/aks-durable-agents/entraauth"
	"github.com/agent-primitives/sessions/api"
	"github.com/agent-primitives/sessions/authn"
)

type workspaceJoinVerifier struct{}

func (workspaceJoinVerifier) VerifyHuman(context.Context) (entraauth.VerifiedHuman, error) {
	return entraauth.VerifiedHuman{Caller: authn.VerifiedCaller{Identity: api.CallerIdentity{Issuer: "issuer", Subject: "person"}, ValidUntil: time.Now().Add(time.Hour)}, Roles: []string{"Approver"}}, nil
}

type workspaceJoinPolicy struct{}

func (workspaceJoinPolicy) AuthorizeRead(context.Context, entraauth.VerifiedHuman, dl.Subject) error {
	return nil
}
func (workspaceJoinPolicy) WithDecision(_ context.Context, h entraauth.VerifiedHuman, s dl.Subject, a dl.Action, f func(dl.Authorization) error) error {
	ref, e := s.Reference()
	if e != nil {
		return e
	}
	return f(dl.Authorization{Actor: h.Caller.Identity, Subject: ref, Action: a, Role: "Approver", PolicyVersion: "policy", GrantIDs: []string{"grant"}})
}

// Contract regression: a workspace accepted by the shared E1/G1 evidence
// domain must not need renaming before the host can admit qualification in it.
// This tests identifier compatibility, NOT an already implemented Q/E adapter.
func TestQualificationWorkspaceJoin(t *testing.T) {
	for _, workspace := range []string{"workspace", "équipe", strings.Repeat("w", 129)} {
		t.Run(workspace, func(t *testing.T) {
			p := testPlan()
			p.Subject.Workspace = workspace
			ledger, e := dl.Initialize(filepath.Join(privateTestDir(t), "e1", "records.db"), "host")
			if e != nil {
				t.Fatal(e)
			}
			defer ledger.Close()
			d := strings.Repeat("a", 64)
			subject := dl.Subject{Workspace: workspace, Kind: dl.SuiteKind, ID: "proposal", Generation: 1, Resource: p.Subject.Target, Source: "host", ExpiresAt: time.Now().Add(time.Hour), Suite: &dl.SuiteProposal{ProposedBy: api.CallerIdentity{Issuer: "issuer", Subject: "proposer"}, ProposalID: "proposal", TargetID: p.Subject.Target, ExpectedVersion: "existing-version", ExpectedRevision: 1, Intent: "activate", OperationKey: "activate", PredecessorDigest: d, SuiteDigest: strings.TrimPrefix(p.Subject.SuiteDigest, "sha256:"), Member: p.MemberID, Composition: "none", Platform: p.Platform, InventoryDigest: d, CasesDigest: d, BindingDigest: strings.TrimPrefix(p.Subject.BindingDigest, "sha256:"), QualificationID: "qualification", EvidenceDigest: d, SourceDigest: d}}
			ref, e := ledger.RegisterSubject(context.Background(), subject)
			if e != nil {
				t.Fatal(e)
			}
			service, e := dl.NewService(ledger, workspaceJoinVerifier{}, workspaceJoinPolicy{})
			if e != nil {
				t.Fatal(e)
			}
			record, e := service.Decide(context.Background(), dl.DecideRequest{Workspace: workspace, Key: "approve", Subject: ref, Action: dl.Accept})
			if e != nil || record.Outcome != "recorded" {
				t.Fatalf("E1 rejected control: %v", e)
			}
			q, _ := testStore(t)
			if _, e = q.Admit(context.Background(), Request{Key: "qualify", Requester: "host", Plan: p}); e != nil {
				t.Fatalf("shared E1/G1 workspace rejected by Q1: %v", e)
			}
		})
	}
}
