//go:build decision_projection_conformance

package targetversions

import (
	"context"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	dl "github.com/Azure/aks-durable-agents/decisionledger"
	"github.com/Azure/aks-durable-agents/decisionrecord"
	"github.com/Azure/aks-durable-agents/entraauth"
	"github.com/agent-primitives/sessions/api"
	"github.com/agent-primitives/sessions/authn"
)

// This opt-in test runs with both real packages in a combined source checkout.
// It imports no runtime adapter. Synthetic credentials and bootstrap receipts
// qualify copied evidence only, never live authority, qualification or dispatch.
type projectionVerifier struct{ role string }

func (v projectionVerifier) VerifyHuman(context.Context) (entraauth.VerifiedHuman, error) {
	return entraauth.VerifiedHuman{Caller: authn.VerifiedCaller{Identity: api.CallerIdentity{Issuer: "issuer", Subject: "person"}, ValidUntil: time.Now().Add(time.Hour)}, Roles: []string{v.role}}, nil
}

type projectionPolicy struct{ role, policy, grant string }

func (p projectionPolicy) AuthorizeRead(context.Context, entraauth.VerifiedHuman, dl.Subject) error {
	return nil
}
func (p projectionPolicy) WithDecision(_ context.Context, h entraauth.VerifiedHuman, s dl.Subject, a dl.Action, commit func(dl.Authorization) error) error {
	ref, err := s.Reference()
	if err != nil {
		return err
	}
	return commit(dl.Authorization{Actor: h.Caller.Identity, Subject: ref, Action: a, Role: p.role, PolicyVersion: p.policy, GrantIDs: []string{p.grant}})
}
func TestDecisionProjectionConformance(t *testing.T) {
	for _, tc := range []struct{ name, workspace, subject, role, policy, grant, lineage string }{
		{"canonical", "workspace", "proposal", "Agent.Approver", "p1", "grant", "host"},
		{"custom role", "workspace", "proposal", "Approver", "p1", "grant", "host"},
		{"unicode workspace", "équipe", "proposal", "Agent.Approver", "p1", "grant", "host"},
		{"long subject", "workspace", strings.Repeat("s", 129), "Agent.Approver", "p1", "grant", "host"},
		{"unicode policy", "workspace", "proposal", "Agent.Approver", "politique-équipe", "grant", "host"},
		{"long grant", "workspace", "proposal", "Agent.Approver", "p1", strings.Repeat("g", 129), "host"},
		{"unicode role", "workspace", "proposal", "Approbateur-équipe", "p1", "grant", "host"},
		{"maximum evidence", strings.Repeat("é", 128), strings.Repeat("s", 256), strings.Repeat("R", 256), strings.Repeat("p", 256), strings.Repeat("g", 256), strings.Repeat("h", 256)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			versions, path := newStore(t)
			// Establish S1 using G1's explicitly synthetic bootstrap fixture. The real
			// producer cannot authorize genesis; the conformance operation is S1→S2.
			committed(t, versions, begin(t, versions, request(register(t, versions, "agent"), "bootstrap")))
			r := activeRequest(t, versions, "agent", "activate-next")
			r.Candidate.Artifact.SuiteDigest = strings.Repeat("b", 64)
			r.Candidate.Qualification.Artifact = r.Candidate.Artifact
			a := r.Candidate.Artifact
			subject := dl.Subject{Workspace: tc.workspace, Kind: dl.SuiteKind, ID: tc.subject, Generation: 1, Resource: r.TargetID, ExpiresAt: time.Now().Add(time.Hour), Source: "host", Suite: &dl.SuiteProposal{
				ProposedBy: api.CallerIdentity{Issuer: "issuer", Subject: "proposer"}, ProposalID: tc.subject, TargetID: r.TargetID, ExpectedVersion: r.Predecessor.ID, ExpectedRevision: r.ExpectedRevision, Intent: "activate", OperationKey: r.Key, PredecessorDigest: digest, SuiteDigest: a.SuiteDigest, Member: a.Member, Composition: a.Composition, Platform: a.Platform, InventoryDigest: a.InventoryDigest, CasesDigest: a.CasesDigest, BindingDigest: a.BindingDigest, QualificationID: r.Candidate.Qualification.ID, EvidenceDigest: r.Candidate.Qualification.EvidenceDigest, SourceDigest: r.Candidate.SourceDigest,
			}}
			ledger, err := dl.Initialize(filepath.Join(t.TempDir(), "ledger", "decisions.db"), tc.lineage)
			if err != nil {
				t.Fatal(err)
			}
			defer ledger.Close()
			ref, err := ledger.RegisterSubject(ctx, subject)
			if err != nil {
				t.Fatal(err)
			}
			service, err := dl.NewService(ledger, projectionVerifier{tc.role}, projectionPolicy{tc.role, tc.policy, tc.grant})
			if err != nil {
				t.Fatal(err)
			}
			original, err := service.Decide(ctx, dl.DecideRequest{Workspace: tc.workspace, Key: r.Key, Subject: ref, Action: dl.Accept, Feedback: "Retain exact evidence.\n"})
			if err != nil {
				t.Fatal(err)
			}
			if original.Outcome != "recorded" || original.Authorization == nil || original.Authorization.Role != tc.role {
				t.Fatalf("producer did not record exact role: %+v", original)
			}
			// This is one shared type, not a JSON-translated consumer copy.
			r.Subject = original.Request.Subject
			r.DecisionRecord = original
			operation, err := versions.Begin(ctx, r)
			if err != nil {
				t.Fatalf("producer evidence rejected at Begin: %v", err)
			}
			operation = prepared(t, versions, operation)
			current := authority(versions, operation)
			// The synthetic current policy uses the actual verified role/grant domain,
			// not a canonical label substituted into the historical decision.
			current.Role = original.Authorization.Role
			current.PolicyVersion = original.Authorization.PolicyVersion
			current.GrantIDs = append([]string(nil), original.Authorization.GrantIDs...)
			operation, err = versions.Reserve(ctx, step(operation), current)
			if err != nil {
				t.Fatalf("producer domain rejected at Reserve: %v", err)
			}
			operation = retired(t, versions, operation)
			operation, err = versions.Commit(ctx, step(operation), receipt(versions, operation, "commit"))
			if err != nil {
				t.Fatal(err)
			}
			assertExactDecisionProjection(t, original, operation.Request.DecisionRecord)
			if operation.Reserved == nil {
				t.Fatal("missing reserved authority")
			}
			assertExactDecisionProjection(t, original, operation.Reserved.DecisionRecord)
			versions = reopen(t, versions, path)
			retained, err := versions.ReadOperation(ctx, operation.ID)
			if err != nil {
				t.Fatal(err)
			}
			assertExactDecisionProjection(t, original, retained.Request.DecisionRecord)
			if retained.Reserved == nil {
				t.Fatal("missing retained reserved authority")
			}
			assertExactDecisionProjection(t, original, retained.Reserved.DecisionRecord)
		})
	}
}
func assertExactDecisionProjection(t *testing.T, original, retained decisionrecord.DecisionRecord) {
	t.Helper()
	if !reflect.DeepEqual(original, retained) {
		t.Fatal("consumer changed recorded evidence during projection or persistence")
	}
}
