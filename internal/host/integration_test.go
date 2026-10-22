package host

import (
	"context"
	"database/sql"
	"reflect"
	"testing"
	"time"

	"github.com/agent-primitives/sessions/api"
	v1 "github.com/agent-primitives/sessions/api/genpb"
	"github.com/agent-primitives/sessions/authn"
	"github.com/agent-primitives/sessions/client"
	"github.com/agent-primitives/sessions/controller"
	"github.com/agent-primitives/sessions/harnesswire"
	"github.com/agent-primitives/sessions/sqlitelog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

func decision(t *testing.T, s *v1.Session, approved bool) api.ApprovalDecision {
	t.Helper()
	p := s.GetPendingApproval()
	if p == nil {
		t.Fatal("execution did not park for approval")
	}
	return api.ApprovalDecision{ExecutionID: p.GetExecutionId(), ToolCallID: p.GetToolCallId(), RequestSeq: p.GetRequestSeq(), Approved: approved}
}

// Catches wiring that skips approval, loses the durable park, reissues model calls
// during recovery, or publishes twice. RPC Replay alone cannot prove determinism.
func TestFixtureAssemblyIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	f := newHostFixture(t)
	_, c, stop := f.start(t)
	a, err := c.Exec(ctx, client.ExecOptions{Harness: "release-notes", Inputs: []string{"Proposal A"}})
	if err != nil {
		t.Fatal(err)
	}
	uid := a.Session.GetMetadata().GetUid()
	if f.models.Load() != 1 || f.sockets.Load() != 0 {
		t.Fatal("first proposal did not park before effect")
	}
	if _, err := c.Approve(ctx, uid, decision(t, a.Session, false)); err != nil {
		t.Fatal(err)
	}
	denied, err := c.Resume(ctx, uid, false)
	if err != nil || denied.GetPendingApproval() != nil {
		t.Fatalf("denied resume: %+v %v", denied, err)
	}
	b, err := c.Exec(ctx, client.ExecOptions{Session: uid, Inputs: []string{"Proposal B"}})
	if err != nil {
		t.Fatal(err)
	}
	approveB := decision(t, b.Session, true)
	if f.models.Load() != 2 || f.sockets.Load() != 0 {
		t.Fatal("second proposal did not park without publishing")
	}
	stop()
	// Construct a v4-shaped fixture by removing v5 ownership and v6 model-policy
	// additions from the stopped journal. This is test setup, NOT a rollback path.
	raw, err := sql.Open("sqlite", f.config.Journal)
	if err != nil {
		t.Fatal(err)
	}
	_, err = raw.Exec(`DROP INDEX sessions_owner_project_created;
 ALTER TABLE sessions DROP COLUMN owner_subject;
 ALTER TABLE sessions DROP COLUMN owner_issuer;
 ALTER TABLE sessions DROP COLUMN model_policy;
 DROP TABLE journal_authorization;
 PRAGMA user_version=4;`)
	if err != nil {
		_ = raw.Close()
		t.Fatal(err)
	}
	if err = raw.Close(); err != nil {
		t.Fatal(err)
	}
	app, c, _ := f.start(t)
	parked, err := c.GetSession(ctx, uid)
	if err != nil || parked.GetLastSeq() != b.Session.GetLastSeq() || !reflect.DeepEqual(decision(t, parked, true), approveB) {
		t.Fatalf("durable approval changed: %+v %v", parked, err)
	}
	if err := app.store.Session(uid).Verify(); err != nil {
		t.Fatal(err)
	}
	check, err := sql.Open("sqlite", f.config.Journal)
	if err != nil {
		t.Fatal(err)
	}
	var version int
	err = check.QueryRow(`PRAGMA user_version`).Scan(&version)
	_ = check.Close()
	if err != nil || version != 6 {
		t.Fatalf("journal not upgraded to v6: %d %v", version, err)
	}
	if _, err := c.Approve(ctx, uid, approveB); err != nil {
		t.Fatal(err)
	}
	if f.sockets.Load() != 0 {
		t.Fatal("Approve executed a tool before Resume")
	}
	published, err := c.Resume(ctx, uid, false)
	if err != nil || published.GetPendingApproval() != nil {
		t.Fatalf("approved resume: %+v %v", published, err)
	}
	records, err := c.Replay(ctx, uid, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	var codesSeen []v1.ToolResult_Code
	for _, r := range records {
		if r.GetEvent().GetKind() == v1.EventKind_EVENT_TOOL_RESULT {
			codesSeen = append(codesSeen, r.GetEvent().GetResult().GetCode())
		}
	}
	if !reflect.DeepEqual(codesSeen, []v1.ToolResult_Code{v1.ToolResult_APPROVAL_DENIED, v1.ToolResult_CODE_UNSPECIFIED}) {
		t.Fatalf("publication receipts: %v", codesSeen)
	}
	conn, err := grpc.NewClient(f.config.Harnesses["release-notes"], grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	replayer, err := controller.New(app.store.Session(uid), func(context.Context, api.ModelRequest) (api.ModelResponse, error) {
		t.Error("replay invoked live model")
		return api.ModelResponse{}, nil
	}, controller.WithSessionUID(uid), controller.WithHarness("release-notes"), controller.WithToolExecutor(func(context.Context, controller.ToolCallContext, api.ToolCall) (api.ToolResult, error) {
		t.Error("replay invoked live executor")
		return api.ToolResult{}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	runs := f.harness.runs.Load()
	outputs, err := replayer.Replay(ctx, harnesswire.NewClientHarness(v1.NewHarnessClient(conn)))
	want := []string{"Fixed release draft.", "Publication denied; nothing published.", "Fixed release draft.", "Published locally: release-notes-demo."}
	if err != nil || !reflect.DeepEqual(outputs, want) {
		t.Fatalf("deterministic replay: %v %v", outputs, err)
	}
	if f.harness.runs.Load() != runs+2 {
		t.Fatal("replay did not re-execute both harness turns")
	}
	var effects int
	if err := f.effects.QueryRow(`SELECT count(*) FROM effects`).Scan(&effects); err != nil {
		t.Fatal(err)
	}
	if f.models.Load() != 2 || f.sockets.Load() != 1 || effects != 1 || replayer.ModelInvocations() != 0 || replayer.ToolInvocations() != 0 {
		t.Fatalf("extra replay effects: models=%d sockets=%d effects=%d", f.models.Load(), f.sockets.Load(), effects)
	}
	f.assertNoSecrets(t, records)
}

// Required is Entra admission plus an independent approval allowlist, not per-RPC
// ownership enforcement. Preseed an owner explicitly: upstream creation is unbound.
func TestRequiredEntraAdmissionAndIndependentApproval(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	f := newHostFixture(t)
	identity, sign := entraFixture(t)
	f.config.Mode, f.config.Identity = authn.Required, identity
	const ownerOID, approverOID = "0a0a0a0a-0000-4000-8000-000000000001", "0b0b0b0b-0000-4000-8000-000000000002"
	f.config.Approvers = []api.CallerIdentity{{Issuer: fixtureIssuer, Subject: approverOID}}
	ownerToken, approverToken := sign(ownerOID), sign(approverOID)
	owner, approver := bearer(ctx, "Bearer "+ownerToken), bearer(ctx, "Bearer "+approverToken)
	app, c, _ := f.start(t)
	for _, tc := range []struct {
		name   string
		values []string
	}{{"missing", nil}, {"bad", []string{"Bearer not-a-jwt"}}, {"duplicate", []string{"Bearer " + ownerToken, "Bearer " + ownerToken}}} {
		t.Run(tc.name, func(t *testing.T) {
			bad := bearer(ctx, tc.values...)
			_, err := c.CreateSession(bad, &v1.Session{})
			if status.Code(err) != codes.Unauthenticated {
				t.Fatalf("unary admission: %v", err)
			}
			_, err = c.Exec(bad, client.ExecOptions{Harness: "release-notes", Inputs: []string{"must not run"}})
			if status.Code(err) != codes.Unauthenticated {
				t.Fatalf("stream admission: %v", err)
			}
		})
	}
	listed, err := c.ListSessions(owner, "")
	if err != nil || len(listed) != 0 || f.models.Load() != 0 || f.sockets.Load() != 0 {
		t.Fatalf("rejected admission reached session/effects: %v %v", listed, err)
	}
	const uid = "owned-proposal"
	if err := app.store.CreateOwnedSession(sqlitelog.SessionMeta{UID: uid, Harness: "release-notes"}, api.CallerIdentity{Issuer: fixtureIssuer, Subject: ownerOID}, false); err != nil {
		t.Fatal(err)
	}
	turn, err := c.Exec(owner, client.ExecOptions{Session: uid, Inputs: []string{"Publish this"}})
	if err != nil {
		t.Fatal(err)
	}
	d := decision(t, turn.Session, true)
	before, err := app.store.Session(uid).Read(1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Approve(owner, uid, d); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-allowlisted owner approval: %v", err)
	}
	after, err := app.store.Session(uid).Read(1)
	if err != nil || !reflect.DeepEqual(before, after) || f.sockets.Load() != 0 {
		t.Fatal("denied owner approval mutated journal or executor")
	}
	if _, err := c.Approve(approver, uid, d); err != nil {
		t.Fatal(err)
	}
	if f.sockets.Load() != 0 {
		t.Fatal("allowlisted approval executed before resume")
	}
	if _, err := c.Resume(approver, uid, false); err != nil {
		t.Fatal(err)
	}
	records, err := c.Replay(approver, uid, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if f.models.Load() != 1 || f.sockets.Load() != 1 {
		t.Fatal("required approval recovery repeated or skipped an effect")
	}
	f.assertNoSecrets(t, records, ownerToken, approverToken)
}
