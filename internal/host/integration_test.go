package host

import (
	"context"
	"database/sql"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
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
	// Construct a v4-shaped fixture by removing later ownership and model-policy
	// additions. This is test setup, NOT a supported rollback path.
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
	if err != nil || version != sqlitelog.SchemaVersion {
		t.Fatalf("journal not upgraded to v%d: %d %v", sqlitelog.SchemaVersion, version, err)
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

// Catches missing per-tool dedup wiring at the real host assembly boundary.
// The executor commits before its reply; host loss must leave a trailing intent,
// and only an exact durable declaration may redrive it under its original key.
func TestInterruptedDeclaredToolRecovery(t *testing.T) {
	for _, declaration := range []string{"true", "false", "omitted"} {
		t.Run(declaration, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			f := newHostFixture(t)
			f.harness.mediation = api.MediationControllerMediated
			reached, release := make(chan struct{}), make(chan struct{})
			var first atomic.Bool
			var unblock sync.Once
			t.Cleanup(func() { unblock.Do(func() { close(release) }) })
			f.afterEffect = func() {
				if first.CompareAndSwap(false, true) {
					close(reached)
					<-release
				}
			}
			_, c, stop := f.start(t)
			s, err := c.CreateSession(ctx, &v1.Session{Harness: "release-notes"})
			if err != nil {
				t.Fatal(err)
			}
			uid := s.GetMetadata().GetUid()
			done := make(chan error, 1)
			go func() {
				_, err := c.Exec(ctx, client.ExecOptions{Session: uid, Inputs: []string{"Publish this"}})
				done <- err
			}()
			select {
			case <-reached:
			case <-ctx.Done():
				t.Fatal("executor did not reach the committed-effect barrier")
			}
			stop()
			unblock.Do(func() { close(release) })
			if err := <-done; err == nil {
				t.Fatal("interrupted Exec unexpectedly completed")
			}
			config, err := os.ReadFile(f.config.ToolExecutors)
			if err != nil {
				t.Fatal(err)
			}
			if declaration == "omitted" {
				config = []byte(strings.Replace(string(config), `,"durable_dedup":true`, "", 1))
			} else {
				config = []byte(strings.Replace(string(config), `"durable_dedup":true`, `"durable_dedup":`+declaration, 1))
			}
			if err := os.WriteFile(f.config.ToolExecutors, config, 0600); err != nil {
				t.Fatal(err)
			}
			_, c, _ = f.start(t)
			before, err := c.Replay(ctx, uid, 0, 0)
			if err != nil || len(before) == 0 {
				t.Fatalf("read interrupted execution: %v", err)
			}
			var intent *v1.LogRecord
			for _, r := range before {
				switch r.GetEvent().GetKind() {
				case v1.EventKind_EVENT_TOOL_CALL:
					intent = r
				case v1.EventKind_EVENT_TOOL_RESULT, v1.EventKind_EVENT_END:
					t.Fatal("interruption recorded a tool receipt or END")
				}
			}
			if intent == nil {
				t.Fatal("interruption has no tool intent")
			}
			head := before[len(before)-1].GetSeq()
			_, err = c.Sessions().Resume(ctx, &v1.ResumeRequest{Session: uid, ExpectedLastSeq: &head})
			if declaration == "true" {
				if err != nil {
					t.Fatalf("declared tool recovery: %v", err)
				}
			} else if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), controller.ErrUnansweredToolCall.Error()) {
				t.Fatalf("undeclared tool must refuse ambiguous redrive: %v", err)
			}
			after, err := c.Replay(ctx, uid, 0, 0)
			if err != nil {
				t.Fatal(err)
			}
			attempts := int32(1)
			if declaration == "true" {
				attempts = 2
				ends, receipts := 0, 0
				for _, r := range after {
					if r.GetEvent().GetExecutionId() != intent.GetEvent().GetExecutionId() {
						continue
					}
					if r.GetEvent().GetKind() == v1.EventKind_EVENT_END {
						ends++
					}
					if r.GetEvent().GetKind() == v1.EventKind_EVENT_TOOL_RESULT && r.GetEvent().GetResult().GetId() == intent.GetEvent().GetTool().GetId() {
						receipts++
					}
				}
				if ends != 1 || receipts != 1 {
					t.Fatalf("recovered invocation ends=%d receipts=%d", ends, receipts)
				}
			} else if !reflect.DeepEqual(before, after) {
				t.Fatal("refused recovery changed the journal")
			}
			var effects, matching int
			if err := f.effects.QueryRow(`SELECT count(*), count(CASE WHEN uid=? AND key=? THEN 1 END) FROM effects`, uid, intent.GetEvent().GetTool().GetIdempotencyKey()).Scan(&effects, &matching); err != nil {
				t.Fatal(err)
			}
			if f.models.Load() != 1 || f.sockets.Load() != attempts || effects != 1 || matching != 1 {
				t.Fatalf("recovery models=%d executor attempts=%d effects=%d matching session/key=%d", f.models.Load(), f.sockets.Load(), effects, matching)
			}
		})
	}
}

// Required binds newly created sessions to the admitted caller. Independent
// approval authority allows decisions and reads, never another owner's recovery.
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
	created, err := c.CreateSession(owner, &v1.Session{Harness: "release-notes"})
	if err != nil {
		t.Fatal(err)
	}
	uid := created.GetMetadata().GetUid()
	info, err := app.store.SessionInfo(uid)
	if err != nil || info.Owner != (api.CallerIdentity{Issuer: fixtureIssuer, Subject: ownerOID}) {
		t.Errorf("CreateSession did not capture verified owner: %+v %v", info.Owner, err)
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
	before, err = app.store.Session(uid).Read(1)
	if err != nil {
		t.Fatal(err)
	}
	runs := f.harness.runs.Load()
	if resumed, err := c.Resume(approver, uid, false); status.Code(err) != codes.PermissionDenied || resumed != nil {
		t.Fatalf("approver cannot resume another owner's session: %v", err)
	}
	after, err = app.store.Session(uid).Read(1)
	if err != nil || !reflect.DeepEqual(before, after) || f.harness.runs.Load() != runs || f.models.Load() != 1 || f.sockets.Load() != 0 {
		t.Fatal("denied approver recovery changed journal or invoked runtime/effects")
	}
	if _, err := c.Resume(owner, uid, false); err != nil {
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
