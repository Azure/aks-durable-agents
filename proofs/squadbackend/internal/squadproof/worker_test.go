//go:build squadproof

package squadproof

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agent-primitives/sessions/api"
	v1 "github.com/agent-primitives/sessions/api/genpb"
	"github.com/agent-primitives/sessions/client"
	"github.com/agent-primitives/sessions/eventlog"
	"github.com/agent-primitives/sessions/wire"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func workerLead(t *testing.T, l *Ledger, payload string) {
	t.Helper()
	if _, err := l.Admit(t.Context(), Operation{ID: "lead", Kind: "lead", Team: "proof-team", PackageDigest: proofDigest(), Member: "lead", Epoch: 1, Payload: []byte(payload)}); err != nil {
		t.Fatal(err)
	}
}

// Catches allocation being sent without a durable intent, and attempts to adopt
// or retry an allocation whose response was lost.
func TestBrokerAllocationIntentHolds(t *testing.T) {
	l, _ := openTestLedger(t)
	workerLead(t, l, `{"kind":"start"}`)
	if err := l.beginAllocation(t.Context(), "lead"); err != nil {
		t.Fatal(err)
	}
	w := &Worker{Ledger: l}
	for range 2 {
		if err := w.Reconcile(t.Context()); !errors.Is(err, ErrHeld) {
			t.Fatalf("lost allocation: %v", err)
		}
		op, _ := l.Operation(t.Context(), "lead")
		if op.State != "uncertain" || op.SessionUID != "" || op.Reason != "lost-create" {
			t.Fatalf("adopted/retried allocation: %+v", op)
		}
	}
	if n, _ := l.attemptCount(t.Context(), "rpc-create"); n != 0 {
		t.Fatalf("retried: %d", n)
	}
}

// Catches using Replay as an acknowledgement, and releasing an unknown Exec.
func TestBrokerDeliveringInputHolds(t *testing.T) {
	l, _ := openTestLedger(t)
	op := seedLead(t, l)
	if _, err := l.Enqueue(t.Context(), Input{ID: "initial-lead", Target: op.ID, Kind: "user", Payload: op.Payload}); err != nil {
		t.Fatal(err)
	}
	if _, err := l.NextInput(t.Context(), op.ID, op.Epoch, 0); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := (&Worker{Ledger: l}).Reconcile(t.Context()); !errors.Is(err, ErrHeld) {
			t.Fatalf("unknown exec: %v", err)
		}
	}
	inputs, _ := l.Inputs(t.Context(), op.ID)
	if inputs[0].State != "delivering" || inputs[0].ExecutionID != "" {
		t.Fatalf("unknown delivery released: %+v", inputs)
	}
}

// Catches implicit SDK allocation through empty-UID Exec, and empty-UID reads.
func TestBrokerRejectsEmptyUID(t *testing.T) {
	l, _ := openTestLedger(t)
	workerLead(t, l, `{"kind":"start"}`)
	w := &Worker{Ledger: l}
	if _, err := w.Inspect(t.Context(), "lead"); !errors.Is(err, ErrHeld) {
		t.Fatalf("empty UID inspection: %v", err)
	}
	if err := w.execute(t.Context(), Operation{ID: "lead"}, Input{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("implicit allocation: %v", err)
	}
	if n, _ := l.attemptCount(t.Context(), "rpc-exec"); n != 0 {
		t.Fatal("sent empty-UID Exec")
	}
}

// Catches auto-approval, non-resumed decisions, result injection into the old
// execution, and historical decisions rearming an already completed action.
func TestBrokerSDKWorkflow(t *testing.T) {
	for _, approved := range []bool{true, false} {
		t.Run(map[bool]string{true: "approve", false: "deny"}[approved], func(t *testing.T) {
			l, path := openTestLedger(t)
			c, _ := startProofHost(t, l, filepath.Dir(path))
			workerLead(t, l, `{"kind":"start"}`)
			w := &Worker{Ledger: l, Sessions: c}
			decisions := map[string]api.ApprovalDecision{}
			for range 45 {
				if err := w.Reconcile(t.Context()); err != nil {
					t.Fatal(err)
				}
				ops, err := l.Operations(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				for _, op := range ops {
					if op.SessionUID == "" || op.Evidence.ExecutionID == "" {
						continue
					}
					v, err := w.Inspect(t.Context(), op.ID)
					if err != nil {
						t.Fatal(err)
					}
					if v.Evidence.RequestSeq > 0 && v.Evidence.DecisionSeq == 0 {
						d := api.ApprovalDecision{ExecutionID: v.Request.ExecutionID, ToolCallID: v.Request.ToolCallID, RequestSeq: v.Request.RequestSeq, Approved: approved, Reason: "trusted test decision", Identity: api.IdentityRef{Principal: "proof-approver"}}
						if err = w.Decide(t.Context(), op.ID, d); err != nil {
							t.Fatal(err)
						}
						decisions[op.ID] = d
					}
				}
			}
			inputs, err := l.Inputs(t.Context(), "lead")
			if err != nil {
				t.Fatal(err)
			}
			if len(inputs) != 2 || inputs[0].ID != "initial-lead" || inputs[1].Kind != "result" || inputs[1].State != "delivered" || inputs[1].ExecutionID == inputs[0].ExecutionID {
				t.Fatalf("result was not a fresh input: %+v", inputs)
			}
			stats, _ := l.Counts(t.Context())
			wantEffects := 0
			if approved {
				wantEffects = 1
			}
			if stats.Operations != 2 || stats.Effects != wantEffects {
				t.Fatalf("bad workflow counts: %+v", stats)
			}
			before, _ := l.attemptCount(t.Context(), "rpc-resume")
			for id, d := range decisions {
				if err := w.Decide(t.Context(), id, d); err != nil {
					t.Fatalf("historical exact retry: %v", err)
				}
				d.Reason = "changed"
				if err := w.Decide(t.Context(), id, d); !errors.Is(err, ErrConflict) {
					t.Fatalf("changed historical decision: %v", err)
				}
			}
			for range 3 {
				if err := w.Reconcile(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
			after, _ := l.attemptCount(t.Context(), "rpc-resume")
			if before != 2 || after != before {
				t.Fatalf("historical retry resumed: %d -> %d", before, after)
			}
			if n, _ := l.attemptCount(t.Context(), "rpc-exec"); n != 3 {
				t.Fatalf("wrong Exec count: %d", n)
			}
		})
	}
}

// A narrow wire-boundary server exercises SDK failures without manufacturing a
// private execution ACK. Successful team behavior uses the actual host above.
type brokerBoundary struct {
	v1.UnimplementedSessionsServer
	log                     *eventlog.Log
	creates, execs, resumes int
}

func (s *brokerBoundary) GetSession(context.Context, *v1.GetSessionRequest) (*v1.Session, error) {
	return &v1.Session{Metadata: &v1.ResourceMetadata{Uid: "session-lead"}, LastSeq: s.log.Head(), PendingApproval: &v1.ApprovalRef{ExecutionId: "spoofed-projection", ToolCallId: "spoofed", RequestSeq: 999}}, nil
}
func (s *brokerBoundary) Replay(_ *v1.ReplayRequest, stream v1.Sessions_ReplayServer) error {
	for _, r := range s.log.Snapshot() {
		if err := stream.Send(eventlog.RecordToProto(r)); err != nil {
			return err
		}
	}
	return nil
}
func (s *brokerBoundary) CreateSession(context.Context, *v1.CreateSessionRequest) (*v1.Session, error) {
	s.creates++
	return nil, status.Error(codes.Unavailable, "lost create response")
}
func (s *brokerBoundary) Exec(*v1.ExecRequest, v1.Sessions_ExecServer) error {
	s.execs++
	return status.Error(codes.Aborted, "pre-start refusal")
}
func (s *brokerBoundary) Approve(_ context.Context, q *v1.ApproveRequest) (*v1.ApproveResponse, error) {
	ev := wire.EventFromProto(wire.EventToProto(api.Event{Kind: api.EventApprovalResult, ExecutionID: q.GetExecutionId(), ApprovalResult: &api.ApprovalResult{ToolCallID: q.GetToolCallId(), RequestSeq: q.GetRequestSeq(), Approved: q.GetApproved(), Reason: q.GetReason()}}))
	if q.GetIdentity() != nil {
		ev.Actor = api.IdentityRef{Principal: q.GetIdentity().GetPrincipal(), Issuer: q.GetIdentity().GetIssuer(), Subject: q.GetIdentity().GetSubject()}
	}
	r, err := s.log.Append(s.log.Head(), 0, ev)
	return &v1.ApproveResponse{Decision: eventlog.RecordToProto(r)}, err
}
func (s *brokerBoundary) Resume(_ context.Context, q *v1.ResumeRequest) (*v1.Session, error) {
	s.resumes++
	if q.ExpectedLastSeq == nil || q.GetExpectedLastSeq() != s.log.Head() {
		return nil, status.Error(codes.InvalidArgument, "missing verified CAS")
	}
	return nil, status.Error(codes.Aborted, "stale CAS")
}
func dialBrokerBoundary(t *testing.T, s *brokerBoundary) *client.Client {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	v1.RegisterSessionsServer(server, s)
	go server.Serve(ln)
	c, err := client.Dial(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(); server.Stop(); ln.Close() })
	return c
}
func appendBrokerEvents(t *testing.T, log *eventlog.Log, events ...api.Event) {
	t.Helper()
	for _, e := range events {
		if _, err := log.Append(log.Head(), 0, e); err != nil {
			t.Fatal(err)
		}
	}
}
func brokerGateEvents() []api.Event {
	n := int64(1)
	return []api.Event{
		{Kind: api.EventExecutionStart, ExecutionID: "exec", ExecutionStart: &api.ExecutionStart{InputCount: &n, Harness: "proof-lead"}},
		{Kind: api.EventToolCall, ExecutionID: "exec", ToolCall: &api.ToolCall{ID: "call", Tool: "checkpoint", Mediation: api.MediationRequiresApproval}},
		{Kind: api.EventApprovalRequest, ExecutionID: "exec", Approval: &api.ApprovalRequest{ToolCallID: "call"}},
	}
}
func TestBrokerCreateIntentIsNamespacedJSON(t *testing.T) {
	l, _ := openTestLedger(t)
	workerLead(t, l, `{"kind":"start"}`)
	if err := l.beginAllocation(t.Context(), "lead"); err != nil {
		t.Fatal(err)
	}
	var raw []byte
	if err := l.db.QueryRow(`SELECT operation FROM events WHERE kind='broker.create'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if !json.Valid(raw) {
		t.Fatalf("create intent is not JSON: %q", raw)
	}
}
func TestBrokerEnsuresInitialDespiteQueuedFollowup(t *testing.T) {
	l, path := openTestLedger(t)
	c, _ := startProofHost(t, l, filepath.Dir(path))
	workerLead(t, l, `{"kind":"admitted"}`)
	w := &Worker{Ledger: l, Sessions: c}
	if _, err := w.Enqueue(t.Context(), Input{ID: "followup", Target: "lead", Kind: "user", Payload: []byte(`{"kind":"later"}`)}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := w.Reconcile(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	inputs, _ := l.Inputs(t.Context(), "lead")
	if len(inputs) != 2 || inputs[0].ID != "initial-lead" || inputs[0].State != "delivered" || string(inputs[0].Payload) != `{"kind":"admitted"}` || inputs[1].State != "queued" {
		t.Fatalf("admitted payload did not run first: %+v", inputs)
	}
	for range 3 {
		if err := w.Reconcile(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	inputs, _ = l.Inputs(t.Context(), "lead")
	if inputs[1].State != "delivered" || inputs[0].ExecutionID == inputs[1].ExecutionID {
		t.Fatalf("followup not delivered once after initial: %+v", inputs)
	}
	v, err := w.Inspect(t.Context(), "lead")
	if err != nil || v.Evidence.EndSeq == 0 {
		t.Fatalf("followup never completed: %+v %v", v.Evidence, err)
	}
}
func TestBrokerCallbackFailureCannotAdoptJournalACK(t *testing.T) {
	for _, point := range []string{"broker.before-ack", "broker.after-ack"} {
		t.Run(point, func(t *testing.T) {
			l, path := openTestLedger(t)
			c, _ := startProofHost(t, l, filepath.Dir(path))
			workerLead(t, l, `{"kind":"start"}`)
			w := &Worker{Ledger: l, Sessions: c}
			for range 2 {
				if err := w.Reconcile(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := l.db.Exec(`INSERT INTO events(kind,operation) VALUES(?,?)`, "fault.arm."+point, `{"mode":"invalid"}`); err != nil {
				t.Fatal(err)
			}
			if err := w.Reconcile(t.Context()); !errors.Is(err, ErrForeign) {
				t.Fatalf("callback error hidden: %v", err)
			}
			op, _ := l.Operation(t.Context(), "lead")
			if op.State != "uncertain" {
				t.Fatalf("failed callback adopted: %+v", op)
			}
			if err := w.Reconcile(t.Context()); !errors.Is(err, ErrHeld) {
				t.Fatalf("callback failure recovered: %v", err)
			}
			inputs, _ := l.Inputs(t.Context(), "lead")
			want := "delivering"
			if point == "broker.after-ack" {
				want = "delivered"
			}
			if inputs[0].State != want {
				t.Fatalf("callback ordering: %+v", inputs)
			}
			if n, _ := l.attemptCount(t.Context(), "rpc-exec"); n != 1 {
				t.Fatalf("callback retry: %d", n)
			}
		})
	}
}
func TestBrokerUnknownRPCsNeverRetry(t *testing.T) {
	for _, kind := range []string{"create", "exec"} {
		t.Run(kind, func(t *testing.T) {
			l, _ := openTestLedger(t)
			workerLead(t, l, `{"kind":"start"}`)
			s := &brokerBoundary{log: eventlog.New()}
			w := &Worker{Ledger: l, Sessions: dialBrokerBoundary(t, s)}
			if kind == "exec" {
				if err := l.BindSession(t.Context(), "lead", "session-lead"); err != nil {
					t.Fatal(err)
				}
				if err := w.Reconcile(t.Context()); err != nil {
					t.Fatal(err)
				} // stable initial input
			}
			if err := w.Reconcile(t.Context()); err == nil {
				t.Fatal("RPC failure disappeared")
			}
			for range 2 {
				if err := w.Reconcile(t.Context()); !errors.Is(err, ErrHeld) {
					t.Fatalf("unknown was retried: %v", err)
				}
			}
			op, _ := l.Operation(t.Context(), "lead")
			if op.State != "uncertain" || op.Reason != "lost-"+kind {
				t.Fatalf("not durably held: %+v", op)
			}
			if s.creates+s.execs != 1 || s.resumes != 0 {
				t.Fatalf("resent mutation: %+v", s)
			}
			if kind == "exec" {
				inputs, _ := l.Inputs(t.Context(), "lead")
				if inputs[0].State != "delivering" || inputs[0].ExecutionID != "" {
					t.Fatalf("pre-start ABORTED released input: %+v", inputs)
				}
			}
		})
	}
}
func TestBrokerStaleResumeHeldAndHistoricalDecisionImmutable(t *testing.T) {
	l, _ := openTestLedger(t)
	op := seedLead(t, l)
	in := initialInput(op)
	if _, err := l.Enqueue(t.Context(), in); err != nil {
		t.Fatal(err)
	}
	if _, err := l.NextInput(t.Context(), op.ID, op.Epoch, 0); err != nil {
		t.Fatal(err)
	}
	if err := l.ConfirmInput(t.Context(), in.ID, "exec"); err != nil {
		t.Fatal(err)
	}
	s := &brokerBoundary{log: eventlog.New()}
	appendBrokerEvents(t, s.log, brokerGateEvents()...)
	w := &Worker{Ledger: l, Sessions: dialBrokerBoundary(t, s)}
	d := api.ApprovalDecision{ExecutionID: "exec", ToolCallID: "call", RequestSeq: 3, Approved: true, Reason: "trusted"}
	if err := w.Decide(t.Context(), "lead", d); err != nil {
		t.Fatal(err)
	}
	if err := w.Reconcile(t.Context()); status.Code(err) != codes.Aborted {
		t.Fatalf("stale error lost: %v", err)
	}
	appendBrokerEvents(t, s.log, api.Event{Kind: api.EventLifecycle, Lifecycle: &api.Lifecycle{Kind: api.LifecycleSuspend}})
	for range 2 {
		if err := w.Decide(t.Context(), "lead", d); err != nil {
			t.Fatal(err)
		}
		if err := w.Reconcile(t.Context()); !errors.Is(err, ErrHeld) {
			t.Fatalf("advanced rejected CAS: %v", err)
		}
	}
	if s.resumes != 1 {
		t.Fatalf("stale cursor advanced: %d", s.resumes)
	}
	actions, err := brokerActions(t.Context(), l.db)
	if err != nil || len(actions) != 1 || actions[0].Head != 4 || actions[0].Phase != "held" || actions[0].Seq != 4 {
		t.Fatalf("held obligation lost: %+v %v", actions, err)
	}
	d.Identity.Principal = "changed"
	if err := w.Decide(t.Context(), "lead", d); !errors.Is(err, ErrConflict) {
		t.Fatalf("identity changed: %v", err)
	}
	d.RequestSeq = 2
	if err := w.Decide(t.Context(), "lead", d); !errors.Is(err, ErrConflict) {
		t.Fatalf("invented historical decision: %v", err)
	}
}

// Catches accepting unrelated receipts, a first receipt clearing a later gate,
// projection-only decisions, forged ownership, or unverified journal tails.
func TestBrokerScannerCorrelatesCurrentExecution(t *testing.T) {
	events := brokerGateEvents()
	events = append(events,
		api.Event{Kind: api.EventApprovalResult, ExecutionID: "exec", ApprovalResult: &api.ApprovalResult{ToolCallID: "call", RequestSeq: 3, Approved: true}},
		api.Event{Kind: api.EventToolResult, ExecutionID: "exec", Result: &api.ToolResult{ID: "call", ApprovalRequestSeq: 3, ApprovalDecisionSeq: 4}},
		api.Event{Kind: api.EventOutput, ExecutionID: "exec", Message: api.TextMessage("assistant", "recorded summary")},
		api.Event{Kind: api.EventEnd, ExecutionID: "exec", End: &api.HarnessEnd{State: "COMPLETED"}},
	)
	for _, mode := range []string{"valid", "receipt-before-end", "second-request", "wrong-receipt", "wrong-call", "failed-end", "foreign-execution", "early-start", "wrong-head", "gap", "hash", "oversized-output"} {
		t.Run(mode, func(t *testing.T) {
			raw, _ := json.Marshal(events)
			var es []api.Event
			_ = json.Unmarshal(raw, &es)
			op := Operation{State: "running", Member: "lead", Evidence: Evidence{ExecutionID: "exec"}}
			switch mode {
			case "receipt-before-end":
				es = es[:5]
			case "second-request":
				es = append(es[:5], api.Event{Kind: api.EventToolCall, ExecutionID: "exec", ToolCall: &api.ToolCall{ID: "second", Mediation: api.MediationRequiresApproval}}, api.Event{Kind: api.EventApprovalRequest, ExecutionID: "exec", Approval: &api.ApprovalRequest{ToolCallID: "second"}})
			case "wrong-receipt":
				es[4].Result.ApprovalDecisionSeq = 3
			case "wrong-call":
				es[4].Result.ID = "other"
			case "failed-end":
				es[6].End.State = "FAILED"
			case "foreign-execution":
				es[6].ExecutionID = "other"
			case "early-start":
				op.InputHeadSeq = 1
			case "oversized-output":
				es[5].Message = api.TextMessage("assistant", strings.Repeat("a", 8193))
			}
			log := eventlog.New()
			appendBrokerEvents(t, log, es...)
			var records []*v1.LogRecord
			for _, r := range log.Snapshot() {
				records = append(records, eventlog.RecordToProto(r))
			}
			session := &v1.Session{LastSeq: int64(len(records))}
			if mode == "wrong-head" {
				session.LastSeq++
			}
			if mode == "gap" {
				records[2].Seq++
			}
			if mode == "hash" {
				records[2].ContentHash = strings.Repeat("f", 64)
			}
			v, err := scanJournal(op, session, records)
			if mode != "valid" && mode != "receipt-before-end" && mode != "second-request" {
				if err == nil {
					t.Fatalf("accepted %s", mode)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if mode == "second-request" {
				if v.Evidence.RequestSeq != 7 || v.Evidence.ReceiptSeq != 0 || v.Evidence.DecisionSeq != 0 || v.Evidence.EndSeq != 0 || v.Request.ToolCallID != "second" {
					t.Fatalf("first receipt cleared new gate: %+v", v)
				}
			} else if mode == "receipt-before-end" {
				if v.Evidence.EndSeq != 0 || v.Evidence.ReceiptSeq != 5 {
					t.Fatalf("receipt mistaken for END: %+v", v)
				}
			} else if v.Evidence.EndSeq != 7 || v.Output != "recorded summary" {
				t.Fatalf("bad terminal: %+v", v)
			}
		})
	}
}
