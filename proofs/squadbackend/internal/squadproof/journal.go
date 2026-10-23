//go:build squadproof

package squadproof

import (
	"context"
	"unicode/utf8"

	"github.com/agent-primitives/sessions/api"
	v1 "github.com/agent-primitives/sessions/api/genpb"
	"github.com/agent-primitives/sessions/eventlog"
	"github.com/agent-primitives/sessions/wire"
)

type View struct {
	Session  *v1.Session
	Records  []*v1.LogRecord
	Evidence Evidence
	Request  api.ApprovalRef
	Output   string
}

// Inspect never derives an execution acknowledgement from Replay or a session
// projection. Only the input owner's durable OnRecord ACK supplies that identity.
func (w *Worker) Inspect(ctx context.Context, id string) (View, error) {
	op, err := w.Ledger.Operation(ctx, id)
	if err != nil {
		return View{}, err
	}
	if op.SessionUID == "" || op.State == "uncertain" {
		return View{}, ErrHeld
	}
	if op.ParentID != "" {
		root, e := w.Ledger.Operation(ctx, op.ParentID)
		if e != nil {
			return View{}, e
		}
		if root.State == "uncertain" || root.Epoch != op.Epoch {
			return View{}, ErrHeld
		}
	}
	inputs, err := w.Ledger.Inputs(ctx, id)
	if err != nil {
		return View{}, err
	}
	owned := op.Evidence.ExecutionID == ""
	for _, in := range inputs {
		if in.State == "delivering" {
			return View{}, ErrHeld
		}
		if in.ExecutionID == op.Evidence.ExecutionID && in.State == "delivered" && in.Epoch == op.Epoch && in.HeadSeq == op.InputHeadSeq {
			owned = true
		}
	}
	if !owned {
		return View{}, ErrHeld
	}
	records, err := w.Sessions.Replay(ctx, op.SessionUID, 0, 0)
	if err != nil {
		return View{}, err
	}
	session, err := w.Sessions.GetSession(ctx, op.SessionUID)
	if err != nil {
		return View{}, err
	}
	if session.GetMetadata().GetUid() != op.SessionUID {
		return View{}, ErrConflict
	}
	return scanJournal(op, session, records)
}

func scanJournal(op Operation, s *v1.Session, records []*v1.LogRecord) (View, error) {
	v := View{Session: s, Records: records}
	domain := make([]eventlog.Record, 0, len(records))
	for i, r := range records {
		if r == nil || r.GetEvent() == nil || r.GetSeq() != int64(i+1) {
			return v, ErrInvalid
		}
		domain = append(domain, eventlog.Record{Seq: r.GetSeq(), PrevHash: r.GetPrevHash(), Hash: r.GetContentHash(), Fence: r.GetFence(), Event: wire.EventFromProto(r.GetEvent())})
	}
	if err := eventlog.NewFrom(domain).Verify(); err != nil {
		return v, err
	}
	if s.GetLastSeq() != int64(len(records)) {
		return v, ErrConflict
	}
	if len(domain) == 0 {
		if op.State != "mapped" || op.Evidence.ExecutionID != "" {
			return v, ErrHeld
		}
		return v, nil
	}
	e := Evidence{ExecutionID: op.Evidence.ExecutionID, HeadSeq: domain[len(domain)-1].Seq, HeadHash: domain[len(domain)-1].Hash}
	if e.ExecutionID == "" {
		return v, ErrHeld
	}
	type callState struct {
		call                       *api.ToolCall
		request, decision, receipt int64
	}
	calls := map[string]*callState{}
	started := false
	ended := false
	for _, r := range domain {
		ev := r.Event
		if r.Seq <= op.InputHeadSeq || ev.Kind == api.EventLifecycle {
			continue
		}
		if ev.ExecutionID != e.ExecutionID || ended {
			return v, ErrConflict
		}
		if ev.Kind == api.EventExecutionStart {
			if started || ev.ExecutionStart == nil || ev.ExecutionStart.Harness != "proof-"+op.Member {
				return v, ErrConflict
			}
			started = true
		} else if !started {
			return v, ErrConflict
		}
		switch ev.Kind {
		case api.EventToolCall:
			c := ev.ToolCall
			if c == nil || c.ID == "" || calls[c.ID] != nil {
				return v, ErrConflict
			}
			calls[c.ID] = &callState{call: c}
		case api.EventApprovalRequest:
			if ev.Approval == nil {
				return v, ErrConflict
			}
			c := calls[ev.Approval.ToolCallID]
			if c == nil || c.call.Mediation != api.MediationRequiresApproval || c.request != 0 || e.RequestSeq > 0 && e.ReceiptSeq == 0 {
				return v, ErrConflict
			}
			c.request = r.Seq
			e.RequestSeq, e.DecisionSeq, e.ReceiptSeq = r.Seq, 0, 0
			v.Request = api.ApprovalRef{ExecutionID: e.ExecutionID, ToolCallID: c.call.ID, RequestSeq: r.Seq}
		case api.EventApprovalResult:
			d := ev.ApprovalResult
			if d == nil {
				return v, ErrConflict
			}
			c := calls[d.ToolCallID]
			if c == nil || c.request != d.RequestSeq || d.RequestSeq != e.RequestSeq || c.decision != 0 {
				return v, ErrConflict
			}
			c.decision = r.Seq
			e.DecisionSeq = r.Seq
		case api.EventToolResult:
			result := ev.Result
			if result == nil {
				return v, ErrConflict
			}
			c := calls[result.ID]
			if c == nil || c.receipt != 0 {
				return v, ErrConflict
			}
			if c.call.Mediation == api.MediationRequiresApproval {
				if c.request == 0 || c.decision == 0 || result.ApprovalRequestSeq != c.request || result.ApprovalDecisionSeq != c.decision {
					return v, ErrConflict
				}
				if c.request == e.RequestSeq {
					e.ReceiptSeq = r.Seq
				}
			} else if result.ApprovalRequestSeq != 0 || result.ApprovalDecisionSeq != 0 {
				return v, ErrConflict
			}
			c.receipt = r.Seq
		case api.EventOutput:
			if ev.Message == nil {
				return v, ErrInvalid
			}
			v.Output = ev.Message.Text()
			if len(v.Output) > 8192 || !utf8.ValidString(v.Output) {
				return v, ErrInvalid
			}
		case api.EventEnd:
			if ev.End == nil || ev.End.State != "COMPLETED" {
				return v, ErrHeld
			}
			for _, c := range calls {
				if c.receipt == 0 {
					return v, ErrHeld
				}
			}
			e.EndSeq, e.EndHash = r.Seq, r.Hash
			ended = true
		}
	}
	if !started || !e.valid() {
		return v, ErrHeld
	}
	v.Evidence = e
	return v, nil
}

func matchingDecision(v View, a brokerAction) bool {
	for _, r := range v.Records {
		if r.GetSeq() == a.Seq {
			ev := wire.EventFromProto(r.GetEvent())
			d := ev.ApprovalResult
			return ev.ExecutionID == a.Decision.ExecutionID && d != nil && d.RequestSeq == a.Decision.RequestSeq && d.ToolCallID == a.Decision.ToolCallID && d.Approved == a.Decision.Approved && d.Reason == a.Decision.Reason && ev.Actor == a.Decision.Identity
		}
	}
	return false
}
func actionComplete(v View, a brokerAction) bool {
	if a.Decision.RequestSeq == 0 {
		return v.Evidence.EndSeq > 0
	}
	for _, r := range v.Records {
		ev := wire.EventFromProto(r.GetEvent())
		receipt := ev.Result
		if ev.ExecutionID == a.Decision.ExecutionID && receipt != nil && receipt.ID == a.Decision.ToolCallID && receipt.ApprovalRequestSeq == a.Decision.RequestSeq && receipt.ApprovalDecisionSeq == a.Seq {
			return v.Evidence.EndSeq > 0 || v.Evidence.RequestSeq > a.Decision.RequestSeq
		}
	}
	return false
}
