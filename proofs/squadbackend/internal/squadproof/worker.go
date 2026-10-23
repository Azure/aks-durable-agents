//go:build squadproof

package squadproof

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sync"

	"github.com/agent-primitives/sessions/api"
	v1 "github.com/agent-primitives/sessions/api/genpb"
	"github.com/agent-primitives/sessions/client"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Worker is a single active proof broker. Recovery requires the manager to
// quiesce all writers before reopening the ledger, not an online takeover.
type Worker struct {
	Ledger   *Ledger
	Sessions *client.Client
	mu       sync.Mutex
}

func (w *Worker) Reconcile(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	ops, err := w.Ledger.Operations(ctx)
	if err != nil {
		return err
	}
	for _, op := range ops {
		if op.State == "uncertain" {
			return ErrHeld
		}
		if op.State == "allocating" && op.SessionUID == "" {
			return errors.Join(ErrHeld, w.Ledger.MarkUncertain(ctx, op.ID, "lost-create"))
		}
		inputs, e := w.Ledger.Inputs(ctx, op.ID)
		if e != nil {
			return e
		}
		for _, in := range inputs {
			if in.State == "delivering" {
				return errors.Join(ErrHeld, w.Ledger.MarkUncertain(ctx, op.ID, "lost-exec"))
			}
		}
		if len(inputs) > 0 {
			first, initial := inputs[0], initialInput(op)
			if first.ID != initial.ID || first.Kind != initial.Kind || first.PayloadHash != op.PayloadHash {
				return ErrConflict
			}
		}
	}
	actions, err := brokerActions(ctx, w.Ledger.db)
	if err != nil {
		return err
	}
	for _, a := range actions {
		if a.Phase != "done" {
			return w.driveAction(ctx, a)
		}
	}
	for _, op := range ops {
		if op.State == "admitted" {
			return w.allocate(ctx, op)
		}
		inputs, e := w.Ledger.Inputs(ctx, op.ID)
		if e != nil {
			return e
		}
		initial := false
		for _, in := range inputs {
			if in.ID == "initial-"+op.ID {
				initial = true
			}
		}
		if !initial && op.State == "mapped" {
			_, err = w.Ledger.Enqueue(ctx, initialInput(op))
			return err
		}
		v, e := w.Inspect(ctx, op.ID)
		if e != nil {
			return e
		}
		if v.Evidence.ExecutionID != "" && !reflect.DeepEqual(op.Evidence, v.Evidence) {
			if err = w.Ledger.Observe(ctx, op.ID, v.Evidence); err != nil {
				return err
			}
			if v.Evidence.EndSeq > 0 {
				return w.Ledger.hit(ctx, "broker.after-terminal")
			}
			return nil
		}
		if op.Kind == "dispatch" && op.State == "terminal" {
			parentInputs, e := w.Ledger.Inputs(ctx, op.ParentID)
			if e != nil {
				return e
			}
			exists := false
			for _, in := range parentInputs {
				if in.ID == "result-"+op.ID {
					exists = true
				}
			}
			if !exists {
				payload, e := json.Marshal(map[string]string{"summary": v.Output})
				if e != nil {
					return e
				}
				if _, err = w.Ledger.EnqueueResult(ctx, op.ID, payload); err != nil {
					return err
				}
				return w.Ledger.hit(ctx, "broker.after-result")
			}
		}
		if v.Evidence.ExecutionID != "" && v.Evidence.EndSeq == 0 {
			if v.Evidence.RequestSeq > 0 {
				continue
			}
			a := brokerAction{Op: op.ID, Decision: api.ApprovalDecision{ExecutionID: v.Evidence.ExecutionID}, Phase: "ready"}
			if err = w.Ledger.saveAction(ctx, a); err != nil {
				return err
			}
			return w.driveAction(ctx, a)
		}
		if op.State != "mapped" && op.State != "terminal" {
			continue
		}
		for _, in := range inputs {
			if in.State == "queued" || in.State == "queued-behind-approval" {
				reserved, e := w.Ledger.NextInput(ctx, op.ID, op.Epoch, v.Evidence.HeadSeq)
				if e != nil {
					return e
				}
				if err = w.Ledger.hit(ctx, "broker.after-reserve"); err != nil {
					return err
				}
				return w.execute(ctx, op, reserved)
			}
		}
	}
	return nil
}

func (w *Worker) allocate(ctx context.Context, op Operation) error {
	if w.Sessions == nil || op.PackageDigest != proofDigest() {
		return ErrInvalid
	}
	if err := w.Ledger.beginAllocation(ctx, op.ID); err != nil {
		return err
	}
	if _, err := w.Ledger.attempt(ctx, "rpc-create", op.ID); err != nil {
		return err
	}
	session, err := w.Sessions.CreateSession(ctx, &v1.Session{Harness: "proof-" + op.Member})
	if err != nil {
		return errors.Join(err, w.Ledger.MarkUncertain(ctx, op.ID, "lost-create"))
	}
	if err = w.Ledger.hit(ctx, "broker.after-create"); err != nil {
		return err
	}
	if session.GetMetadata().GetUid() == "" {
		return errors.Join(ErrHeld, w.Ledger.MarkUncertain(ctx, op.ID, "lost-create"))
	}
	return w.Ledger.BindSession(ctx, op.ID, session.GetMetadata().GetUid())
}
func (w *Worker) execute(ctx context.Context, op Operation, in Input) error {
	if op.SessionUID == "" || w.Sessions == nil || op.PackageDigest != proofDigest() {
		return ErrInvalid
	}
	if _, err := w.Ledger.attempt(ctx, "rpc-exec", op.ID); err != nil {
		return err
	}
	ack := false
	var callbackErr error
	_, err := w.Sessions.Exec(ctx, client.ExecOptions{Session: op.SessionUID, Inputs: []string{string(in.Payload)}, ExpectedLastSeq: &in.HeadSeq, OnRecord: func(r *v1.LogRecord) {
		if r.GetEvent().GetKind() != v1.EventKind_EVENT_EXECUTION_START || callbackErr != nil {
			return
		}
		callbackErr = w.Ledger.hit(ctx, "broker.before-ack")
		if callbackErr != nil {
			return
		}
		callbackErr = w.Ledger.ConfirmInput(ctx, in.ID, r.GetEvent().GetExecutionId())
		if callbackErr != nil {
			return
		}
		ack = true
		callbackErr = w.Ledger.hit(ctx, "broker.after-ack")
	}})
	if callbackErr != nil || !ack {
		return errors.Join(err, callbackErr, ErrHeld, w.Ledger.MarkUncertain(ctx, op.ID, "lost-exec"))
	}
	return err
}

// Decide is for an explicit trusted caller. No pending projection, tool or model
// can authorize a decision. Exact historical retries never rearm a continuation.
func (w *Worker) Decide(ctx context.Context, id string, d api.ApprovalDecision) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	a := brokerAction{Op: id, Decision: d, Phase: "intent"}
	actions, err := brokerActions(ctx, w.Ledger.db)
	if err != nil {
		return err
	}
	for _, old := range actions {
		if old.key() == a.key() {
			if old.Decision != d {
				return ErrConflict
			}
			return nil
		}
	}
	v, err := w.Inspect(ctx, id)
	if err != nil {
		return err
	}
	if d.RequestSeq <= 0 || v.Request != (api.ApprovalRef{ExecutionID: d.ExecutionID, ToolCallID: d.ToolCallID, RequestSeq: d.RequestSeq}) || v.Evidence.DecisionSeq != 0 || v.Evidence.EndSeq != 0 {
		return ErrConflict
	}
	if err = w.Ledger.saveAction(ctx, a); err != nil {
		return err
	}
	return w.driveAction(ctx, a)
}
func (w *Worker) driveAction(ctx context.Context, a brokerAction) error {
	if a.Phase == "held" {
		return ErrHeld
	}
	op, err := w.Ledger.Operation(ctx, a.Op)
	if err != nil {
		return err
	}
	v, err := w.Inspect(ctx, a.Op)
	if err != nil {
		return err
	}
	if op.Evidence.ExecutionID != a.Decision.ExecutionID {
		return ErrHeld
	}
	if a.Phase == "intent" {
		if v.Request != (api.ApprovalRef{ExecutionID: a.Decision.ExecutionID, ToolCallID: a.Decision.ToolCallID, RequestSeq: a.Decision.RequestSeq}) {
			return ErrHeld
		}
		if _, err = w.Ledger.attempt(ctx, "rpc-approve", a.Op); err != nil {
			return err
		}
		response, e := w.Sessions.Approve(ctx, op.SessionUID, a.Decision)
		if e != nil {
			return e
		}
		if err = w.Ledger.hit(ctx, "broker.before-decision-ack"); err != nil {
			return err
		}
		a.Seq = response.GetDecision().GetSeq()
		if a.Seq <= a.Decision.RequestSeq {
			return ErrInvalid
		}
		a.Phase = "ready"
		if err = w.Ledger.saveAction(ctx, a); err != nil {
			return err
		}
		return w.Ledger.hit(ctx, "broker.after-decision")
	}
	if a.Decision.RequestSeq > 0 && !matchingDecision(v, a) {
		return ErrConflict
	}
	if actionComplete(v, a) {
		a.Phase = "done"
		return w.Ledger.saveAction(ctx, a)
	}
	if a.Decision.RequestSeq > 0 && v.Evidence.RequestSeq != a.Decision.RequestSeq {
		return ErrHeld
	}
	if a.Decision.RequestSeq == 0 && v.Evidence.RequestSeq > 0 {
		a.Phase = "done"
		return w.Ledger.saveAction(ctx, a)
	}
	a.Phase, a.Head = "resuming", v.Evidence.HeadSeq
	if err = w.Ledger.saveAction(ctx, a); err != nil {
		return err
	}
	if _, err = w.Ledger.attempt(ctx, "rpc-resume", a.Op); err != nil {
		return err
	}
	if err = w.Ledger.hit(ctx, "broker.before-resume"); err != nil {
		return err
	}
	_, err = w.Sessions.Sessions().Resume(ctx, &v1.ResumeRequest{Session: op.SessionUID, ExpectedLastSeq: &a.Head})
	if status.Code(err) == codes.Aborted {
		a.Phase = "held"
		return errors.Join(err, w.Ledger.saveAction(ctx, a))
	}
	if err != nil {
		return err
	}
	return w.Ledger.hit(ctx, "broker.after-resume")
}
