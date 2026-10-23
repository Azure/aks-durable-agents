//go:build squadproof

package squadproof

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/agent-primitives/sessions/api"
	"github.com/agent-primitives/sessions/client"
)

type Proof struct {
	Outcome      string         `json:"outcome"`
	Cancellation string         `json:"cancellation"`
	Operations   []Operation    `json:"operations"`
	Inputs       []Input        `json:"inputs"`
	Counts       Stats          `json:"counts"`
	Counters     map[string]int `json:"counters"`
	Replays      []ReplayProof  `json:"replays,omitempty"`
}

func ledgerProof(ctx context.Context, l *Ledger) (p Proof, err error) {
	p.Cancellation = "unsupported"
	p.Operations, err = l.Operations(ctx)
	if err != nil {
		return p, err
	}
	for _, op := range p.Operations {
		in, e := l.Inputs(ctx, op.ID)
		if e != nil {
			return p, e
		}
		p.Inputs = append(p.Inputs, in...)
	}
	p.Counts, err = l.Counts(ctx)
	if err != nil {
		return p, err
	}
	p.Counters = map[string]int{}
	for _, kind := range []string{"rpc-create", "rpc-exec", "rpc-approve", "rpc-resume", "model", "executor"} {
		p.Counters[kind], err = l.attemptCount(ctx, kind)
		if err != nil {
			return p, err
		}
	}
	return p, nil
}

// RunCase drives fresh happy/deny/queue fixtures, not a fault matrix or backend.
// Callers must quiesce writers before OpenLedger, then keep serving roles ready;
// hot broker-only restart and online ledger recovery are deliberately unsupported.
func RunCase(ctx context.Context, name, dataDir, server string) (Proof, error) {
	if (name != "happy" && name != "deny" && name != "queue") || !privateDirectory(dataDir) {
		return Proof{}, ErrInvalid
	}
	target, err := proofServer(server)
	if err != nil {
		return Proof{}, err
	}
	l, err := existingLedger(dataDir)
	if err != nil {
		return Proof{}, err
	}
	defer l.Close()
	ops, err := l.Operations(ctx)
	if err != nil {
		return Proof{}, err
	}
	if len(ops) != 0 {
		return Proof{}, ErrConflict
	}
	if _, err = l.Admit(ctx, Operation{ID: "lead", Kind: "lead", Team: "proof-team", PackageDigest: proofDigest(), Member: "lead", Epoch: 1, Payload: []byte(`{"kind":"start"}`)}); err != nil {
		return Proof{}, err
	}
	c, err := client.Dial(target)
	if err != nil {
		return Proof{}, err
	}
	defer c.Close()
	w := &Worker{Ledger: l, Sessions: c}
	for range 64 {
		p, e := ledgerProof(ctx, l)
		if e != nil {
			return p, e
		}
		want := 3
		if name == "queue" {
			want = 5
		}
		complete := len(p.Operations) == 2 && len(p.Inputs) == want
		user, result, tick := false, false, false
		for _, in := range p.Inputs {
			complete = complete && in.State == "delivered" && in.ExecutionID != ""
			user = user || in.ID == "case-user"
			result = result || in.Kind == "result"
			tick = tick || in.ID == "case-tick"
		}
		for _, op := range p.Operations {
			complete = complete && op.State == "terminal" && op.Evidence.EndSeq > 0
		}
		if complete {
			p.Outcome = "completed"
			return p, nil
		}
		acted := false
		for _, op := range p.Operations {
			if op.SessionUID == "" || op.Evidence.ExecutionID == "" {
				continue
			}
			v, e := w.Inspect(ctx, op.ID)
			if e != nil {
				return p, e
			}
			if name == "queue" && op.ID == "lead" && op.Evidence.RequestSeq > 0 && !user {
				_, err = w.Enqueue(ctx, Input{ID: "case-user", Target: "lead", Kind: "user", Payload: []byte(`{"kind":"followup"}`)})
				acted = true
				break
			}
			if name == "queue" && result && !tick {
				_, err = w.Enqueue(ctx, Input{ID: "case-tick", Target: "lead", Kind: "tick", Payload: []byte(`{"kind":"tick"}`)})
				acted = true
				break
			}
			if v.Request.RequestSeq == 0 || v.Evidence.DecisionSeq != 0 || v.Evidence.EndSeq != 0 || (op.ID == "lead" && (!result || name == "queue" && !tick)) || (name == "queue" && op.Kind == "dispatch" && !user) {
				continue
			}
			d := api.ApprovalDecision{ExecutionID: v.Request.ExecutionID, ToolCallID: v.Request.ToolCallID, RequestSeq: v.Request.RequestSeq, Approved: name != "deny", Reason: "fixed synthetic case " + name, Identity: api.IdentityRef{Principal: "proof-case"}}
			err = w.Decide(ctx, op.ID, d)
			acted = true
			break
		}
		if !acted {
			err = w.Reconcile(ctx)
		}
		if err != nil && !errors.Is(err, ErrHeld) && !errors.Is(err, ErrNotFound) {
			return p, err
		}
		if errors.Is(err, ErrHeld) {
			p.Outcome = "held"
			return p, ErrHeld
		}
	}
	p, err := ledgerProof(ctx, l)
	p.Outcome = "bounded-incomplete"
	return p, errors.Join(ErrHeld, err)
}

func existingLedger(data string) (*Ledger, error) {
	path := filepath.Join(data, "proof.db")
	// A missing database is not an invitation to initialize a new case directory.
	if _, err := os.Lstat(path); err != nil {
		return nil, ErrInvalid
	}
	return OpenLedger(path)
}
