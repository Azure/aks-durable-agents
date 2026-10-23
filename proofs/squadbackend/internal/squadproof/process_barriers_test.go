//go:build squadproof

package squadproof

import (
	"errors"
	"os/exec"
	"testing"

	"github.com/agent-primitives/sessions/api"
	v1 "github.com/agent-primitives/sessions/api/genpb"
	"github.com/agent-primitives/sessions/wire"
)

func (f *processCase) startStep() *ownedProcess {
	f.t.Helper()
	p := &ownedProcess{cmd: f.stepCommand(), done: make(chan error, 1)}
	p.cmd.Stdout = &p.stderr
	p.cmd.Stderr = &p.stderr
	if err := p.cmd.Start(); err != nil {
		f.t.Fatal(err)
	}
	f.roles = append(f.roles, p)
	go func() { p.done <- p.cmd.Wait(); close(p.done) }()
	return p
}
func (f *processCase) finishLead() {
	f.until(func() bool { return f.op("lead").State == "awaiting-approval" })
	f.decide(f.op("lead"), true)
	f.until(func() bool { return f.op("lead").State == "terminal" })
	f.until(func() bool {
		for _, op := range f.ops() {
			if op.Kind == "dispatch" && op.State == "awaiting-approval" {
				return true
			}
		}
		return false
	})
}
func (f *processCase) queueThree() {
	f.t.Helper()
	f.until(func() bool { return f.op("lead").State == "awaiting-approval" })
	if _, err := f.l.Enqueue(f.ctx, Input{ID: "queued-user", Target: "lead", Kind: "user", Payload: []byte(`{"kind":"followup"}`)}); err != nil {
		f.t.Fatal(err)
	}
	f.until(func() bool {
		for _, op := range f.ops() {
			if op.Kind == "dispatch" && op.State == "awaiting-approval" {
				return true
			}
		}
		return false
	})
	for _, op := range f.ops() {
		if op.Kind == "dispatch" {
			f.decide(op, true)
		}
	}
	f.until(func() bool { inputs, err := f.l.Inputs(f.ctx, "lead"); return err == nil && len(inputs) == 3 })
	if _, err := f.l.Enqueue(f.ctx, Input{ID: "queued-tick", Target: "lead", Kind: "tick", Payload: []byte(`{"kind":"tick"}`)}); err != nil {
		f.t.Fatal(err)
	}
	f.assertQueueHeld()
}
func (f *processCase) assertQueueHeld() {
	f.t.Helper()
	op := f.op("lead")
	inputs, err := f.l.Inputs(f.ctx, "lead")
	if err != nil || len(inputs) != 4 {
		f.t.Fatalf("queue count %d %v", len(inputs), err)
	}
	for i, kind := range []string{"user", "result", "tick"} {
		if inputs[i+1].Kind != kind || inputs[i+1].ExecutionID != "" {
			f.t.Fatalf("queue order or premature delivery: %+v", inputs)
		}
	}
	if _, err = f.l.NextInput(f.ctx, op.ID, op.Epoch, op.Evidence.HeadSeq); !errors.Is(err, ErrHeld) {
		f.t.Fatalf("receipt without safe END drained queue: %v", err)
	}
	if f.count("attempt-rpc-exec", "lead") != 1 {
		f.t.Fatal("queued lead Exec bypassed approval/END")
	}
}
func (f *processCase) assertQueueDrained() {
	f.t.Helper()
	inputs, err := f.l.Inputs(f.ctx, "lead")
	if err != nil || len(inputs) != 4 {
		f.t.Fatal(err)
	}
	ids := map[string]bool{}
	for i, in := range inputs {
		if in.State != "delivered" || in.ExecutionID == "" || ids[in.ExecutionID] {
			f.t.Fatalf("duplicate/unacknowledged queue delivery: %+v", inputs)
		}
		ids[in.ExecutionID] = true
		if i > 0 && in.Ordinal <= inputs[i-1].Ordinal {
			f.t.Fatal("queue reordered")
		}
	}
	if f.count("attempt-rpc-exec", "lead") != 4 || f.count("attempt-model", "") > 12 {
		f.t.Fatal("queue duplicated or per-case fake cap exceeded")
	}
}

func TestEffectCommittedReceiptMissingProcessCut(t *testing.T) {
	bin := buildProofBinary(t)
	f := newProcessCase(t, bin, "")
	f.finishLead()
	for _, op := range f.ops() {
		if op.Kind == "dispatch" {
			f.decide(op, true)
		}
	}
	if err := f.l.ArmCut(f.ctx, "executor.after-publish", "pause"); err != nil {
		t.Fatal(err)
	}
	f.startStep()
	f.waitCut("executor.after-publish")
	var effects int
	if err := f.ro.QueryRow(`SELECT count(*) FROM effects`).Scan(&effects); err != nil || effects != 1 {
		t.Fatalf("effect not durably committed: %d %v", effects, err)
	}
	for _, op := range f.ops() {
		if op.Kind == "dispatch" {
			records, err := f.c.Replay(f.ctx, op.SessionUID, 0, 0)
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range records {
				if e := wire.EventFromProto(r.GetEvent()); e.Result != nil && e.Result.ApprovalRequestSeq > 0 {
					t.Fatal("cut happened after a Sessions receipt")
				}
			}
		}
	}
	// Killing only the executor would let the live host journal a failure result.
	// Kill the host while the executor is held after its effect/result commit.
	if err := f.roles[3].cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	f.restart()
	f.drive(false)
	f.assertOneMember(1)
	if f.count("attempt-executor", "") != 4 {
		t.Fatalf("want three successful tools plus one durable-key redrive: %d", f.count("attempt-executor", ""))
	}
}

func TestReceiptBeforeEndQueueProcessCuts(t *testing.T) {
	bin := buildProofBinary(t)
	for _, crash := range []bool{false, true} {
		t.Run(map[bool]string{false: "live-barrier", true: "host-crash"}[crash], func(t *testing.T) {
			f := newProcessCase(t, bin, "")
			f.queueThree()
			if err := f.l.ArmCut(f.ctx, "host.finish.lead", "pause"); err != nil {
				t.Fatal(err)
			}
			f.decide(f.op("lead"), true)
			p := f.startStep()
			f.waitCut("host.finish.lead")
			v, err := (&Worker{Ledger: f.l, Sessions: f.c}).Inspect(f.ctx, "lead")
			if err != nil || v.Evidence.ReceiptSeq == 0 || v.Evidence.EndSeq != 0 {
				t.Fatalf("not receipt-before-END: %+v %v", v.Evidence, err)
			}
			if err = f.l.Observe(f.ctx, "lead", v.Evidence); err != nil {
				t.Fatal(err)
			}
			f.assertQueueHeld()
			if crash {
				if err = f.roles[3].cmd.Process.Kill(); err != nil {
					t.Fatal(err)
				}
				f.restart()
			} else {
				if err = f.l.ReleaseCut(f.ctx, "host.finish.lead"); err != nil {
					t.Fatal(err)
				}
				if err = <-p.done; err != nil {
					t.Fatalf("released Resume: %v %s", err, p.stderr.String())
				}
			}
			f.drive(false)
			f.assertQueueDrained()
			f.assertOneMember(1)
		})
	}
}

func TestSecondApprovalAndHistoricalDecision(t *testing.T) {
	bin := buildProofBinary(t)
	f := newProcessCase(t, bin, "double")
	f.queueThree()
	w := &Worker{Ledger: f.l, Sessions: f.c}
	v, err := w.Inspect(f.ctx, "lead")
	if err != nil {
		t.Fatal(err)
	}
	old := api.ApprovalDecision{ExecutionID: v.Request.ExecutionID, ToolCallID: v.Request.ToolCallID, RequestSeq: v.Request.RequestSeq, Approved: true, Reason: "explicit synthetic case decision"}
	if err = w.Decide(f.ctx, "lead", old); err != nil {
		t.Fatal(err)
	}
	f.until(func() bool { return f.op("lead").Evidence.RequestSeq > old.RequestSeq })
	f.assertQueueHeld()
	approvals, resumes := f.count("attempt-rpc-approve", "lead"), f.count("attempt-rpc-resume", "lead")
	if err = w.Decide(f.ctx, "lead", old); err != nil {
		t.Fatal(err)
	}
	if f.count("attempt-rpc-approve", "lead") != approvals || f.count("attempt-rpc-resume", "lead") != resumes {
		t.Fatal("historical decision resumed a newer approval")
	}
	f.restart()
	f.assertQueueHeld()
	f.drive(false)
	f.assertQueueDrained()
	f.assertOneMember(1)
}

func TestStaleResumeCursorProcessHold(t *testing.T) {
	bin := buildProofBinary(t)
	f := newProcessCase(t, bin, "")
	f.until(func() bool { return f.op("lead").State == "awaiting-approval" })
	f.decide(f.op("lead"), true)
	if err := f.l.ArmCut(f.ctx, "broker.before-resume", "pause"); err != nil {
		t.Fatal(err)
	}
	p := f.startStep()
	f.waitCut("broker.before-resume")
	s, err := f.c.GetSession(f.ctx, f.op("lead").SessionUID)
	if err != nil {
		t.Fatal(err)
	}
	head := s.GetLastSeq()
	if _, err = f.c.Sessions().Resume(f.ctx, &v1.ResumeRequest{Session: s.GetMetadata().GetUid(), ExpectedLastSeq: &head}); err != nil {
		t.Fatal(err)
	}
	if err = f.l.ReleaseCut(f.ctx, "broker.before-resume"); err != nil {
		t.Fatal(err)
	}
	var exit *exec.ExitError
	if err = <-p.done; !errors.As(err, &exit) {
		t.Fatalf("stale CAS not rejected: %v %s", err, p.stderr.String())
	}
	before := f.count("attempt-rpc-resume", "lead")
	for range 2 {
		f.restart()
		f.mustStep()
	}
	if f.count("attempt-rpc-resume", "lead") != before || f.count("attempt-rpc-exec", "lead") != 1 {
		t.Fatal("rejected Resume cursor advanced or queue drained")
	}
}
