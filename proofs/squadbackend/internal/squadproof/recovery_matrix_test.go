//go:build squadproof

package squadproof

import (
	"testing"
)

func TestAdmissionAndEffectProcessCuts(t *testing.T) {
	bin := buildProofBinary(t)
	for _, cut := range []string{"executor.before-dispatch_member", "executor.after-dispatch_member"} {
		t.Run(cut, func(t *testing.T) {
			f := newProcessCase(t, bin, "")
			if err := f.l.ArmCut(f.ctx, cut, "crash"); err != nil {
				t.Fatal(err)
			}
			crashed := false
			for i := 0; i < 40; i++ {
				for _, op := range f.ops() {
					if op.State == "awaiting-approval" && op.Evidence.DecisionSeq == 0 {
						f.decide(op, true)
					}
				}
				_, err := f.step()
				if err != nil {
					f.waitCut(cut)
					crashed = true
					break
				}
			}
			if !crashed {
				t.Fatal("executor process cut not reached")
			}
			requireCutExit(t, <-f.roles[0].done, "executor role")
			ops := f.ops()
			if cut == "executor.before-dispatch_member" && len(ops) != 1 {
				t.Fatal("uncommitted admission survived")
			}
			if cut == "executor.after-dispatch_member" && len(ops) != 2 {
				t.Fatal("committed handle missing")
			}
			if f.count("attempt-rpc-create", "") != 1 {
				t.Fatal("dispatch performed member RPC inline")
			}
			f.restart()
			f.drive(false)
			f.assertOneMember(1)
		})
	}
}

func TestKnownAckAndPendingHostReplacement(t *testing.T) {
	bin := buildProofBinary(t)
	t.Run("after-ack", func(t *testing.T) {
		f := newProcessCase(t, bin, "")
		if err := f.l.ArmCut(f.ctx, "broker.after-ack", "crash"); err != nil {
			t.Fatal(err)
		}
		crashed := false
		for i := 0; i < 12; i++ {
			out, err := f.step()
			if err != nil {
				requireCutExit(t, err, out)
				crashed = true
				break
			}
		}
		if !crashed {
			t.Fatal("armed broker.after-ack crash was not reached")
		}
		root := f.op("lead")
		if root.Evidence.ExecutionID == "" {
			t.Fatal("cut lacked durable execution ACK")
		}
		f.restart()
		f.drive(false)
		f.assertOneMember(1)
		if f.count("attempt-rpc-exec", "lead") != 2 {
			t.Fatal("known invocation was sent as a new input")
		}
	})
	t.Run("pending-approval", func(t *testing.T) {
		f := newProcessCase(t, bin, "")
		f.until(func() bool { return f.op("lead").State == "awaiting-approval" })
		before := f.op("lead")
		models, tools := f.count("attempt-model", ""), f.count("attempt-executor", "")
		f.restart()
		after := f.op("lead")
		current, err := f.c.GetSession(f.ctx, before.SessionUID)
		if err != nil {
			t.Fatal(err)
		}
		if after.SessionUID != before.SessionUID || after.Evidence != before.Evidence || current.GetLastSeq() != before.Evidence.HeadSeq {
			t.Fatal("pending identity/logical head changed without a decision")
		}
		if f.count("attempt-model", "") != models || f.count("attempt-executor", "") != tools {
			t.Fatal("replacement replayed completed prefix")
		}
		f.drive(false)
		f.assertOneMember(1)
	})
}

func TestMemberCompletionResultAndAckCuts(t *testing.T) {
	bin := buildProofBinary(t)
	for _, cut := range []string{"broker.after-terminal", "broker.after-result", "broker.after-ack"} {
		t.Run(cut, func(t *testing.T) {
			f := newProcessCase(t, bin, "")
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
			for _, op := range f.ops() {
				if op.Kind == "dispatch" {
					f.decide(op, true)
				}
			}
			if cut == "broker.after-ack" {
				f.until(func() bool { in, err := f.l.Inputs(f.ctx, "lead"); return err == nil && len(in) == 2 })
			}
			if err := f.l.ArmCut(f.ctx, cut, "crash"); err != nil {
				t.Fatal(err)
			}
			crashed := false
			for i := 0; i < 15; i++ {
				out, err := f.step()
				if err != nil {
					requireCutExit(t, err, out)
					crashed = true
					break
				}
			}
			if !crashed {
				t.Fatal("result boundary not reached")
			}
			f.restart()
			f.drive(false)
			f.assertOneMember(1)
			inputs, err := f.l.Inputs(f.ctx, "lead")
			if err != nil || len(inputs) != 2 || inputs[1].Kind != "result" {
				t.Fatalf("result key duplicated: %+v %v", inputs, err)
			}
			if f.count("attempt-rpc-exec", "lead") != 2 {
				t.Fatal("result delivery retried as fresh Exec")
			}
		})
	}
}
