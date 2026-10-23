//go:build squadproof

package squadproof

import "testing"

func TestQueuedUserAndTickAckProcessCuts(t *testing.T) {
	bin := buildProofBinary(t)
	for _, kind := range []string{"user", "tick"} {
		t.Run(kind, func(t *testing.T) {
			f := newProcessCase(t, bin, "")
			f.queueThree()
			f.decide(f.op("lead"), true)
			f.until(func() bool { return f.op("lead").State == "terminal" })
			if kind == "tick" {
				f.until(func() bool {
					inputs, err := f.l.Inputs(f.ctx, "lead")
					return err == nil && len(inputs) == 4 && inputs[1].State == "delivered" && inputs[2].State == "delivered" && inputs[3].State != "delivered" && f.op("lead").State == "terminal"
				})
			}
			if err := f.l.ArmCut(f.ctx, "broker.after-ack", "crash"); err != nil {
				t.Fatal(err)
			}
			crashed := false
			for i := 0; i < 8; i++ {
				out, err := f.step()
				if err != nil {
					requireCutExit(t, err, out)
					crashed = true
					break
				}
			}
			if !crashed {
				t.Fatal("queued ACK cut not reached")
			}
			inputs, err := f.l.Inputs(f.ctx, "lead")
			if err != nil {
				t.Fatal(err)
			}
			index := 1
			if kind == "tick" {
				index = 3
			}
			if inputs[index].State != "delivered" || inputs[index].ExecutionID == "" {
				t.Fatal("cut did not preserve exact queued-input acknowledgment")
			}
			acknowledged := inputs[index].ExecutionID
			f.restart()
			f.drive(false)
			f.assertQueueDrained()
			f.assertOneMember(1)
			inputs, err = f.l.Inputs(f.ctx, "lead")
			if err != nil || inputs[index].ExecutionID != acknowledged {
				t.Fatal("queued input was re-admitted after ACK")
			}
		})
	}
}
