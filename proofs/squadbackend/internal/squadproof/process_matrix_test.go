//go:build squadproof

package squadproof

import (
	"encoding/json"
	"os/exec"
	"testing"

	"github.com/agent-primitives/sessions/api"
	v1 "github.com/agent-primitives/sessions/api/genpb"
)

func (f *processCase) until(test func() bool) {
	f.t.Helper()
	for i := 0; i < 30; i++ {
		if test() {
			return
		}
		f.mustStep()
	}
	f.t.Fatalf("phase not reached: %+v", f.ops())
}
func (f *processCase) decisionCommand(op Operation, approved bool) *exec.Cmd {
	f.t.Helper()
	v, err := (&Worker{Ledger: f.l, Sessions: f.c}).Inspect(f.ctx, op.ID)
	if err != nil {
		f.t.Fatal(err)
	}
	raw, _ := json.Marshal(api.ApprovalDecision{ExecutionID: v.Request.ExecutionID, ToolCallID: v.Request.ToolCallID, RequestSeq: v.Request.RequestSeq, Approved: approved, Reason: "explicit synthetic case decision"})
	return exec.CommandContext(f.ctx, f.bin, "broker", "--proof-only", "--data="+f.data, "--server="+f.server, "--operation="+op.ID, "--decision="+string(raw))
}
func TestApprovalDecisionProcessCut(t *testing.T) {
	bin := buildProofBinary(t)
	for _, cut := range []string{"broker.after-decision", "broker.before-decision-ack"} {
		for _, approved := range []bool{true, false} {
			t.Run(cut+map[bool]string{true: "approve", false: "deny"}[approved], func(t *testing.T) {
				f := newProcessCase(t, bin, "")
				f.until(func() bool { return f.op("lead").State == "awaiting-approval" })
				if err := f.l.ArmCut(f.ctx, cut, "crash"); err != nil {
					t.Fatal(err)
				}
				out, err := f.decisionCommand(f.op("lead"), approved).CombinedOutput()
				requireCutExit(t, err, string(out))
				if f.count("attempt-rpc-approve", "") != 1 || f.count("attempt-rpc-resume", "") != 0 {
					t.Fatal("decision did not stop before resume")
				}
				f.restart()
				// Recover the committed decision before asking the fixed positive driver to
				// decide later requests. Do not overwrite a denial from a stale projection.
				f.mustStep()
				f.mustStep()
				f.mustStep()
				f.drive(false)
				f.assertOneMember(1)
				want := 1
				if cut == "broker.before-decision-ack" {
					want = 2
				}
				if f.count("attempt-rpc-approve", "lead") != want {
					t.Fatal("approval retry count mismatch")
				}
				records, err := f.c.Replay(f.ctx, f.op("lead").SessionUID, 0, 0)
				if err != nil {
					t.Fatal(err)
				}
				decisions := 0
				for _, r := range records {
					if r.GetEvent().GetKind() == v1.EventKind_EVENT_APPROVAL_RESULT {
						decisions++
					}
				}
				if decisions != 1 {
					t.Fatal("idempotent retry journaled another decision")
				}
				if !approved && f.count("attempt-executor", "") != 2 {
					t.Fatal("denied checkpoint reached the executor")
				}
			})
		}
	}
}
