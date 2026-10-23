//go:build squadproof

package squadproof

import (
	"encoding/json"
	"testing"

	v1 "github.com/agent-primitives/sessions/api/genpb"
)

func TestProofReportsUnsupportedCancellation(t *testing.T) {
	l, _ := openTestLedger(t)
	p, err := ledgerProof(t.Context(), l)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err = json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	if object["cancellation"] != "unsupported" {
		t.Fatal("proof omits unsupported cancellation capability")
	}
}

func TestChildCreateResponseLostWitness(t *testing.T) {
	bin := buildProofBinary(t)
	f := newProcessCase(t, bin, "")
	f.until(func() bool { return len(f.ops()) == 2 })
	if err := f.l.ArmCut(f.ctx, "broker.after-create", "crash"); err != nil {
		t.Fatal(err)
	}
	out, err := f.step()
	requireCutExit(t, err, out)
	f.restart()
	// The observer can see the orphan, but this UID never enters broker recovery.
	sessions, err := f.c.ListSessions(f.ctx, "")
	if err != nil || len(sessions) != 2 {
		t.Fatalf("missing witness-visible orphan: %d %v", len(sessions), err)
	}
	var child string
	for _, op := range f.ops() {
		if op.Kind == "dispatch" {
			child = op.ID
			if op.SessionUID != "" {
				t.Fatal("lost child Create was mapped")
			}
		}
	}
	creates, execs := f.count("attempt-rpc-create", ""), f.count("attempt-rpc-exec", "")
	for range 2 {
		f.mustStep()
		if f.op(child).State != "uncertain" {
			t.Fatal("orphan adopted or replaced")
		}
		f.restart()
	}
	if f.count("attempt-rpc-create", "") != creates || f.count("attempt-rpc-exec", "") != execs {
		t.Fatal("unknown child outcome retried")
	}
	if sessions, err = f.c.ListSessions(f.ctx, ""); err != nil || len(sessions) != 2 {
		t.Fatal("substitute allocation appeared")
	}
}

func TestExecStartLostAckWitness(t *testing.T) {
	bin := buildProofBinary(t)
	f := newProcessCase(t, bin, "")
	if err := f.l.ArmCut(f.ctx, "broker.before-ack", "crash"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 12; i++ {
		out, err := f.step()
		if err != nil {
			requireCutExit(t, err, out)
			break
		}
	}
	f.restart()
	root := f.op("lead")
	records, err := f.c.Replay(f.ctx, root.SessionUID, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	starts := 0
	for _, r := range records {
		if r.GetEvent().GetKind() == v1.EventKind_EVENT_EXECUTION_START {
			starts++
		}
	}
	if starts != 1 || root.Evidence.ExecutionID != "" {
		t.Fatalf("witness/ACK planes conflated: starts%d op%+v", starts, root)
	}
	for range 2 {
		f.mustStep()
		f.restart()
	}
	if f.op("lead").Evidence.ExecutionID != "" || f.count("attempt-rpc-exec", "lead") != 1 {
		t.Fatal("witness execution identity adopted/retried")
	}
}
