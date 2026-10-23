//go:build squadproof

package squadproof

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"path/filepath"
	"testing"

	"github.com/agent-primitives/sessions/api"
)

func TestExplicitUnknownDecisionRefused(t *testing.T) {
	_, path := openTestLedger(t)
	err := RunCLI(t.Context(), []string{"broker", "--proof-only", "--data=" + filepath.Dir(path), "--server=127.0.0.1:9", "--operation=missing", "--decision={\"ExecutionID\":\"unknown\",\"ToolCallID\":\"unknown\",\"RequestSeq\":1,\"Approved\":true}"}, io.Discard)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("explicit missing decision became successful idle: %v", err)
	}
}

func TestBrokerOwnershipAndActionTerminalGuards(t *testing.T) {
	l, path := openTestLedger(t)
	c, _ := startProofHost(t, l, filepath.Dir(path))
	workerLead(t, l, `{"kind":"start"}`)
	w := &Worker{Ledger: l, Sessions: c}
	for i := 0; i < 8; i++ {
		op, _ := l.Operation(t.Context(), "lead")
		if op.Evidence.ExecutionID != "" {
			break
		}
		if err := w.Reconcile(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	in, err := l.Inputs(t.Context(), "lead")
	if err != nil || len(in) != 1 {
		t.Fatal(err)
	}
	in[0].Epoch++
	if err = l.transaction(t.Context(), func(conn *sql.Conn) error { return saveInput(t.Context(), conn, in[0]) }); err != nil {
		t.Fatal(err)
	}
	if _, err = w.Inspect(t.Context(), "lead"); !errors.Is(err, ErrHeld) {
		t.Fatalf("unowned acknowledgement accepted: %v", err)
	}
	for _, phase := range []string{"held", "done"} {
		a := brokerAction{Op: phase, Decision: api.ApprovalDecision{ExecutionID: phase}, Phase: phase}
		if err = l.saveAction(context.Background(), a); err != nil {
			t.Fatal(err)
		}
		a.Phase = "ready"
		if err = l.saveAction(context.Background(), a); !errors.Is(err, ErrHeld) {
			t.Fatalf("%s obligation rearmed: %v", phase, err)
		}
	}
}
