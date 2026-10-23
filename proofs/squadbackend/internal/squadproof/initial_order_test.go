//go:build squadproof

package squadproof

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestBrokerRejectsBypassedInitialOrdering(t *testing.T) {
	l, path := openTestLedger(t)
	c, _ := startProofHost(t, l, filepath.Dir(path))
	workerLead(t, l, `{"kind":"admitted"}`)
	w := &Worker{Ledger: l, Sessions: c}
	if err := w.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Enqueue(t.Context(), Input{ID: "followup", Target: "lead", Kind: "user", Payload: []byte(`{"kind":"later"}`)}); err != nil {
		t.Fatal(err)
	}
	if err := w.Reconcile(t.Context()); !errors.Is(err, ErrConflict) {
		t.Fatalf("accepted followup before admitted payload: %v", err)
	}
	if count, err := l.attemptCount(t.Context(), "rpc-exec"); err != nil || count != 0 {
		t.Fatal("invalid initial queue reached Exec")
	}
	if _, err := w.Enqueue(t.Context(), Input{ID: "another", Target: "lead", Kind: "tick", Payload: []byte(`{}`)}); !errors.Is(err, ErrConflict) {
		t.Fatalf("misordered queue repaired implicitly: %v", err)
	}
	inputs, err := l.Inputs(t.Context(), "lead")
	if err != nil || len(inputs) != 1 || inputs[0].ID != "followup" {
		t.Fatal("refused bootstrap mutated existing queue")
	}
}

func TestBrokerInitialAdmissionBoundary(t *testing.T) {
	for _, kind := range []string{"user", "tick"} {
		t.Run(kind, func(t *testing.T) {
			l, _ := openTestLedger(t)
			workerLead(t, l, `{"kind":"admitted"}`)
			w := &Worker{Ledger: l}
			in := Input{ID: "later", Target: "lead", Kind: kind, Payload: []byte(`{"kind":"later"}`)}
			first, err := w.Enqueue(t.Context(), in)
			if err != nil {
				t.Fatal(err)
			}
			retry, err := w.Enqueue(t.Context(), in)
			if err != nil || retry.Ordinal != first.Ordinal {
				t.Fatal("exact retry changed ordinal")
			}
			inputs, err := l.Inputs(t.Context(), "lead")
			if err != nil || len(inputs) != 2 || inputs[0].ID != "initial-lead" || inputs[1].ID != "later" || inputs[0].Ordinal >= inputs[1].Ordinal {
				t.Fatalf("initial/followup not atomic and ordered: %+v %v", inputs, err)
			}
			in.Payload = []byte(`{"kind":"changed"}`)
			if _, err = w.Enqueue(t.Context(), in); !errors.Is(err, ErrConflict) {
				t.Fatalf("changed input accepted: %v", err)
			}
			in.ID = "initial-lead"
			if _, err = w.Enqueue(t.Context(), in); !errors.Is(err, ErrInvalid) {
				t.Fatalf("caller chose initial namespace: %v", err)
			}
		})
	}
	l, _ := openTestLedger(t)
	workerLead(t, l, `{"kind":"admitted"}`)
	if _, err := l.Admit(t.Context(), Operation{ID: "member", Kind: "dispatch", ParentID: "lead", Team: "proof-team", PackageDigest: proofDigest(), Member: "member", Epoch: 1, Payload: []byte(`{"task":"admitted"}`)}); err != nil {
		t.Fatal(err)
	}
	w := &Worker{Ledger: l}
	if _, err := w.Enqueue(t.Context(), Input{ID: "later-task", Target: "member", Kind: "task", Payload: []byte(`{"task":"later"}`)}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("accepted a member followup: %v", err)
	}
	if _, err := l.Enqueue(t.Context(), Input{ID: "bypass-task", Target: "member", Kind: "task", Payload: []byte(`{"task":"later"}`)}); err != nil {
		t.Fatal(err)
	}
	if err := w.Reconcile(t.Context()); !errors.Is(err, ErrConflict) {
		t.Fatalf("unsafe member task queue reached RPC: %v", err)
	}
	if n, _ := l.attemptCount(t.Context(), "rpc-create"); n != 0 {
		t.Fatal("member task bypass allocated session")
	}
}
