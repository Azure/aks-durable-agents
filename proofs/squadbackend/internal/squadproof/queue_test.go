package squadproof

import (
	"errors"
	"reflect"
	"testing"
)

func TestQueueReceiptAndEndGate(t *testing.T) {
	l, path := openTestLedger(t)
	child := seedMember(t, l)
	complete(t, l, child.ID)
	beginExecution(t, l, "lead", "exec-lead")
	evidence := Evidence{ExecutionID: "exec-lead", RequestSeq: 3, HeadSeq: 3, HeadHash: headHash}
	if err := l.Observe(testContext, "lead", evidence); err != nil {
		t.Fatal(err)
	}
	var ordinals []int64
	for _, kind := range []string{"user", "result", "tick"} {
		var in Input
		var err error
		if kind == "result" {
			in, err = l.EnqueueResult(testContext, child.ID, []byte(`{"text":"hello"}`))
		} else {
			in, err = l.Enqueue(testContext, Input{ID: kind, Target: "lead", Kind: kind, Payload: []byte(`{"text":"hello"}`)})
		}
		if err != nil || in.Ordinal <= 0 || in.State != "queued-behind-approval" {
			t.Fatalf("queue: %+v %v", in, err)
		}
		ordinals = append(ordinals, in.Ordinal)
	}
	assertHeld := func(ledger *Ledger, ev Evidence) {
		t.Helper()
		if _, err := ledger.NextInput(testContext, "lead", 1, ev.HeadSeq); !errors.Is(err, ErrHeld) {
			t.Fatalf("unsafe drain: %v", err)
		}
	}
	assertHeld(l, evidence)
	evidence.DecisionSeq, evidence.HeadSeq = 4, 4
	if err := l.Observe(testContext, "lead", evidence); err != nil {
		t.Fatal(err)
	}
	assertHeld(l, evidence)
	evidence.ReceiptSeq, evidence.HeadSeq = 5, 5
	if err := l.Observe(testContext, "lead", evidence); err != nil {
		t.Fatal(err)
	}
	assertHeld(l, evidence) // A receipt is not END.
	evidence.RequestSeq, evidence.DecisionSeq, evidence.ReceiptSeq, evidence.HeadSeq = 6, 0, 0, 6
	if err := l.Observe(testContext, "lead", evidence); err != nil {
		t.Fatal(err)
	}
	assertHeld(l, evidence) // A second gate blocks despite the first receipt.
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	l, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	assertHeld(l, evidence)
	evidence.DecisionSeq, evidence.ReceiptSeq, evidence.EndSeq, evidence.HeadSeq, evidence.EndHash = 7, 8, 9, 9, endHash
	evidence.HeadHash = endHash
	if err = l.Observe(testContext, "lead", evidence); err != nil {
		t.Fatal(err)
	}
	if _, err = l.NextInput(testContext, "lead", 1, 8); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale head admitted: %v", err)
	}
	for i, kind := range []string{"user", "result-child", "tick"} {
		in, err := l.NextInput(testContext, "lead", 1, evidence.HeadSeq)
		if err != nil || in.ID != kind || in.State != "delivering" || in.Ordinal != ordinals[i] {
			t.Fatalf("ordered drain: %+v %v", in, err)
		}
		if _, err = l.NextInput(testContext, "lead", 1, evidence.HeadSeq); !errors.Is(err, ErrHeld) {
			t.Fatalf("concurrent input: %v", err)
		}
		if err = l.ConfirmInput(testContext, in.ID, "exec-"+kind); err != nil {
			t.Fatal(err)
		}
		evidence = Evidence{ExecutionID: "exec-" + kind, EndSeq: evidence.HeadSeq + 2, HeadSeq: evidence.HeadSeq + 2, EndHash: endHash, HeadHash: endHash}
		if err = l.Observe(testContext, "lead", evidence); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = l.NextInput(testContext, "lead", 1, evidence.HeadSeq); !errors.Is(err, ErrNotFound) {
		t.Fatalf("drained again: %v", err)
	}
}

func TestTerminalResultKeyConflict(t *testing.T) {
	l, _ := openTestLedger(t)
	seedLead(t, l)
	child, err := l.Admit(testContext, Operation{ID: "child", Kind: "dispatch", ParentID: "lead", Team: "team-a", PackageDigest: packageDigest, Member: "member", Epoch: 1, Payload: []byte(`{"task":"work"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = l.EnqueueResult(testContext, child.ID, []byte(`{"text":"result"}`)); !errors.Is(err, ErrHeld) {
		t.Fatalf("result before END: %v", err)
	}
	if err = l.BindSession(testContext, child.ID, "session-member"); err != nil {
		t.Fatal(err)
	}
	complete(t, l, child.ID)
	first, err := l.EnqueueResult(testContext, child.ID, []byte(`{"text":"result"}`))
	if err != nil {
		t.Fatal(err)
	}
	again, err := l.EnqueueResult(testContext, child.ID, []byte(`{ "text": "result" }`))
	if err != nil || !reflect.DeepEqual(first, again) || first.Target != "lead" || first.Source != "child" || first.TerminalHash != endHash {
		t.Fatalf("result retry: %+v %v", again, err)
	}
	if _, err = l.EnqueueResult(testContext, child.ID, []byte(`{"text":"different"}`)); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed result got new key: %v", err)
	}
	items, err := l.Inputs(testContext, "lead")
	if err != nil || len(items) != 1 {
		t.Fatalf("result queue: %+v %v", items, err)
	}
}

func TestEpochAdvanceHeldDuringDelivery(t *testing.T) {
	l, _ := openTestLedger(t)
	seedLead(t, l)
	if _, err := l.Enqueue(testContext, Input{ID: "input", Target: "lead", Kind: "user", Payload: []byte(`{"text":"go"}`)}); err != nil {
		t.Fatal(err)
	}
	if _, err := l.NextInput(testContext, "lead", 1, 0); err != nil {
		t.Fatal(err)
	}
	if err := l.AdvanceEpoch(testContext, "lead", 1, 2); !errors.Is(err, ErrHeld) {
		t.Fatalf("active owner retired: %v", err)
	}
	if err := l.ConfirmInput(testContext, "input", "current-exec"); err != nil {
		t.Fatal(err)
	}
	if err := l.AdvanceEpoch(testContext, "lead", 1, 2); !errors.Is(err, ErrHeld) {
		t.Fatalf("running owner retired: %v", err)
	}
	if err := l.Observe(testContext, "lead", Evidence{ExecutionID: "current-exec", EndSeq: 8, HeadSeq: 8, EndHash: endHash, HeadHash: endHash}); err != nil {
		t.Fatal(err)
	}
	if err := l.AdvanceEpoch(testContext, "lead", 1, 2); err != nil {
		t.Fatalf("idle owner cannot advance: %v", err)
	}
}

func TestHistoricalAcknowledgementKeepsCurrentEpoch(t *testing.T) {
	l, _ := openTestLedger(t)
	seedLead(t, l)
	complete(t, l, "lead")
	if err := l.AdvanceEpoch(testContext, "lead", 1, 2); err != nil {
		t.Fatal(err)
	}
	before, err := l.Counts(testContext)
	if err != nil {
		t.Fatal(err)
	}
	if err = l.ConfirmInput(testContext, "start-exec-lead", "exec-lead"); !errors.Is(err, ErrHeld) {
		t.Fatalf("historical acknowledgement accepted in new epoch: %v", err)
	}
	after, err := l.Counts(testContext)
	if err != nil || before != after {
		t.Fatalf("historical acknowledgement mutated current epoch: %v", err)
	}
}

func TestObserveRequiresConfirmedInput(t *testing.T) {
	l, _ := openTestLedger(t)
	seedLead(t, l)
	e := Evidence{ExecutionID: "unacknowledged", EndSeq: 8, HeadSeq: 8, EndHash: endHash, HeadHash: endHash}
	if err := l.Observe(testContext, "lead", e); !errors.Is(err, ErrHeld) {
		t.Fatalf("unconfirmed completion accepted: %v", err)
	}
	if _, err := l.Enqueue(testContext, Input{ID: "reserved", Target: "lead", Kind: "user", Payload: []byte(`{"text":"go"}`)}); err != nil {
		t.Fatal(err)
	}
	if _, err := l.NextInput(testContext, "lead", 1, 0); err != nil {
		t.Fatal(err)
	}
	if err := l.Observe(testContext, "lead", e); !errors.Is(err, ErrHeld) {
		t.Fatalf("delivering input completed: %v", err)
	}
}

func TestExecutionCannotReuseHistoricalEvidence(t *testing.T) {
	for _, kind := range []string{"end", "approval", "execution-id", "different-execution"} {
		t.Run(kind, func(t *testing.T) {
			l, _ := openTestLedger(t)
			seedLead(t, l)
			in := Input{ID: "one", Target: "lead", Kind: "user", Payload: []byte(`{"text":"go"}`)}
			if _, err := l.Enqueue(testContext, in); err != nil {
				t.Fatal(err)
			}
			if _, err := l.NextInput(testContext, "lead", 1, 0); err != nil {
				t.Fatal(err)
			}
			if err := l.ConfirmInput(testContext, "one", "old-exec"); err != nil {
				t.Fatal(err)
			}
			if err := l.Observe(testContext, "lead", Evidence{ExecutionID: "old-exec", EndSeq: 8, HeadSeq: 8, EndHash: endHash, HeadHash: endHash}); err != nil {
				t.Fatal(err)
			}
			in.ID = "two"
			if _, err := l.Enqueue(testContext, in); err != nil {
				t.Fatal(err)
			}
			if _, err := l.NextInput(testContext, "lead", 1, 8); err != nil {
				t.Fatal(err)
			}
			if kind == "execution-id" {
				if err := l.ConfirmInput(testContext, "two", "old-exec"); !errors.Is(err, ErrConflict) {
					t.Fatalf("old execution reused: %v", err)
				}
				return
			}
			if err := l.ConfirmInput(testContext, "two", "new-exec"); err != nil {
				t.Fatal(err)
			}
			e := Evidence{ExecutionID: "new-exec", EndSeq: 8, HeadSeq: 9, EndHash: endHash, HeadHash: headHash}
			if kind == "approval" {
				e.RequestSeq, e.DecisionSeq, e.ReceiptSeq, e.EndSeq, e.HeadSeq, e.HeadHash = 3, 4, 5, 10, 10, endHash
			}
			if kind == "different-execution" {
				e.ExecutionID, e.EndSeq, e.HeadSeq, e.HeadHash = "old-exec", 10, 10, endHash
			}
			if err := l.Observe(testContext, "lead", e); !errors.Is(err, ErrConflict) {
				t.Fatalf("historical %s accepted: %v", kind, err)
			}
		})
	}
}

func TestGeneratedResultPrefixReserved(t *testing.T) {
	for _, kind := range []string{"user", "tick", "task"} {
		t.Run(kind, func(t *testing.T) {
			l, _ := openTestLedger(t)
			child := seedMember(t, l)
			target := "lead"
			if kind == "task" {
				target = child.ID
			}
			before, err := l.Counts(testContext)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = l.Enqueue(testContext, Input{ID: "result-child", Target: target, Kind: kind, Payload: []byte(`{"text":"collision"}`)}); !errors.Is(err, ErrInvalid) {
				t.Fatalf("host input took generated result identity: %v", err)
			}
			after, err := l.Counts(testContext)
			if err != nil || before != after {
				t.Fatalf("reserved identity mutated ledger: %v", err)
			}
			complete(t, l, child.ID)
			if _, err = l.EnqueueResult(testContext, child.ID, []byte(`{"text":"complete"}`)); err != nil {
				t.Fatalf("generated result blocked: %v", err)
			}
		})
	}
}

func TestInputRetryConflict(t *testing.T) {
	l, _ := openTestLedger(t)
	seedLead(t, l)
	in := Input{ID: "u", Target: "lead", Kind: "user", Payload: []byte(`{"text":"hello"}`)}
	first, err := l.Enqueue(testContext, in)
	if err != nil {
		t.Fatal(err)
	}
	again, err := l.Enqueue(testContext, in)
	if err != nil || !reflect.DeepEqual(first, again) {
		t.Fatalf("input retry: %+v %v", again, err)
	}
	in.Payload = []byte(`{"text":"changed"}`)
	if _, err = l.Enqueue(testContext, in); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed input: %v", err)
	}
	if _, err = l.Enqueue(testContext, Input{ID: "forged", Target: "lead", Kind: "result", Payload: []byte(`{"text":"forged"}`)}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unproven result input: %v", err)
	}
}

func TestUncertainDeliveryStaysHeld(t *testing.T) {
	l, path := openTestLedger(t)
	seedLead(t, l)
	if _, err := l.Enqueue(testContext, Input{ID: "input", Target: "lead", Kind: "user", Payload: []byte(`{"text":"go"}`)}); err != nil {
		t.Fatal(err)
	}
	if _, err := l.NextInput(testContext, "lead", 1, 0); err != nil {
		t.Fatal(err)
	}
	if err := l.MarkUncertain(testContext, "lead", "lost-exec"); err != nil {
		t.Fatal(err)
	}
	l.Close()
	l, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if _, err = l.NextInput(testContext, "lead", 1, 0); !errors.Is(err, ErrHeld) {
		t.Fatalf("uncertain redelivery: %v", err)
	}
	if err = l.ConfirmInput(testContext, "input", "guessed-exec"); !errors.Is(err, ErrHeld) {
		t.Fatalf("uncertain outcome adopted: %v", err)
	}
}
