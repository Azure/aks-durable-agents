//go:build squadproof

package squadproof

import (
	"errors"
	"testing"
)

func TestCutIdentityAndRelease(t *testing.T) {
	l, _ := openTestLedger(t)
	if err := l.ArmCut(t.Context(), "host.finish.lead", "pause"); err != nil {
		t.Fatal(err)
	}
	if err := l.ArmCut(t.Context(), "host.finish.lead", "pause"); err != nil {
		t.Fatal(err)
	}
	if err := l.ArmCut(t.Context(), "host.finish.lead", "crash"); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed cut accepted: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- l.hit(t.Context(), "host.finish.lead") }()
	if err := l.ReleaseCut(t.Context(), "host.finish.lead"); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := l.hit(t.Context(), "host.finish.lead"); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := l.db.QueryRow(`SELECT count(*) FROM events WHERE kind='fault.hit' AND operation='host.finish.lead'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("cut rearmed: %d %v", n, err)
	}
}
