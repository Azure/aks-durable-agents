package qualification

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestClosedStoreUnavailable(t *testing.T) {
	s, _ := testStore(t)
	p := testPlan()
	l := begin(t, s, p)
	obs := []Observation{observation(t, s, "candidate", "hello")}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	for name, call := range map[string]func() error{
		"read": func() error { _, e := s.Read(context.Background(), l.ID); return e },
		"admit": func() error {
			_, e := s.Admit(context.Background(), Request{Key: "key", Requester: "caller", Plan: p})
			return e
		},
		"start":      func() error { _, e := s.start(context.Background(), l.ID); return e },
		"interrupt":  func() error { _, e := s.interrupt(context.Background(), l); return e },
		"retain":     func() error { _, e := s.retain([]byte("bytes")); return e },
		"complete":   func() error { _, e := s.complete(context.Background(), l, obs); return e },
		"activation": func() error { _, e := s.VerifyForActivation(context.Background(), l.ID, p, time.Now()); return e },
	} {
		t.Run(name, func(t *testing.T) {
			err := call()
			if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrIntegrity) {
				t.Fatalf("closed store misclassified: %v", err)
			}
		})
	}
}
func TestSQLiteFullUnavailable(t *testing.T) {
	s, _ := testStore(t)
	var pages int
	if err := s.db.QueryRow("PRAGMA page_count").Scan(&pages); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(fmt.Sprintf("PRAGMA max_page_count=%d", pages)); err != nil {
		t.Fatal(err)
	}
	p := testPlan()
	for i := range 8 {
		p.Cases[0].Assertions = append(p.Cases[0].Assertions, Assertion{ID: fmt.Sprintf("big%d", i), Kind: "contains", Value: strings.Repeat("x", 4096)})
	}
	_, err := s.Admit(context.Background(), Request{Key: "full", Requester: "caller", Plan: p})
	if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrIntegrity) {
		t.Fatalf("disk full misclassified: %v", err)
	}
	var count int
	if err = s.db.QueryRow("SELECT count(*) FROM records").Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed admission persisted: %d %v", count, err)
	}
}
