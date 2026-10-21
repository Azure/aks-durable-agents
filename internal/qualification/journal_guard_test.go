package qualification

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/agent-primitives/sessions/api"
	"github.com/agent-primitives/sessions/eventlog"
)

// Synthetic journal regressions. No runner or producer attestation is implied.
func retainGuardJournal(t *testing.T, s *Store, name string, records []eventlog.Record) Journal {
	t.Helper()
	b, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := s.retain(b)
	if err != nil {
		t.Fatal(err)
	}
	return Journal{SessionID: name, ExecutionID: records[0].Event.ExecutionID, HeadHash: records[len(records)-1].Hash, Count: len(records), Blob: ref}
}
func TestJournalHashChainIntegrity(t *testing.T) {
	s, _ := testStore(t)
	l := begin(t, s, testPlan())
	records := journalRecords(t, "candidate-execution", "question", "denied")
	// Preserve the independently retained terminal head but edit earlier content.
	records[3].Event.Message = api.TextMessage("assistant", "hello")
	o := Observation{CaseID: "case", Run: 1, Candidate: retainGuardJournal(t, s, "candidate", records)}
	r, err := s.complete(context.Background(), l, []Observation{o})
	if err != nil || r.State != Incomplete {
		t.Fatalf("edited hash-chain accepted: %s %v", r.State, err)
	}
}
func TestJournalExactlyOnePayload(t *testing.T) {
	s, _ := testStore(t)
	l := begin(t, s, testPlan())
	records := journalRecords(t, "candidate-execution", "question", "hello")
	records[2].Event.ToolCall = &api.ToolCall{ID: "hidden", Tool: "write"}
	log := eventlog.New()
	for i, r := range records {
		if _, err := log.Append(int64(i), 0, r.Event); err != nil {
			t.Fatal(err)
		}
	}
	o := Observation{CaseID: "case", Run: 1, Candidate: retainGuardJournal(t, s, "candidate", log.Snapshot())}
	r, err := s.complete(context.Background(), l, []Observation{o})
	if err != nil || r.State != Incomplete {
		t.Fatalf("mixed tool/model payload accepted: %s %v", r.State, err)
	}
}
func TestJournalExecutionUniqueness(t *testing.T) {
	s, _ := testStore(t)
	p := testPlan()
	p.Cases[0].Runs = 2
	l := begin(t, s, p)
	a := observation(t, s, "first", "hello")
	b := a
	b.Run = 2
	b.Candidate.SessionID = "other-session"
	r, err := s.complete(context.Background(), l, []Observation{a, b})
	if err != nil || r.State != Incomplete {
		t.Fatalf("reused execution with new session label accepted: %s %v", r.State, err)
	}
}
