package qualification

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agent-primitives/sessions/api"
	"github.com/agent-primitives/sessions/eventlog"
)

func journalRecords(t *testing.T, execution, input, output string, models ...string) []eventlog.Record {
	t.Helper()
	log := eventlog.New()
	model := "model"
	if len(models) != 0 {
		model = models[0]
	}
	n := int64(1)
	events := []api.Event{{Kind: api.EventExecutionStart, ExecutionStart: &api.ExecutionStart{InputCount: &n, Harness: "text", HarnessVersion: "1"}}, {Kind: api.EventInput, Message: api.TextMessage("user", input)}, {Kind: api.EventModelCall, ModelCall: &api.ModelCall{ID: "call", Model: model}}, {Kind: api.EventOutput, Message: api.TextMessage("assistant", output)}, {Kind: api.EventEnd, End: &api.HarnessEnd{State: "COMPLETED"}}}
	for i, e := range events {
		e.ExecutionID = execution
		e.SchemaVersion = 1
		e.Timestamp = time.Date(2026, 1, 1, 0, 0, i, 0, time.UTC)
		if _, err := log.Append(int64(i), 0, e); err != nil {
			t.Fatal(err)
		}
	}
	return log.Snapshot()
}
func retainJournal(t *testing.T, s *Store, name, input, output string, models ...string) Journal {
	t.Helper()
	records := journalRecords(t, name+"-execution", input, output, models...)
	b, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := s.retain(b)
	if err != nil {
		t.Fatal(err)
	}
	return Journal{SessionID: name, ExecutionID: name + "-execution", HeadHash: records[len(records)-1].Hash, Count: len(records), Blob: ref}
}
func observation(t *testing.T, s *Store, name, output string) Observation {
	return Observation{CaseID: "case", Run: 1, Candidate: retainJournal(t, s, name, "question", output)}
}
func begin(t *testing.T, s *Store, p Plan) lease {
	t.Helper()
	r, e := s.Admit(context.Background(), Request{Key: "key", Requester: "caller", Plan: p})
	if e != nil {
		t.Fatal(e)
	}
	l, e := s.start(context.Background(), r.ID)
	if e != nil {
		t.Fatal(e)
	}
	return l
}
func TestJournalJSONRoundTrip(t *testing.T) {
	records := journalRecords(t, "execution", "question", "hello")
	b, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}
	var decoded []eventlog.Record
	if err = strictJSON(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if err = eventlog.VerifyChain("", decoded); err != nil {
		t.Fatalf("pinned Sessions chain changed after JSON: %v", err)
	}
	if decoded[4].Hash != records[4].Hash {
		t.Fatal("head changed")
	}
}
func TestCompletionAndVerification(t *testing.T) {
	s, dir := testStore(t)
	ctx := context.Background()
	p := testPlan()
	l := begin(t, s, p)
	obs := []Observation{observation(t, s, "candidate", "hello world")}
	r, err := s.complete(ctx, l, obs)
	if err != nil || r.State != Passed {
		t.Fatalf("completion: %+v %v", r, err)
	}
	before, _ := os.ReadFile(filepath.Join(dir, "records.db"))
	v, err := s.VerifyForActivation(ctx, r.ID, p, time.Now())
	if err != nil || v.Digest != r.Digest {
		t.Fatalf("verify: %+v %v", v, err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, "records.db"))
	if string(before) != string(after) {
		t.Fatal("verification changed state")
	}
	again, err := s.complete(ctx, l, obs)
	if err != nil || again.Digest != r.Digest {
		t.Fatalf("lost reply retry: %+v %v", again, err)
	}
	changed := testPlan()
	changed.Subject.PolicyDigest = digest("9")
	if _, err = s.VerifyForActivation(ctx, r.ID, changed, time.Now()); !errors.Is(err, ErrIneligible) {
		t.Fatalf("drift: %v", err)
	}
	if _, err = s.VerifyForActivation(ctx, r.ID, p, p.ExpiresAt); !errors.Is(err, ErrIneligible) {
		t.Fatalf("expired: %v", err)
	}
	lineage := s.Lineage()
	s.Close()
	s, err = Open(dir, lineage)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	v, err = s.VerifyForActivation(ctx, r.ID, p, time.Now())
	if err != nil || v.Digest != r.Digest {
		t.Fatalf("restart: %+v %v", v, err)
	}
	blob := filepath.Join(dir, "evidence", obs[0].Candidate.Blob.Digest[7:])
	if err = os.WriteFile(blob, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = s.VerifyForActivation(ctx, r.ID, p, time.Now()); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("corrupt: %v", err)
	}
	if _, err = s.retain([]byte("corrupt")); err != nil {
		t.Fatal(err)
	}
}
func TestCoverageAndJournalRefusals(t *testing.T) {
	for name, change := range map[string]func(*Store, []Observation) []Observation{
		"missing":   func(_ *Store, _ []Observation) []Observation { return nil },
		"duplicate": func(_ *Store, o []Observation) []Observation { return append(o, o[0]) },
		"case":      func(_ *Store, o []Observation) []Observation { o[0].CaseID = "other"; return o },
		"run":       func(_ *Store, o []Observation) []Observation { o[0].Run = 2; return o },
		"head": func(_ *Store, o []Observation) []Observation {
			o[0].Candidate.HeadHash = strings.Repeat("9", 64)
			return o
		},
		"count":     func(_ *Store, o []Observation) []Observation { o[0].Candidate.Count++; return o },
		"execution": func(_ *Store, o []Observation) []Observation { o[0].Candidate.ExecutionID = "foreign"; return o },
		"size":      func(_ *Store, o []Observation) []Observation { o[0].Candidate.Blob.Size++; return o },
		"input": func(s *Store, o []Observation) []Observation {
			o[0].Candidate = retainJournal(t, s, "foreign", "other question", "hello")
			return o
		},
		"unexpected-judge": func(_ *Store, o []Observation) []Observation {
			o[0].Judges = []Judgment{{AssertionID: "answer", Calls: []Journal{o[0].Candidate, o[0].Candidate}}}
			return o
		},
		"tool": func(s *Store, o []Observation) []Observation {
			records := journalRecords(t, "candidate-execution", "question", "hello")
			records[2].Event.Kind = api.EventToolCall
			records[2].Event.ModelCall = nil
			records[2].Event.ToolCall = &api.ToolCall{ID: "tool", Tool: "write"}
			log := eventlog.New()
			for i, r := range records {
				if _, err := log.Append(int64(i), 0, r.Event); err != nil {
					t.Fatal(err)
				}
			}
			records = log.Snapshot()
			b, _ := json.Marshal(records)
			o[0].Candidate.Blob, _ = s.retain(b)
			o[0].Candidate.HeadHash = records[4].Hash
			return o
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, _ := testStore(t)
			p := testPlan()
			l := begin(t, s, p)
			obs := change(s, []Observation{observation(t, s, "candidate", "hello")})
			r, err := s.complete(context.Background(), l, obs)
			if err != nil || r.State != Incomplete {
				t.Fatalf("want incomplete, got %+v %v", r, err)
			}
			if _, err = s.VerifyForActivation(context.Background(), r.ID, p, time.Now()); !errors.Is(err, ErrIneligible) {
				t.Fatalf("eligibility: %v", err)
			}
		})
	}
}
func judgedPlan() Plan {
	p := testPlan()
	p.Cases[0].Assertions = []Assertion{{ID: "quality", Kind: "llmJudge", MinScore: 70, JudgeModel: "judge-model"}}
	return p
}
func judgedObservation(t *testing.T, s *Store, scores [2]int) Observation {
	o := observation(t, s, "candidate", "hello")
	input := `{"version":1,"assertionID":"quality","outputDigest":"` + hashBytes([]byte("hello")) + `","model":"judge-model"}`
	o.Judges = []Judgment{{AssertionID: "quality"}}
	for i, score := range scores {
		o.Judges[0].Calls = append(o.Judges[0].Calls, retainJournal(t, s, fmt.Sprintf("judge-%d", i), input, fmt.Sprintf(`{"score":%d,"model":"judge-model"}`, score), "judge-model"))
	}
	return o
}
func TestCompletionScoresAndRepeats(t *testing.T) {
	for _, tt := range []struct {
		name   string
		scores [2]int
		want   State
	}{{"pass", [2]int{70, 90}, Passed}, {"fail", [2]int{20, 69}, Failed}, {"split", [2]int{70, 69}, Incomplete}} {
		t.Run(tt.name, func(t *testing.T) {
			s, _ := testStore(t)
			p := judgedPlan()
			l := begin(t, s, p)
			r, err := s.complete(context.Background(), l, []Observation{judgedObservation(t, s, tt.scores)})
			if err != nil || r.State != tt.want {
				t.Fatalf("state %s %v", r.State, err)
			}
			if tt.want == Passed {
				if _, err = s.VerifyForActivation(context.Background(), r.ID, p, time.Now()); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	s, _ := testStore(t)
	p := testPlan()
	p.Cases[0].Runs = 2
	p.Cases[0].MinPasses = 1
	l := begin(t, s, p)
	a := observation(t, s, "first", "no match")
	b := observation(t, s, "second", "hello")
	b.Run = 2
	r, err := s.complete(context.Background(), l, []Observation{a, b})
	if err != nil || r.State != Passed {
		t.Fatalf("minPasses: %s %v", r.State, err)
	}
}
func TestIncompleteNeverPasses(t *testing.T) {
	s, _ := testStore(t)
	p := testPlan()
	l := begin(t, s, p)
	o := []Observation{observation(t, s, "candidate", "hello")}
	if _, err := s.interrupt(context.Background(), l); err != nil {
		t.Fatal(err)
	}
	if _, err := s.complete(context.Background(), l, o); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale lease: %v", err)
	}
}
