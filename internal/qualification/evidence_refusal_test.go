package qualification

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/agent-primitives/sessions/eventlog"
)

func TestJournalRefusesUnsuccessfulExecutionEnd(t *testing.T) {
	for _, state := range []string{"FAILED", "CANCELLED"} {
		t.Run(state, func(t *testing.T) {
			s, _ := testStore(t)
			p := testPlan()
			l := begin(t, s, p)
			records := journalRecords(t, "candidate-execution", "question", "hello")
			records[len(records)-1].Event.End.State = state
			// A fresh valid chain isolates the ExecutionEnd state guard; stale
			// hashes would let the chain verifier mask a missing state check.
			log := eventlog.New()
			for i, r := range records {
				if _, err := log.Append(int64(i), 0, r.Event); err != nil {
					t.Fatal(err)
				}
			}
			records = log.Snapshot()
			if err := eventlog.VerifyChain("", records); err != nil {
				t.Fatalf("unsuccessful-end fixture is not a valid chain: %v", err)
			}
			o := Observation{CaseID: "case", Run: 1, Candidate: retainGuardJournal(t, s, "candidate", records)}
			done, err := s.complete(context.Background(), l, []Observation{o})
			if err != nil || done.State != Incomplete || done.Reason != "evidence" {
				t.Fatalf("%s execution accepted: %+v %v", state, done, err)
			}
			if _, err = s.VerifyForActivation(context.Background(), l.ID, p, time.Now()); !errors.Is(err, ErrIneligible) {
				t.Fatalf("%s execution eligible: %v", state, err)
			}
		})
	}
}

func TestSameSizeCorruptedBlobRefused(t *testing.T) {
	for _, phase := range []string{"completion", "activation", "retain-existing"} {
		t.Run(phase, func(t *testing.T) {
			s, dir := testStore(t)
			p := testPlan()
			l := begin(t, s, p)
			obs := []Observation{observation(t, s, "candidate", "hello")}
			if phase == "activation" {
				if done, err := s.complete(context.Background(), l, obs); err != nil || done.State != Passed {
					t.Fatalf("valid evidence did not pass: %s %v", done.State, err)
				}
			}
			ref := obs[0].Candidate.Blob
			path := filepath.Join(dir, "evidence", ref.Digest[7:])
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			corrupt := bytes.Replace(original, []byte("hello"), []byte("jello"), 1)
			if bytes.Equal(original, corrupt) || int64(len(corrupt)) != ref.Size {
				t.Fatal("same-size corruption fixture did not change content")
			}
			if err = os.WriteFile(path, corrupt, 0600); err != nil {
				t.Fatal(err)
			}
			switch phase {
			case "completion":
				done, err := s.complete(context.Background(), l, obs)
				if err != nil || done.State != Incomplete || done.Reason != "evidence" {
					t.Fatalf("same-size corrupt evidence completed: %+v %v", done, err)
				}
			case "activation":
				if _, err = s.VerifyForActivation(context.Background(), l.ID, p, time.Now()); !errors.Is(err, ErrIntegrity) {
					t.Fatalf("same-size corrupt evidence activated: %v", err)
				}
			case "retain-existing":
				if _, err = s.retain(original); !errors.Is(err, ErrIntegrity) {
					t.Fatalf("same-size corrupt existing object retained: %v", err)
				}
				got, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(got, corrupt) {
					t.Fatalf("refused retain overwrote corrupt object: %v", err)
				}
			}
		})
	}
}

func TestOpenRefusesTamperedRecord(t *testing.T) {
	for _, mutation := range []string{"body-digest", "plan-binding", "scope-projection"} {
		t.Run(mutation, func(t *testing.T) {
			s, dir := testStore(t)
			r := admit(t, s)
			lineage := s.Lineage()
			if mutation == "scope-projection" {
				if _, err := s.db.Exec("UPDATE records SET workspace='foreign' WHERE id=?", r.ID); err != nil {
					t.Fatal(err)
				}
			} else {
				r.Request.Plan.Subject.SuiteDigest = digest("9")
				if mutation == "plan-binding" {
					seal(&r) // A valid outer seal cannot replace request/plan binding.
				}
				body, err := json.Marshal(r)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = s.db.Exec("UPDATE records SET body=? WHERE id=?", body, r.ID); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(filepath.Join(dir, "records.db"))
			if err != nil {
				t.Fatal(err)
			}
			reopened, err := Open(dir, lineage)
			if reopened != nil {
				_ = reopened.Close()
			}
			if !errors.Is(err, ErrIntegrity) {
				t.Fatalf("Open accepted %s tampering: %v", mutation, err)
			}
			after, err := os.ReadFile(filepath.Join(dir, "records.db"))
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("refused Open changed tampered database: %v", err)
			}
		})
	}
}

func TestRetainExistingObjectSyncsDirectory(t *testing.T) {
	s, dir := testStore(t)
	data := []byte("already renamed evidence")
	ref, err := s.retain(data)
	if err != nil {
		t.Fatal(err)
	}
	original := syncDir
	fault := true
	calls := 0
	syncDir = func(path string) error {
		if path == filepath.Join(dir, "evidence") {
			calls++
			if fault {
				return fileError(syscall.EIO)
			}
		}
		return original(path)
	}
	t.Cleanup(func() { syncDir = original })
	if _, err = s.retain(data); !errors.Is(err, ErrUnavailable) || calls != 1 {
		t.Fatalf("existing-object retry did not report failed directory sync: calls=%d err=%v", calls, err)
	}
	fault = false
	again, err := s.retain(data)
	if err != nil || again != ref || calls != 2 {
		t.Fatalf("retry after directory-sync failure: %+v calls=%d err=%v", again, calls, err)
	}
}
