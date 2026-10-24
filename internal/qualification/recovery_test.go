package qualification

import (
	"context"
	"encoding/json"
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func makeFIFO(path string) error { return unix.Mkfifo(path, 0600) }

func TestPrivateStorageRefusals(t *testing.T) {
	for _, name := range []string{"missing-db", "empty-db", "future-schema", "wrong-db-lineage", "missing-anchor", "sidecar", "symlink", "fifo", "evidence-mode"} {
		t.Run(name, func(t *testing.T) {
			s, dir := testStore(t)
			lineage := s.Lineage()
			db := s.db
			switch name {
			case "future-schema":
				if _, err := db.Exec("UPDATE metadata SET version=2"); err != nil {
					t.Fatal(err)
				}
			case "wrong-db-lineage":
				if _, err := db.Exec("UPDATE metadata SET lineage='foreign'"); err != nil {
					t.Fatal(err)
				}
			}
			s.Close()
			switch name {
			case "missing-db":
				os.Remove(filepath.Join(dir, "records.db"))
			case "empty-db":
				os.Truncate(filepath.Join(dir, "records.db"), 0)
			case "missing-anchor":
				os.Remove(filepath.Join(dir, "lineage"))
			case "sidecar":
				os.WriteFile(filepath.Join(dir, "records.db-wal"), []byte("unsafe"), 0600)
				os.Chmod(filepath.Join(dir, "records.db-wal"), 0644)
			case "symlink":
				os.Rename(filepath.Join(dir, "records.db"), filepath.Join(dir, "original"))
				os.Symlink("original", filepath.Join(dir, "records.db"))
			case "fifo":
				os.Remove(filepath.Join(dir, "records.db"))
				if err := makeFIFO(filepath.Join(dir, "records.db")); err != nil {
					t.Fatal(err)
				}
			case "evidence-mode":
				os.Chmod(filepath.Join(dir, "evidence"), 0755)
			}
			before, _ := os.ReadDir(dir)
			if _, err := Open(dir, lineage); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("want integrity, got %v", err)
			}
			after, _ := os.ReadDir(dir)
			if len(after) != len(before) {
				t.Fatal("refused Open created files")
			}
		})
	}
}
func TestInterruptedReadBack(t *testing.T) {
	// Subprocess exits bypass Close and emulate loss of a worker/response after
	// durable boundaries, not power loss or storage-device flush behavior.
	if dir := os.Getenv("QUALIFICATION_CRASH_DIR"); dir != "" {
		s, err := Create(dir)
		if err != nil {
			t.Fatal(err)
		}
		p := testPlan()
		l := begin(t, s, p)
		o := []Observation{observation(t, s, "candidate", "hello")}
		switch os.Getenv("QUALIFICATION_CRASH_PHASE") {
		case "hot-journal":
			if _, err = s.db.Exec("PRAGMA cache_size=1; BEGIN IMMEDIATE; UPDATE records SET body=randomblob(1048576)"); err != nil {
				t.Fatal(err)
			}
		case "verifying":
			r, err := s.Read(context.Background(), l.ID)
			if err != nil {
				t.Fatal(err)
			}
			r.State = Verifying
			r.Observations = o
			if err = s.save(context.Background(), r, false); err != nil {
				t.Fatal(err)
			}
		case "terminal":
			if _, err = s.complete(context.Background(), l, o); err != nil {
				t.Fatal(err)
			}
		}
		os.Exit(0)
	}
	for _, phase := range []string{"retained", "verifying", "terminal", "hot-journal"} {
		t.Run(phase, func(t *testing.T) {
			dir := filepath.Join(privateTestDir(t), "store")
			cmd := exec.Command(os.Args[0], "-test.run=^TestInterruptedReadBack$")
			cmd.Env = append(os.Environ(), "QUALIFICATION_CRASH_DIR="+dir, "QUALIFICATION_CRASH_PHASE="+phase)
			if b, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("child %v: %s", err, b)
			}
			anchor, err := os.ReadFile(filepath.Join(dir, "lineage"))
			if err != nil {
				t.Fatal(err)
			}
			if phase == "hot-journal" {
				journalPath := filepath.Join(dir, "records.db-journal")
				before, err := os.ReadFile(journalPath)
				if err != nil || len(before) == 0 {
					t.Fatalf("missing hot journal: %v", err)
				}
				if _, err = Open(dir, string(anchor)); !errors.Is(err, ErrIntegrity) {
					t.Fatalf("hot journal must fence offline recovery: %v", err)
				}
				after, err := os.ReadFile(journalPath)
				if err != nil || string(before) != string(after) {
					t.Fatalf("refused Open altered hot journal: %v", err)
				}
				return
			}
			s, err := Open(dir, string(anchor))
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			r, err := s.Admit(context.Background(), Request{Key: "key", Requester: "caller", Plan: testPlan()})
			if err != nil {
				t.Fatal(err)
			}
			if phase == "terminal" {
				if r.State != Passed {
					t.Fatalf("terminal state %s", r.State)
				}
				if _, err = s.VerifyForActivation(context.Background(), r.ID, testPlan(), time.Now()); err != nil {
					t.Fatal(err)
				}
			} else {
				want := Running
				if phase == "verifying" {
					want = Verifying
				}
				if r.State != want {
					t.Fatalf("restart advanced %s", r.State)
				}
				l := lease{r.ID, r.Generation}
				if _, err = s.interrupt(context.Background(), l); err != nil {
					t.Fatal(err)
				}
				if _, err = s.complete(context.Background(), l, []Observation{observation(t, s, "later", "hello")}); !errors.Is(err, ErrConflict) {
					t.Fatalf("late completion %v", err)
				}
			}
		})
	}
}
func TestCompletionInterruptRace(t *testing.T) {
	s, _ := testStore(t)
	l := begin(t, s, testPlan())
	obs := []Observation{observation(t, s, "candidate", "hello")}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, f := range []func() error{func() error { _, err := s.complete(context.Background(), l, obs); return err }, func() error { _, err := s.interrupt(context.Background(), l); return err }} {
		wg.Go(func() {
			<-start
			if err := f(); err != nil && !errors.Is(err, ErrConflict) {
				t.Errorf("race: %v", err)
			}
		})
	}
	close(start)
	wg.Wait()
	r, err := s.Read(context.Background(), l.ID)
	if err != nil || (r.State != Passed && r.State != Incomplete) {
		t.Fatalf("race result %s %v", r.State, err)
	}
}
func TestStoreRecordTamperAndConnectionReplacement(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	r := admit(t, s)
	s.db.SetMaxIdleConns(0)
	for range 2 {
		var synchronous int
		var mode string
		if err := s.db.QueryRow("PRAGMA synchronous").Scan(&synchronous); err != nil {
			t.Fatal(err)
		}
		if err := s.db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
			t.Fatal(err)
		}
		if synchronous != 3 || mode != "delete" {
			t.Fatalf("lost pragmas: %d %s", synchronous, mode)
		}
	}
	s.db.SetMaxIdleConns(1)
	r.Request.Plan.Subject.SuiteDigest = digest("9")
	b, _ := json.Marshal(r)
	if _, err := s.db.Exec("UPDATE records SET body=? WHERE id=?", b, r.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Read(ctx, r.ID); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("tamper accepted: %v", err)
	}
}
func TestEvidenceAndScoreRefusals(t *testing.T) {
	for _, name := range []string{"reuse-session", "extra-judge", "missing-judge", "missing-score", "duplicate-score", "null-score", "unknown-score", "binding", "actual-model", "score-model", "score-low", "score-high", "binding-output", "binding-model", "tail", "missing-blob", "corrupt-existing"} {
		t.Run(name, func(t *testing.T) {
			s, dir := testStore(t)
			p := judgedPlan()
			l := begin(t, s, p)
			o := judgedObservation(t, s, [2]int{80, 90})
			switch name {
			case "reuse-session":
				o.Judges[0].Calls[1] = o.Judges[0].Calls[0]
			case "extra-judge":
				o.Judges = append(o.Judges, o.Judges[0])
			case "missing-judge":
				o.Judges = nil
			case "missing-score", "duplicate-score", "null-score", "unknown-score", "binding", "actual-model", "score-model", "score-low", "score-high", "binding-output", "binding-model":
				input := `{"version":1,"assertionID":"quality","outputDigest":"` + hashBytes([]byte("hello")) + `","model":"judge-model"}`
				output := `{"score":80,"model":"judge-model"}`
				switch name {
				case "missing-score":
					output = `{"model":"judge-model"}`
				case "duplicate-score":
					output = `{"score":80,"score":90,"model":"judge-model"}`
				case "null-score":
					output = `{"score":null,"model":"judge-model"}`
				case "unknown-score":
					output = `{"score":80,"model":"judge-model","extra":1}`
				case "binding":
					input = strings.Replace(input, "quality", "foreign", 1)
				case "score-model":
					output = `{"score":80,"model":"wrong-model"}`
				case "score-low":
					output = `{"score":-1,"model":"judge-model"}`
				case "score-high":
					output = `{"score":101,"model":"judge-model"}`
				case "binding-output":
					input = strings.Replace(input, hashBytes([]byte("hello")), digest("9"), 1)
				case "binding-model":
					input = strings.Replace(input, "judge-model", "other-model", 1)
				}
				actualModel := "judge-model"
				if name == "actual-model" {
					actualModel = "wrong-model"
				}
				o.Judges[0].Calls[0] = retainJournal(t, s, "replacement", input, output, actualModel)
			case "tail":
				records := journalRecords(t, "candidate-execution", "question", "hello")
				records = records[:4]
				b, _ := json.Marshal(records)
				ref, err := s.retain(b)
				if err != nil {
					t.Fatal(err)
				}
				o.Candidate.Blob = ref
				o.Candidate.Count = 4
				o.Candidate.HeadHash = records[3].Hash
			case "missing-blob":
				os.Remove(filepath.Join(dir, "evidence", o.Candidate.Blob.Digest[7:]))
			case "corrupt-existing":
				path := filepath.Join(dir, "evidence", o.Candidate.Blob.Digest[7:])
				original, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				os.WriteFile(path, []byte("corrupt"), 0600)
				if _, err = s.retain(original); !errors.Is(err, ErrIntegrity) {
					t.Fatalf("overwrote corrupt object: %v", err)
				}
			}
			r, err := s.complete(context.Background(), l, []Observation{o})
			if err != nil || r.State != Incomplete {
				t.Fatalf("want incomplete got %s %v", r.State, err)
			}
		})
	}
}
