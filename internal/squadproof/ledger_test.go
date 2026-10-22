package squadproof

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/agent-primitives/sessions/controller"
)

var testContext = context.Background()
var packageDigest = strings.Repeat("a", 64)
var headHash = strings.Repeat("b", 64)
var endHash = strings.Repeat("c", 64)

func openTestLedger(t *testing.T) (*Ledger, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "proof.db")
	l, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l, path
}

func seedLead(t *testing.T, l *Ledger) Operation {
	t.Helper()
	op, err := l.Admit(testContext, Operation{ID: "lead", Kind: "lead", Team: "team-a", PackageDigest: packageDigest, Member: "lead", Epoch: 1, Payload: []byte(`{"task":"coordinate"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if err = l.BindSession(testContext, op.ID, "session-lead"); err != nil {
		t.Fatal(err)
	}
	op, err = l.Operation(testContext, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	return op
}

func beginExecution(t *testing.T, l *Ledger, id, executionID string) {
	t.Helper()
	op, err := l.Operation(testContext, id)
	if err != nil {
		t.Fatal(err)
	}
	kind := "user"
	if op.Kind == "dispatch" {
		kind = "task"
	}
	if _, err = l.Enqueue(testContext, Input{ID: "start-" + executionID, Target: id, Kind: kind, Payload: []byte(`{"text":"start"}`)}); err != nil {
		t.Fatal(err)
	}
	if _, err = l.NextInput(testContext, id, op.Epoch, op.Evidence.HeadSeq); err != nil {
		t.Fatal(err)
	}
	if err = l.ConfirmInput(testContext, "start-"+executionID, executionID); err != nil {
		t.Fatal(err)
	}
}

func complete(t *testing.T, l *Ledger, id string) {
	t.Helper()
	beginExecution(t, l, id, "exec-"+id)
	op, err := l.Operation(testContext, id)
	if err != nil {
		t.Fatal(err)
	}
	end := op.InputHeadSeq + 8
	if err = l.Observe(testContext, id, Evidence{ExecutionID: "exec-" + id, HeadSeq: end, HeadHash: endHash, EndSeq: end, EndHash: endHash}); err != nil {
		t.Fatal(err)
	}
}

func TestAdmitRetryConflict(t *testing.T) {
	l, path := openTestLedger(t)
	op := seedLead(t, l)
	retry := op
	retry.SessionUID, retry.State = "", ""
	retry.Payload = []byte(`{ "task" : "coordinate" }`)
	got, err := l.Admit(testContext, retry)
	if err != nil || !reflect.DeepEqual(got, op) {
		t.Fatalf("retry: %+v %v", got, err)
	}
	retry.Payload = []byte(`{"task":"different"}`)
	if _, err = l.Admit(testContext, retry); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed content: %v", err)
	}
	if err = l.BindSession(testContext, "lead", "replacement"); !errors.Is(err, ErrConflict) {
		t.Fatalf("rebound UID: %v", err)
	}
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, err = reopened.Operation(testContext, "lead")
	if err != nil || !reflect.DeepEqual(got, op) {
		t.Fatalf("retained operation: %+v %v", got, err)
	}
	if err = reopened.MarkUncertain(testContext, "lead", "lost-exec"); err != nil {
		t.Fatal(err)
	}
	if err = reopened.Observe(testContext, "lead", Evidence{ExecutionID: "guess", HeadSeq: 8, HeadHash: endHash, EndSeq: 8, EndHash: endHash}); !errors.Is(err, ErrHeld) {
		t.Fatalf("uncertainty cleared: %v", err)
	}
	if err = reopened.BindSession(testContext, "lead", "session-lead"); !errors.Is(err, ErrHeld) {
		t.Fatalf("uncertain rebound: %v", err)
	}
}

func TestForeignLedgerRefused(t *testing.T) {
	for _, kind := range []string{"empty", "foreign", "version", "schema"} {
		t.Run(kind, func(t *testing.T) {
			l, path := openTestLedger(t)
			if err := l.Close(); err != nil {
				t.Fatal(err)
			}
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "empty":
				db.Close()
				if err = os.Truncate(path, 0); err != nil {
					t.Fatal(err)
				}
			case "foreign":
				_, err = db.Exec("PRAGMA application_id=0")
			case "version":
				_, err = db.Exec("PRAGMA user_version=99")
			case "schema":
				_, err = db.Exec("DROP TABLE effects")
			}
			if err != nil {
				t.Fatal(err)
			}
			db.Close()
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if bad, err := OpenLedger(path); !errors.Is(err, ErrForeign) {
				if bad != nil {
					bad.Close()
				}
				t.Fatalf("adopted %s: %v", kind, err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatalf("foreign data changed: %v", err)
			}
		})
	}
}

func TestHotJournalIdentityCheck(t *testing.T) {
	for _, kind := range []string{"foreign", "proof"} {
		t.Run(kind, func(t *testing.T) {
			l, path := openTestLedger(t)
			seedLead(t, l)
			expected, err := l.Counts(testContext)
			if err != nil {
				t.Fatal(err)
			}
			if err = l.Close(); err != nil {
				t.Fatal(err)
			}
			if kind == "foreign" {
				db, err := sql.Open("sqlite", path)
				if err != nil {
					t.Fatal(err)
				}
				_, err = db.Exec("PRAGMA application_id=42")
				db.Close()
				if err != nil {
					t.Fatal(err)
				}
			}
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			out, err := exec.Command(binary, "-test.run=^TestHotJournalWriter$", "--", "hot-journal", path).CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 74 {
				t.Fatalf("writer did not exit with uncommitted spilled pages: %s %v", out, err)
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			journal, err := os.ReadFile(path + "-journal")
			if err != nil || len(journal) < 512 {
				t.Fatalf("writer did not leave rollback journal: %v", err)
			}
			reopened, err := OpenLedger(path)
			if kind == "foreign" {
				if !errors.Is(err, ErrForeign) {
					if reopened != nil {
						reopened.Close()
					}
					t.Fatalf("foreign accepted: %v", err)
				}
				after, readErr := os.ReadFile(path)
				retained, journalErr := os.ReadFile(path + "-journal")
				if readErr != nil || journalErr != nil || !reflect.DeepEqual(before, after) || !reflect.DeepEqual(journal, retained) {
					t.Fatalf("foreign hot journal/database modified: read=%v journal=%v", readErr, journalErr)
				}
			} else {
				if err != nil {
					t.Fatalf("recognized proof cannot recover: %v", err)
				}
				defer reopened.Close()
				got, err := reopened.Counts(testContext)
				if err != nil || got != expected {
					t.Fatalf("uncommitted rows survived recovery: %+v %v", got, err)
				}
			}
		})
	}
}

func TestHotJournalWriter(t *testing.T) {
	if len(os.Args) < 3 || os.Args[len(os.Args)-2] != "hot-journal" {
		t.Skip("subprocess-only hot journal writer")
	}
	db, err := sql.Open("sqlite", os.Args[len(os.Args)-1])
	if err != nil {
		t.Fatal(err)
	}
	conn, err := db.Conn(testContext)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = conn.ExecContext(testContext, `PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA cache_size=4; BEGIN IMMEDIATE;
 WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<128)
 INSERT INTO effects(uid,key,body) SELECT 'uncommitted',printf('%d',i),zeroblob(2048) FROM n`); err != nil {
		t.Fatal(err)
	}
	os.Exit(74) // Leave the dirty pager and transaction open, without SQLite cleanup.
}

func TestEpochAdvanceHeldWithChild(t *testing.T) {
	l, _ := openTestLedger(t)
	child := seedMember(t, l)
	if err := l.AdvanceEpoch(testContext, "lead", 1, 2); !errors.Is(err, ErrHeld) {
		t.Fatalf("outstanding child stranded: %v", err)
	}
	complete(t, l, child.ID)
	if err := l.AdvanceEpoch(testContext, "lead", 1, 2); err != nil {
		t.Fatalf("completed child still holds owner: %v", err)
	}
	call := dispatchCall("next-child")
	call.Args["epoch"] = 2
	if _, err := (&Executor{Ledger: l}).Execute(testContext, controller.ToolCallContext{SessionUID: "session-lead"}, call); err != nil {
		t.Fatalf("new owner cannot dispatch: %v", err)
	}
}

func TestEvidenceRefusesRegression(t *testing.T) {
	l, _ := openTestLedger(t)
	seedLead(t, l)
	beginExecution(t, l, "lead", "exec-lead")
	first := Evidence{ExecutionID: "exec-lead", RequestSeq: 3, DecisionSeq: 4, HeadSeq: 4, HeadHash: headHash}
	if err := l.Observe(testContext, "lead", first); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"head", "execution", "decision", "end"} {
		bad := first
		want := ErrConflict
		switch kind {
		case "head":
			bad.HeadHash = endHash
		case "execution":
			bad.ExecutionID, bad.HeadSeq = "other-exec", 5
		case "decision":
			bad.DecisionSeq, bad.HeadSeq = 0, 5
		case "end":
			bad.EndSeq, bad.EndHash, bad.HeadSeq = 5, endHash, 6
			want = ErrInvalid
		}
		if err := l.Observe(testContext, "lead", bad); !errors.Is(err, want) {
			t.Fatalf("%s evidence accepted: %v", kind, err)
		}
	}
	got, err := l.Operation(testContext, "lead")
	if err != nil || !reflect.DeepEqual(got.Evidence, first) {
		t.Fatalf("rejected evidence changed state: %+v %v", got, err)
	}
}

func TestAdmissionPayloadBoundary(t *testing.T) {
	for _, payload := range []string{`null`, `[]`, `{"task":"one","task":"two"}`, `{"text":"` + strings.Repeat("x", 16<<10) + `"}`} {
		l, _ := openTestLedger(t)
		if _, err := l.Admit(testContext, Operation{ID: "lead", Kind: "lead", Team: "team-a", Member: "lead", PackageDigest: packageDigest, Epoch: 1, Payload: []byte(payload)}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid admission: %v", err)
		}
		stats, err := l.Counts(testContext)
		if err != nil || stats != (Stats{}) {
			t.Fatalf("partial invalid admission: %+v %v", stats, err)
		}
	}
}

func TestLedgerPathRefusals(t *testing.T) {
	_, path := openTestLedger(t)
	link := filepath.Join(filepath.Dir(path), "link.db")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if l, err := OpenLedger(link); !errors.Is(err, ErrInvalid) {
		if l != nil {
			l.Close()
		}
		t.Fatalf("symlink accepted: %v", err)
	}
	if l, err := OpenLedger("relative.db"); !errors.Is(err, ErrInvalid) {
		if l != nil {
			l.Close()
		}
		t.Fatalf("relative path accepted: %v", err)
	}
	if err := os.Chmod(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(filepath.Dir(path), 0700)
	if l, err := OpenLedger(path); !errors.Is(err, ErrInvalid) {
		if l != nil {
			l.Close()
		}
		t.Fatalf("public directory accepted: %v", err)
	}
}
