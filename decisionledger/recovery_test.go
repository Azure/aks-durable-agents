package decisionledger

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Azure/aks-durable-agents/entraauth"
)

// The helper emits only synthetic opaque identities, then waits for its parent.
// Killing it tests process recovery, not a hardware/power-loss guarantee.
func TestLedgerCrashHelper(t *testing.T) {
	mode := os.Getenv("ADA_LEDGER_TEST_MODE")
	if mode == "" {
		return
	}
	s, err := Initialize(os.Getenv("ADA_LEDGER_TEST_PATH"), "host-lineage")
	if err != nil {
		t.Fatal(err)
	}
	ref, err := s.RegisterSubject(context.Background(), suiteSubject())
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(s.ID())
	in := bufio.NewReader(os.Stdin)
	if _, err = in.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	if mode == "after" {
		svc, _ := NewService(s, requestVerifier{}, &testPolicy{})
		out, err := svc.Decide(humanContext("alice", time.Now().Add(time.Hour)), DecideRequest{Workspace: ref.Workspace, Key: "key", Subject: ref, Action: Accept})
		if err != nil {
			t.Fatal(err)
		}
		fmt.Println(out.ID)
	} else {
		fmt.Println("before")
	}
	in.ReadString('\n')
}
func TestProcessCrashReadBack(t *testing.T) {
	for _, mode := range []string{"before", "after"} {
		t.Run(mode, func(t *testing.T) {
			dir, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "private", "ledger.sqlite")
			cmd := exec.Command(os.Args[0], "-test.run=^TestLedgerCrashHelper$")
			cmd.Env = append(os.Environ(), "ADA_LEDGER_TEST_MODE="+mode, "ADA_LEDGER_TEST_PATH="+path)
			out, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			in, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			defer in.Close()
			cmd.Stderr = os.Stderr
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { cmd.Process.Kill(); cmd.Wait() }()
			scanner := bufio.NewScanner(out)
			if !scanner.Scan() {
				t.Fatal("no store identity")
			}
			id := scanner.Text()
			fmt.Fprintln(in, "proceed")
			if !scanner.Scan() {
				t.Fatal("no crash boundary")
			}
			recordID := scanner.Text()
			if err = cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			cmd.Wait()
			s, err := Open(path, id, "host-lineage")
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			svc, _ := NewService(s, requestVerifier{}, &testPolicy{})
			record, err := svc.Get(humanContext("alice", time.Now().Add(time.Hour)), "workspace", "key")
			if mode == "before" {
				if !errors.Is(err, ErrNotFound) {
					t.Fatalf("intent advanced: %+v %v", record, err)
				}
			} else {
				if err != nil || record.ID != recordID || record.Outcome != "recorded" {
					t.Fatalf("lost durable decision: %+v %v", record, err)
				}
			}
		})
	}
}
func TestReopenRejectsTamperedRecordsAndProjections(t *testing.T) {
	for _, stmt := range []string{
		`UPDATE subjects SET snapshot='{}'`,
		`UPDATE subjects SET state='open'`,
		`UPDATE requests SET record='{}'`,
		`UPDATE requests SET issuer='another-person'`,
		`DELETE FROM requests`,
	} {
		t.Run(stmt, func(t *testing.T) {
			s, svc, _, r := serviceFixture(t)
			if _, err := svc.Decide(humanContext("alice", time.Now().Add(time.Hour)), r); err != nil {
				t.Fatal(err)
			}
			id, path := s.ID(), s.path
			s.Close()
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = db.Exec(stmt); err != nil {
				t.Fatal(err)
			}
			db.Close()
			if reopened, err := Open(path, id, "host-lineage"); !errors.Is(err, ErrUnavailable) {
				if reopened != nil {
					reopened.Close()
				}
				t.Fatalf("corrupt store reopened: %v", err)
			}
		})
	}
}
func TestSQLiteLockProbe(t *testing.T) {
	path := os.Getenv("ADA_LEDGER_LOCK_PROBE")
	if path == "" {
		return
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err = conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err == nil {
		conn.ExecContext(context.Background(), "ROLLBACK")
		t.Fatal("external writer entered a live SQLite transaction")
	}
}
func TestFailedSecondOpenPreservesSQLiteLocks(t *testing.T) {
	s := newTestStore(t)
	conn, err := s.db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err = conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	defer conn.ExecContext(context.Background(), "ROLLBACK")
	if _, err := Open(s.path, s.ID(), "host-lineage"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("second writer: %v", err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestSQLiteLockProbe$")
	cmd.Env = append(os.Environ(), "ADA_LEDGER_LOCK_PROBE="+s.path)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed Open dropped SQLite lock: %s %v", out, err)
	}
}

func TestPersistenceFailureRollsBackSubjectDecision(t *testing.T) {
	s, svc, _, r := serviceFixture(t)
	if _, err := s.db.Exec(`CREATE TRIGGER fail_insert BEFORE INSERT ON requests BEGIN SELECT RAISE(ABORT,'private storage diagnostic'); END`); err != nil {
		t.Fatal(err)
	}
	ctx := humanContext("alice", time.Now().Add(time.Hour))
	if _, err := svc.Decide(ctx, r); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("storage failure: %v", err)
	}
	if _, state, err := s.subject(context.Background(), r.Subject); err != nil || state != "open" {
		t.Fatalf("failure consumed subject: %s %v", state, err)
	}
	if _, err := s.lookup(context.Background(), ctx.Value(humanKey{}).(entraauth.VerifiedHuman).Caller.Identity, r.Workspace, r.Key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed insert persisted: %v", err)
	}
}

func TestReplacementConnectionsKeepDurability(t *testing.T) {
	s := newTestStore(t)
	s.db.SetMaxIdleConns(0)
	for range 2 {
		c, err := s.db.Conn(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range []struct{ query, want string }{{"PRAGMA foreign_keys", "1"}, {"PRAGMA synchronous", "3"}, {"PRAGMA journal_mode", "delete"}} {
			var got string
			if err = c.QueryRowContext(context.Background(), p.query).Scan(&got); err != nil || strings.ToLower(got) != p.want {
				t.Fatalf("%s=%s %v", p.query, got, err)
			}
		}
		c.Close()
	}
	if _, err := s.RegisterSubject(context.Background(), suiteSubject()); err != nil {
		t.Fatal(err)
	}
}
