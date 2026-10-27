package githubtools

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/agent-primitives/sessions/api"
)

func testApproval() Approval {
	return Approval{Call: Call{SessionUID: "session", ExecutionID: "execution", CallID: "call", Key: "key", CallSeq: 3, RequestSeq: 4, CallHash: strings.Repeat("b", 64), OperationDigest: strings.Repeat("c", 64), Requester: api.CallerIdentity{Issuer: "issuer", Subject: "requester"}, AppID: "1", InstallationID: "2", RepositoryID: "3"}, Approver: api.CallerIdentity{Issuer: "issuer", Subject: "approver"}, Approved: true, Reason: "reviewed exact comment"}
}
func prepared(t *testing.T, s *Store) Approval {
	t.Helper()
	a := testApproval()
	if err := s.PrepareApproval(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	return a
}
func committed(t *testing.T, s *Store) Approval {
	t.Helper()
	a := prepared(t, s)
	if err := s.CommitApproval(t.Context(), a.Call, a.Approver, 5); err != nil {
		t.Fatal(err)
	}
	return a
}

var success = Outcome{Status: "succeeded", CommentID: "42", URL: "https://github.com/example/repo/issues/1#issuecomment-42"}

// Catches a mismatch between input bounds and escaped JSON storage bounds.
func TestApprovalEscapedBoundsRoundtrip(t *testing.T) {
	s := testStore(t)
	a := testApproval()
	a.Reason = strings.Repeat("<", 2048)
	a.Call.SessionUID = strings.Repeat("<", 256)
	a.Call.ExecutionID = strings.Repeat(">", 256)
	a.Call.CallID = strings.Repeat("&", 256)
	if err := s.PrepareApproval(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	got, err := s.Approval(t.Context(), a.Call)
	if err != nil || got.Approval != a {
		t.Fatalf("escaped record read-back: %+v %v", got, err)
	}
	path, id := s.path, s.ID()
	s.Close()
	s, err = Open(path, id, "host-lineage", testBinding)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err = s.Approval(t.Context(), a.Call)
	if err != nil || got.Approval != a {
		t.Fatalf("escaped record reopen: %+v %v", got, err)
	}
}

// Catches approval attribution being overwritten on retries or host reconciliation.
func TestApprovalBindingAndReconciliation(t *testing.T) {
	s := testStore(t)
	a := prepared(t, s)
	before, err := s.Approval(t.Context(), a.Call)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.PrepareApproval(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	after, err := s.Approval(t.Context(), a.Call)
	if err != nil || before != after {
		t.Fatalf("retry changed evidence: %+v %v", after, err)
	}
	for _, mutate := range []func(*Approval){func(a *Approval) { a.Approver.Subject = "other" }, func(a *Approval) { a.Reason = "changed" }, func(a *Approval) { a.Approved = false }, func(a *Approval) { a.Call.InstallationID = "99" }, func(a *Approval) { a.Call.CallHash = strings.Repeat("d", 64) }, func(a *Approval) { a.Call.Key = "new-key" }, func(a *Approval) { a.Call.CallID = "new-call" }} {
		b := a
		mutate(&b)
		if err := s.PrepareApproval(t.Context(), b); !errors.Is(err, ErrConflict) {
			t.Fatalf("changed approval accepted: %+v %v", b, err)
		}
	}
	if _, _, err = s.Reserve(t.Context(), a.Call, 5); !errors.Is(err, ErrConflict) {
		t.Fatalf("pending released: %v", err)
	}
	other := a.Approver
	other.Subject = "other"
	if err = s.CommitApproval(t.Context(), a.Call, other, 5); !errors.Is(err, ErrConflict) {
		t.Fatalf("transferred attribution: %v", err)
	}
	if err = s.CommitApproval(t.Context(), a.Call, a.Approver, 4); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad sequence: %v", err)
	}
	// The trusted host can reconcile the native decision with the original
	// approver evidence; no new human approval is being manufactured here.
	if err = s.CommitApproval(t.Context(), a.Call, a.Approver, 5); err != nil {
		t.Fatal(err)
	}
	if err = s.CommitApproval(t.Context(), a.Call, a.Approver, 5); err != nil {
		t.Fatal(err)
	}
	if err = s.CommitApproval(t.Context(), a.Call, a.Approver, 6); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed decision sequence: %v", err)
	}
	stored, err := s.Approval(t.Context(), a.Call)
	if err != nil || stored.DecisionSeq != 5 || stored.Approver != a.Approver {
		t.Fatalf("lost native linkage: %+v %v", stored, err)
	}
	if err = s.AbandonApproval(t.Context(), a.Call, a.Approver, 6); !errors.Is(err, ErrConflict) {
		t.Fatalf("abandoned committed: %v", err)
	}
}

func TestApprovalAbandonmentRetainsEvidence(t *testing.T) {
	s := testStore(t)
	a := prepared(t, s)
	if err := s.AbandonApproval(t.Context(), a.Call, a.Approver, 3); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad head: %v", err)
	}
	if err := s.AbandonApproval(t.Context(), a.Call, a.Approver, 4); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Approval(t.Context(), a.Call); !errors.Is(err, ErrNotFound) {
		t.Fatalf("abandoned still active: %v", err)
	}
	b := a
	b.Call.InstallationID = "7"
	if err := s.PrepareApproval(t.Context(), b); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed archived call: %v", err)
	}
	b = a
	b.Approver.Subject = "replacement"
	if err := s.PrepareApproval(t.Context(), b); err != nil {
		t.Fatal(err)
	}
	if err := s.CommitApproval(t.Context(), b.Call, a.Approver, 5); !errors.Is(err, ErrConflict) {
		t.Fatalf("old approver claimed replacement: %v", err)
	}
	var raw string
	if err := s.db.QueryRow("SELECT record FROM approvals WHERE state='abandoned'").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var old ApprovalRecord
	if decode(raw, &old) != nil || old.Approval != a || old.AbandonedAt.IsZero() || old.AbandonedHead != 4 {
		t.Fatalf("lost abandonment audit: %+v", old)
	}
	if err := s.CommitApproval(t.Context(), b.Call, b.Approver, 5); err != nil {
		t.Fatal(err)
	}
	path, id := s.path, s.ID()
	s.Close()
	reopened, err := Open(path, id, "host-lineage", testBinding)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, err := reopened.Approval(t.Context(), b.Call)
	if err != nil || got.Approver != b.Approver {
		t.Fatalf("replacement lost: %+v %v", got, err)
	}
}

func TestApprovalValidationAndDenial(t *testing.T) {
	s := testStore(t)
	for _, mutate := range []func(*Approval){func(a *Approval) { a.Approver = a.Call.Requester }, func(a *Approval) { a.Call.CallHash = "invalid" }, func(a *Approval) { a.Call.RepositoryID = "03" }, func(a *Approval) { a.Call.RequestSeq = a.Call.CallSeq }, func(a *Approval) { a.Call.Key = "with space" }, func(a *Approval) { a.Reason = "bad\x00reason" }} {
		a := testApproval()
		mutate(&a)
		if err := s.PrepareApproval(t.Context(), a); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid accepted: %v", err)
		}
	}
	a := testApproval()
	a.Approved = false
	if err := s.PrepareApproval(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	if err := s.CommitApproval(t.Context(), a.Call, a.Approver, 5); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Reserve(t.Context(), a.Call, 5); !errors.Is(err, ErrConflict) {
		t.Fatalf("denial released: %v", err)
	}
}

// Removing the immediate transaction or returning created on retries allows two sends.
func TestIntentReservationSingleOwner(t *testing.T) {
	s := testStore(t)
	a := committed(t, s)
	var wg sync.WaitGroup
	results := make(chan bool, 12)
	for range 12 {
		wg.Go(func() {
			_, created, err := s.Reserve(t.Context(), a.Call, 5)
			if err != nil && !errors.Is(err, ErrUnknownOutcome) {
				t.Error(err)
			}
			results <- created
		})
	}
	wg.Wait()
	close(results)
	owners := 0
	for created := range results {
		if created {
			owners++
		}
	}
	if owners != 1 {
		t.Fatalf("send owners=%d", owners)
	}
	changed := a.Call
	changed.CallHash = strings.Repeat("d", 64)
	if _, _, err := s.Reserve(t.Context(), changed, 5); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed call: %v", err)
	}
	if _, _, err := s.Reserve(t.Context(), a.Call, 6); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed sequence: %v", err)
	}
	intent, err := s.Intent(t.Context(), a.Call)
	if err != nil || intent.Outcome != nil || intent.ApprovalID == "" || intent.ReservedAt.IsZero() {
		t.Fatalf("intent: %+v %v", intent, err)
	}
}

func TestUnknownHoldSurvivesRestartAndNewKeys(t *testing.T) {
	s := testStore(t)
	a := committed(t, s)
	if _, created, err := s.Reserve(t.Context(), a.Call, 5); err != nil || !created {
		t.Fatalf("initial: %v %v", created, err)
	}
	path, id := s.path, s.ID()
	s.Close()
	s, err := Open(path, id, "host-lineage", testBinding)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, created, err := s.Reserve(t.Context(), a.Call, 5); created || !errors.Is(err, ErrUnknownOutcome) {
		t.Fatalf("re-drive sent: %v %v", created, err)
	}
	for _, crossSession := range []bool{false, true} {
		b := a
		b.Call.Key = "another"
		b.Call.CallID = "another"
		b.Call.RequestSeq = 14
		b.Call.CallSeq = 13
		if crossSession {
			b.Call.SessionUID = "other-session"
		} else {
			b.Call.OperationDigest = strings.Repeat("e", 64)
		}
		if err := s.PrepareApproval(t.Context(), b); err != nil {
			t.Fatal(err)
		}
		if err := s.CommitApproval(t.Context(), b.Call, b.Approver, 15); err != nil {
			t.Fatal(err)
		}
		if _, created, err := s.Reserve(t.Context(), b.Call, 15); created || !errors.Is(err, ErrUnknownOutcome) {
			t.Fatalf("unknown bypass: %v %v", created, err)
		}
	}
}

func TestIntentTerminalResultIsImmutable(t *testing.T) {
	for _, outcome := range []Outcome{success, {Status: "failed", FailureCode: "provider_rejected"}, {Status: "unknown", FailureCode: "response_unknown"}} {
		t.Run(outcome.Status, func(t *testing.T) {
			s := testStore(t)
			a := committed(t, s)
			intent, _, err := s.Reserve(t.Context(), a.Call, 5)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Finish(t.Context(), a.Call, "wrong-owner", outcome); !errors.Is(err, ErrConflict) {
				t.Fatalf("wrong owner: %v", err)
			}
			if err := s.Finish(t.Context(), a.Call, intent.ReservationID, outcome); err != nil {
				t.Fatal(err)
			}
			if err := s.Finish(t.Context(), a.Call, intent.ReservationID, outcome); err != nil {
				t.Fatal(err)
			}
			changed := success
			if outcome == success {
				changed = Outcome{Status: "failed", FailureCode: "provider_rejected"}
			}
			if err := s.Finish(t.Context(), a.Call, intent.ReservationID, changed); !errors.Is(err, ErrConflict) {
				t.Fatalf("changed valid terminal result: %v", err)
			}
			unchanged, err := s.Intent(t.Context(), a.Call)
			if err != nil || unchanged.Outcome == nil || *unchanged.Outcome != outcome {
				t.Fatalf("terminal result overwritten: %+v %v", unchanged, err)
			}
			path, id := s.path, s.ID()
			s.Close()
			s, err = Open(path, id, "host-lineage", testBinding)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			cached, created, err := s.Reserve(t.Context(), a.Call, 5)
			if created || cached.Outcome == nil || *cached.Outcome != outcome {
				t.Fatalf("lost cached result: %+v %v %v", cached, created, err)
			}
			if outcome.Status == "unknown" {
				if !errors.Is(err, ErrUnknownOutcome) {
					t.Fatal(err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			got, err := s.Intent(t.Context(), a.Call)
			if err != nil || got.Outcome == nil || *got.Outcome != outcome {
				t.Fatalf("read-back: %+v %v", got, err)
			}
			if outcome.Status != "unknown" {
				// Identical text is legitimate new work after a known terminal outcome;
				// only unresolved outcomes create the cross-call operation hold.
				b := a
				b.Call.CallID = "new"
				b.Call.Key = "new"
				b.Call.RequestSeq = 14
				b.Call.CallSeq = 13
				if err := s.PrepareApproval(t.Context(), b); err != nil {
					t.Fatal(err)
				}
				if err := s.CommitApproval(t.Context(), b.Call, b.Approver, 15); err != nil {
					t.Fatal(err)
				}
				if _, created, err := s.Reserve(t.Context(), b.Call, 15); err != nil || !created {
					t.Fatalf("new legitimate operation: %v %v", created, err)
				}
			}
		})
	}
}

func TestFailedResultPersistenceLeavesUnknown(t *testing.T) {
	s := testStore(t)
	a := committed(t, s)
	intent, _, err := s.Reserve(t.Context(), a.Call, 5)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("CREATE TRIGGER refuse_update BEFORE UPDATE ON intents BEGIN SELECT RAISE(ABORT,'test failure'); END"); err != nil {
		t.Fatal(err)
	}
	if err := s.Finish(t.Context(), a.Call, intent.ReservationID, success); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("storage failure: %v", err)
	}
	if _, created, err := s.Reserve(t.Context(), a.Call, 5); created || !errors.Is(err, ErrUnknownOutcome) {
		t.Fatalf("failed persistence repost: %v %v", created, err)
	}
}

// Exercises abrupt process loss, not just a cooperative Close/reopen.
func TestIntentProcessCrash(t *testing.T) {
	if path := os.Getenv("GITHUB_CALL_CRASH_STORE"); path != "" {
		s, err := Initialize(path, "host-lineage", testBinding)
		if err != nil {
			t.Fatal(err)
		}
		a := committed(t, s)
		if _, created, err := s.Reserve(t.Context(), a.Call, 5); err != nil || !created {
			t.Fatalf("reserve: %v %v", created, err)
		}
		fmt.Println(s.ID()) // retained independently from the DB, like recovery config.
		os.Exit(27)
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "private", "github.db")
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestIntentProcessCrash$")
	cmd.Env = append(os.Environ(), "GITHUB_CALL_CRASH_STORE="+path)
	output, err := cmd.Output()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 27 {
		t.Fatalf("child did not reach crash cut: %v %s", err, output)
	}
	s, err := Open(path, strings.TrimSpace(string(output)), "host-lineage", testBinding)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, created, err := s.Reserve(t.Context(), testApproval().Call, 5); created || !errors.Is(err, ErrUnknownOutcome) {
		t.Fatalf("post-crash re-drive: %v %v", created, err)
	}
}

// Full-history binding checks must not scan unrelated retained approvals while
// holding the store's writer transaction. Partial active indexes cannot help.
func TestApprovalHistoryLookupAvoidsFullScan(t *testing.T) {
	s := testStore(t)
	a := prepared(t, s)
	rows, err := s.db.QueryContext(t.Context(), "EXPLAIN QUERY PLAN SELECT record FROM approvals WHERE slot=? OR (session_uid=? AND request_key=?)", a.Call.slot(), a.Call.SessionUID, a.Call.Key)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	searches := 0
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		t.Log(detail)
		if strings.Contains(detail, "SCAN approvals") {
			t.Error("full-history lookup scans unrelated retained approvals")
		}
		if strings.Contains(detail, "SEARCH approvals") {
			searches++
		}
	}
	if rows.Err() != nil || searches != 2 {
		t.Fatalf("expected indexed searches for both alternatives, got %d: %v", searches, rows.Err())
	}
}

func TestStoreRejectsInconsistentRecordProjection(t *testing.T) {
	s := testStore(t)
	a := committed(t, s)
	if _, _, err := s.Reserve(t.Context(), a.Call, 5); err != nil {
		t.Fatal(err)
	}
	path, id := s.path, s.ID()
	s.Close()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("UPDATE intents SET operation_digest=?", strings.Repeat("e", 64))
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, id, "host-lineage", testBinding); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("corrupt projection accepted: %v", err)
	}
}
