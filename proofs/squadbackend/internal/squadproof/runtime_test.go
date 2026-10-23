//go:build squadproof

package squadproof

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/agent-primitives/sessions/api"
	v1 "github.com/agent-primitives/sessions/api/genpb"
	"github.com/agent-primitives/sessions/client"
)

// Explicit SDK actions exercise fixtures, not an automatic broker or crash test.
func TestRuntimeNativeDenialAndCompletedReplay(t *testing.T) {
	l, path := openTestLedger(t)
	c, _ := startProofHost(t, l, filepath.Dir(path))
	ctx := t.Context()
	input := `{"kind":"start"}`
	if _, err := l.Admit(ctx, Operation{ID: "lead", Kind: "lead", Team: "proof-team", PackageDigest: proofDigest(), Member: "lead", Epoch: 1, Payload: []byte(input)}); err != nil {
		t.Fatal(err)
	}
	lead, err := c.CreateSession(ctx, &v1.Session{Harness: "proof-lead"})
	if err != nil {
		t.Fatal(err)
	}
	uid := lead.GetMetadata().GetUid()
	if err = l.BindSession(ctx, "lead", uid); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Exec(ctx, client.ExecOptions{Session: uid, Inputs: []string{input}}); err != nil {
		t.Fatal(err)
	}
	lead, err = c.GetSession(ctx, uid)
	if err != nil || lead.GetPendingApproval() == nil {
		t.Fatalf("lead did not park at checkpoint: %+v %v", lead, err)
	}
	request := lead.GetPendingApproval()
	if !strings.HasSuffix(request.GetToolCallId(), "/checkpoint") {
		t.Fatalf("unexpected approval: %+v", request)
	}
	var childID string
	if err = l.db.QueryRowContext(ctx, `SELECT id FROM operations WHERE parent='lead'`).Scan(&childID); err != nil {
		t.Fatalf("dispatch did not return a child handle: %v", err)
	}
	child, err := l.Operation(ctx, childID)
	if err != nil || child.SessionUID != "" || child.State != "admitted" {
		t.Fatalf("child allocated before explicit caller action: %+v %v", child, err)
	}
	if n, err := l.attemptCount(ctx, "executor"); err != nil || n != 1 {
		t.Fatalf("only dispatch may enter executor before decision: %d %v", n, err)
	}
	records, err := c.Replay(ctx, uid, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := VerifyReplay(ctx, uid, records, NewHarness("lead", proofDigest()))
	if !errors.Is(err, ErrHeld) || proof.Models != 0 || proof.Tools != 0 {
		t.Fatalf("unfinished journal must be refused without callbacks: %+v %v", proof, err)
	}
	decision, err := c.Approve(ctx, uid, api.ApprovalDecision{ExecutionID: request.GetExecutionId(), ToolCallID: request.GetToolCallId(), RequestSeq: request.GetRequestSeq(), Approved: false, Reason: "synthetic denial"})
	if err != nil || decision.GetDecision() == nil {
		t.Fatalf("denial did not create a decision: %+v %v", decision, err)
	}
	lead, err = c.GetSession(ctx, uid)
	if err != nil {
		t.Fatal(err)
	}
	head := lead.GetLastSeq()
	if _, err = c.Sessions().Resume(ctx, &v1.ResumeRequest{Session: uid, ExpectedLastSeq: &head}); err != nil {
		t.Fatal(err)
	}
	if n, err := l.attemptCount(ctx, "executor"); err != nil || n != 1 {
		t.Fatalf("denied checkpoint entered executor: %d %v", n, err)
	}
	var deniedResults int
	if err = l.db.QueryRowContext(ctx, `SELECT count(*) FROM tool_results WHERE uid=? AND key=?`, uid, request.GetToolCallId()).Scan(&deniedResults); err != nil || deniedResults != 0 {
		t.Fatalf("denied tool committed an executor receipt: %d %v", deniedResults, err)
	}
	stats, err := l.Counts(ctx)
	if err != nil || stats.Operations != 2 || stats.ToolResults != 1 || stats.Effects != 0 {
		t.Fatalf("denial changed effects/dispatch: %+v %v", stats, err)
	}
	checkReplay := func(executions int) {
		t.Helper()
		records, err := c.Replay(ctx, uid, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		models, err := l.attemptCount(ctx, "model")
		if err != nil {
			t.Fatal(err)
		}
		proof, err := VerifyReplay(ctx, uid, records, NewHarness("lead", proofDigest()))
		if err != nil || proof.Models != 0 || proof.Tools != 0 || len(proof.Executions) != executions || !reflect.DeepEqual(proof.Executions, proof.Covered) {
			t.Fatalf("completed invocation coverage: %+v %v", proof, err)
		}
		if executions == 2 && proof.Executions[0] == proof.Executions[1] {
			t.Fatal("second input did not create a distinct execution")
		}
		changed, err := VerifyReplay(ctx, uid, records, NewHarness("lead", strings.Repeat("b", 64)))
		if err == nil || changed.Models != 0 || changed.Tools != 0 {
			t.Fatalf("changed package must fail without callbacks: %+v %v", changed, err)
		}
		if n, err := l.attemptCount(ctx, "model"); err != nil || n != models {
			t.Fatalf("replay reached model provider: %d, was %d: %v", n, models, err)
		}
		if n, err := l.attemptCount(ctx, "executor"); err != nil || n != 1 {
			t.Fatalf("replay entered executor: %d %v", n, err)
		}
	}
	checkReplay(1)
	// This is a caller's manual next input, not broker delivery or queue recovery.
	if _, err = c.Exec(ctx, client.ExecOptions{Session: uid, Inputs: []string{`{"kind":"followup","text":"new input"}`}}); err != nil {
		t.Fatal(err)
	}
	checkReplay(2)
}

// Dropping persistent attempt accounting would reset the cap on a new handle.
func TestRuntimeFakeCapSurvivesAdditionalHandleAndReopen(t *testing.T) {
	l, path := openTestLedger(t)
	send := func(ledger *Ledger, first, last int) {
		t.Helper()
		for i := first; i <= last; i++ {
			w := httptest.NewRecorder()
			(&fakeModel{ledger: ledger}).ServeHTTP(w, fakeRequest(t, "lead", "finish", false))
			want := 200
			if i == 17 {
				want = 400
			}
			if w.Code != want {
				t.Fatalf("attempt %d status=%d want=%d: %s", i, w.Code, want, w.Body.String())
			}
		}
	}
	send(l, 1, 8)
	other, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.Close() })
	send(other, 9, 16)
	if n, err := l.attemptCount(t.Context(), "model"); err != nil || n != 16 {
		t.Fatalf("additional handle lost durable count: %d %v", n, err)
	}
	if err = other.Close(); err != nil {
		t.Fatal(err)
	}
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	send(reopened, 17, 17)
	if n, err := reopened.attemptCount(t.Context(), "model"); err != nil || n != 17 {
		t.Fatalf("refused attempt not durably counted: %d %v", n, err)
	}
}

// A preexisting unmarked SQLite journal must not be adopted or modified.
func TestRuntimeHostRefusesUnmarkedForeignJournal(t *testing.T) {
	_, path := openTestLedger(t)
	data := filepath.Dir(path)
	journal := filepath.Join(data, "journal.db")
	if err := os.WriteFile(journal, nil, 0600); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", journal)
	if err != nil {
		t.Fatal(err)
	}
	_, seedErr := db.Exec(`CREATE TABLE foreign_data(value TEXT); INSERT INTO foreign_data VALUES('retain me')`)
	closeErr := db.Close()
	if seedErr != nil || closeErr != nil {
		t.Fatalf("foreign fixture: %v %v", seedErr, closeErr)
	}
	before, err := os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := HostConfig([]string{"--proof-only", "--data=" + data, "--addr=127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ready := false
	err = RunHost(ctx, cfg, func(string) { ready = true; cancel() })
	if !errors.Is(err, ErrForeign) || ready {
		t.Fatalf("host adopted unmarked journal: ready=%v err=%v", ready, err)
	}
	after, err := os.ReadFile(journal)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("foreign journal modified: %v", err)
	}
}
