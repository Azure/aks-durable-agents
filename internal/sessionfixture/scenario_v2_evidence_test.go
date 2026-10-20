package sessionfixture

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/agent-primitives/sessions/api"
	"github.com/agent-primitives/sessions/sqlitelog"
)

func createRealLedger(t *testing.T, data string) *sql.DB {
	t.Helper()
	path := filepath.Join(data, "real-attempts.db")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	for _, q := range []string{
		`CREATE TABLE model_budget(id INTEGER PRIMARY KEY CHECK(id=1),snapshot TEXT NOT NULL)`,
		`CREATE TABLE model_attempts(id INTEGER PRIMARY KEY,request_hash TEXT NOT NULL UNIQUE,started_at TEXT NOT NULL,finished_at TEXT,outcome TEXT NOT NULL,input_tokens INTEGER,output_tokens INTEGER,reasoning_tokens INTEGER)`,
		`INSERT INTO model_budget VALUES(1,'{"maxAttempts":2,"reservationUSD":"0.50"}')`,
		`INSERT INTO model_attempts VALUES(1,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','2026-10-18T00:00:00Z','2026-10-18T00:00:01Z','succeeded',120,80,10)`,
	} {
		if _, err = db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

// Break caught: evidence invents zero attempts, loses unknown usage, or writes the host ledger.
func TestV2EvidenceReadOnlyLedger(t *testing.T) {
	data := privateTempDir(t)
	if err := initDataScenario(data, filepath.Join(data, "publish.sock"), "v2"); err != nil {
		t.Fatal(err)
	}
	if _, err := readEvidenceScenario(data, "v2"); err == nil {
		t.Fatal("missing ledger accepted")
	}
	if _, err := os.Stat(filepath.Join(data, "real-attempts.db")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("read created ledger")
	}
	db := createRealLedger(t, data)
	if _, err := db.Exec(`INSERT INTO model_attempts VALUES(2,'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','2026-10-18T00:00:02Z',NULL,'unknown',NULL,NULL,NULL)`); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(data, "real-attempts.db")
	before, _ := fileDigest(path)
	ev, err := readEvidenceScenario(data, "v2")
	if err != nil {
		t.Fatal(err)
	}
	if ev.RealModelCalls == nil || *ev.RealModelCalls != 2 || len(ev.RealAttempts) != 2 || len(ev.RealLedgerDigest) != 64 {
		t.Fatalf("bad real evidence: %#v", ev)
	}
	if ev.RealLedgerDigest != "399e76b0e8621a51b4a60af54559482794a7a5e55af4eefc88175f538d1c2669" {
		t.Fatalf("wrong canonical digest: %s", ev.RealLedgerDigest)
	}
	if ev.RealAttempts[0].AttemptID != 1 || ev.RealAttempts[0].InputTokens == nil || *ev.RealAttempts[0].InputTokens != 120 || ev.RealAttempts[1].FinishedAt != nil || ev.RealAttempts[1].InputTokens != nil || ev.RealAttempts[1].Outcome != "unknown" {
		t.Fatalf("usage/outcomes lost: %#v", ev.RealAttempts)
	}
	var encoded bytes.Buffer
	if err := encodeEvidence(&encoded, ev, "v2"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(encoded.String(), `"fakeModelCalls":0`) {
		t.Fatal("v2 omits the separately measured fake counter")
	}
	again, err := readEvidenceScenario(data, "v2")
	if err != nil || !reflect.DeepEqual(ev, again) {
		t.Fatalf("unstable evidence: %v", err)
	}
	after, _ := fileDigest(path)
	if before != after {
		t.Fatal("read mutated ledger")
	}
	if _, err := db.Exec(`UPDATE model_attempts SET request_hash='cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	changed, err := readEvidenceScenario(data, "v2")
	if err != nil || changed.RealLedgerDigest == ev.RealLedgerDigest {
		t.Fatal("digest omits request hash")
	}
	if _, err := db.Exec(`UPDATE model_budget SET snapshot='{"maxAttempts":2,"reservationUSD":"0.60"}'`); err != nil {
		t.Fatal(err)
	}
	budgetChanged, err := readEvidenceScenario(data, "v2")
	if err != nil || changed.RealLedgerDigest == budgetChanged.RealLedgerDigest {
		t.Fatal("digest omits budget")
	}
	if _, err := db.Exec(`INSERT INTO model_attempts VALUES(3,'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd','2026-10-18T00:00:03Z',NULL,'reserved',NULL,NULL,NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := readEvidenceScenario(data, "v2"); err == nil {
		t.Fatal("third attempt accepted")
	}
}

func TestV2BaselineWireEvidenceKeepsEmptyAttemptsAndMeasuredFakeCount(t *testing.T) {
	data := privateTempDir(t)
	if err := initDataScenario(data, filepath.Join(data, "publish.sock"), "v2"); err != nil {
		t.Fatal(err)
	}
	db := createRealLedger(t, data)
	if _, err := db.Exec(`DELETE FROM model_attempts`); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "fake-calls.jsonl"), []byte(`{"provider":"deterministic-local-fake","requestDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runCLI(t.Context(), []string{"evidence", "--scenario", "v2", "--data", data}, &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(out.Bytes(), &wire); err != nil {
		t.Fatal(err)
	}
	if wire["fakeModelCalls"] != float64(1) || wire["realModelCalls"] != float64(0) {
		t.Fatalf("independent counters missing: %s", &out)
	}
	if attempts, ok := wire["realAttempts"].([]any); !ok || len(attempts) != 0 {
		t.Fatalf("empty attempts must remain []: %s", &out)
	}
}

func TestV2EvidenceRefusesCorruption(t *testing.T) {
	for _, query := range []string{`DROP TABLE model_attempts`, `DELETE FROM model_budget`, `UPDATE model_attempts SET outcome='invented'`, `UPDATE model_attempts SET input_tokens=-1`, `UPDATE model_attempts SET started_at='not a time'`, `UPDATE model_attempts SET input_tokens=NULL`, `UPDATE model_attempts SET output_tokens=4097`, `UPDATE model_attempts SET reasoning_tokens=81`, `UPDATE model_attempts SET finished_at=NULL`, `UPDATE model_attempts SET id=3`} {
		t.Run(query, func(t *testing.T) {
			data := privateTempDir(t)
			if err := initDataScenario(data, filepath.Join(data, "publish.sock"), "v2"); err != nil {
				t.Fatal(err)
			}
			db := createRealLedger(t, data)
			if _, err := db.Exec(query); err != nil {
				t.Fatal(err)
			}
			if _, err := readEvidenceScenario(data, "v2"); err == nil {
				t.Fatal("corrupt ledger accepted")
			}
		})
	}
}

// Break caught: arbitrary v2 model wording is replaced, replay dispatches effects, or ledger changes.
func TestV2ArbitraryDraftActualJournalReplay(t *testing.T) {
	data := privateTempDir(t)
	if err := initDataScenario(data, filepath.Join(data, "publish.sock"), "v2"); err != nil {
		t.Fatal(err)
	}
	createRealLedger(t, data)
	ex, err := openExecutorScenario(filepath.Join(data, "publications.db"), "v2")
	if err != nil {
		t.Fatal(err)
	}
	defer ex.close()
	store, err := sqlitelog.Open(filepath.Join(data, "journal.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	log := store.Session("v2-session")
	h := newHarnessScenario("v2")
	draft := validV2Draft + "An editor can choose a completely different ending.\n"
	calls := 0
	model := func(_ context.Context, req api.ModelRequest) (api.ModelResponse, error) {
		calls++
		if len(req.Messages) != 2 || !strings.Contains(req.Messages[0].Text(), "Northwind Lantern v2.4") {
			t.Fatalf("not real instructions: %#v", req)
		}
		return api.ModelResponse{Message: *api.TextMessage("assistant", draft)}, nil
	}
	c := controllerFor(t, log, "v2-session", model, ex.execute)
	if err = c.Exec(t.Context(), h, []api.Message{*api.TextMessage("user", "Draft a clear fictional release announcement, not a frozen variant.")}, 0); !errors.Is(err, api.ErrApprovalParked) {
		t.Fatal(err)
	}
	if p, r, err := ex.counts(); err != nil || p != 0 || r != 0 {
		t.Fatal("published before approval")
	}
	decide(t, c, log, true)
	c = controllerFor(t, log, "v2-session", model, ex.execute)
	if _, err = c.Resume(t.Context(), h); err != nil {
		t.Fatal(err)
	}
	before, err := readEvidenceScenario(data, "v2")
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err = runCLI(t.Context(), []string{"verify-replay", "--scenario", "v2", "--journal", filepath.Join(data, "journal.db"), "--instructions", filepath.Join(data, "instructions.txt"), "--session", "v2-session"}, &out, io.Discard)
	var proof replayProof
	if e := json.Unmarshal(out.Bytes(), &proof); e != nil {
		t.Fatalf("%s: %v", out.String(), e)
	}
	if err != nil || !proof.Completed || proof.ProviderCalls != 0 || proof.ExecutorCalls != 0 || calls != 1 {
		t.Fatalf("replay: %s %v calls=%d", out.String(), err, calls)
	}
	after, err := readEvidenceScenario(data, "v2")
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("replay changed evidence")
	}
	rows, err := ex.inventory()
	if err != nil || len(rows) != 1 || !bytes.Contains(rows[0].Raw, []byte("completely different ending")) {
		t.Fatal("arbitrary draft not stored")
	}
	if _, err = verifyJournal(t.Context(), filepath.Join(data, "journal.db"), filepath.Join(data, "instructions.txt"), "v2-session"); err == nil {
		t.Fatal("v1 replay accepted v2")
	}
}
