package modeltransport

import (
	"bytes"
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

const slotDeclaration = `"plannedCallSlots":["case/1:repeat/1","case/1:repeat/2","case/1:judge/1"],`

func plannedPolicyConfig(t *testing.T) (string, string) {
	t.Helper()
	path, ledger := v2PolicyConfig(t)
	replacePolicy(t, path, `"version":2,`, `"version":3,`+slotDeclaration)
	return path, ledger
}
func replacePolicy(t *testing.T, path, from, to string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), from) {
		t.Fatalf("missing policy fixture fragment %q", from)
	}
	if err = os.WriteFile(path, []byte(strings.Replace(string(data), from, to, 1)), 0600); err != nil {
		t.Fatal(err)
	}
}
func openPlannedPolicy(t *testing.T, path string) *Policy {
	t.Helper()
	p, err := OpenPolicyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}
func slotClient(t *testing.T, p *Policy, slot string, s *httptest.Server) *http.Client {
	t.Helper()
	c, err := NewClient(Config{Endpoint: s.URL + "/openai/v1/", Deployment: "test-deployment", Credential: goodCredential(), Transport: s.Client().Transport.(*http.Transport), Policy: p, CallSlot: slot})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.CloseIdleConnections)
	return c
}

// A loose version/slot check would accept undeclared calls or silently downgrade a legacy policy.
func TestPlannedSlotsPolicyContract(t *testing.T) {
	for _, tc := range []struct {
		name, from, to string
		ok             bool
	}{
		{"valid", slotDeclaration, slotDeclaration, true},
		{"missing", slotDeclaration, "", false},
		{"empty", slotDeclaration, `"plannedCallSlots":[],`, false},
		{"two", slotDeclaration, `"plannedCallSlots":["a","b"],`, false},
		{"four", slotDeclaration, `"plannedCallSlots":["a","b","c","d"],`, false},
		{"duplicate", slotDeclaration, `"plannedCallSlots":["a","a","c"],`, false},
		{"null", slotDeclaration, `"plannedCallSlots":null,`, false},
		{"empty-id", "case/1:repeat/1", "", false},
		{"spaces", "case/1:repeat/1", " a", false},
		{"non-ascii", "case/1:repeat/1", "é", false},
		{"oversize", "case/1:repeat/1", strings.Repeat("a", 129), false},
		{"max-id", "case/1:repeat/1", strings.Repeat("a", 128), true},
		{"missing-count", `"maxAttempts":3,`, "", false},
		{"wrong-count", `"maxAttempts":3`, `"maxAttempts":2`, false},
		{"v2", `"version":3`, `"version":2`, false},
		{"v2-empty", `"version":3,` + slotDeclaration, `"version":2,"plannedCallSlots":[],`, false},
		{"v1-empty", `"version":3,` + slotDeclaration + `"maxAttempts":3,`, `"version":1,"plannedCallSlots":[],`, false},
		{"cost-bound", `500000`, `200000000`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, _ := plannedPolicyConfig(t)
			replacePolicy(t, path, tc.from, tc.to)
			p, err := OpenPolicyFile(path)
			if p != nil {
				defer p.Close()
				if p.AttemptLimit() != 3 {
					t.Fatal("attempt ceiling changed")
				}
			}
			if tc.ok != (err == nil) {
				t.Fatalf("accepted=%t err=%v", tc.ok, err)
			}
		})
	}
}

// Slot selection belongs to trusted transport construction, never the request body or a header.
func TestPlannedSlotsSelector(t *testing.T) {
	path, _ := plannedPolicyConfig(t)
	p := openPlannedPolicy(t, path)
	legacy, _, _ := openTestPolicy(t)
	for _, tc := range []struct {
		name string
		p    *Policy
		slot string
		ok   bool
	}{
		{"member", p, "case/1:repeat/1", true}, {"missing", p, "", false}, {"unknown", p, "other", false},
		{"legacy", legacy, "case/1:repeat/1", false}, {"nil", nil, "case/1:repeat/1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewClient(Config{Endpoint: "https://example.invalid/openai/v1/", Deployment: "test-deployment", Credential: goodCredential(), Policy: tc.p, CallSlot: tc.slot})
			if c != nil {
				c.CloseIdleConnections()
			}
			if tc.ok != (err == nil) {
				t.Fatalf("accepted=%t err=%v", tc.ok, err)
			}
		})
	}
}

// Removing slot uniqueness permits re-spend; retaining body uniqueness blocks legitimate repetitions.
func TestPlannedSlotsEqualBodiesAndRestart(t *testing.T) {
	path, ledger := plannedPolicyConfig(t)
	var bodies []string
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(data))
		io.WriteString(w, usageResponse)
	}))
	defer s.Close()
	target := s.URL + "/openai/v1/chat/completions"
	p := openPlannedPolicy(t, path)
	first := slotClient(t, p, "case/1:repeat/1", s)
	if err := boundedSend(first, target, chat("same", false)); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{chat("same", false), chat("changed", false)} {
		if err := boundedSend(first, target, body); err == nil {
			t.Fatal("reused slot dispatched")
		}
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	p = openPlannedPolicy(t, path)
	if err := boundedSend(slotClient(t, p, "case/1:repeat/1", s), target, chat("same", false)); err == nil {
		t.Fatal("restart replenished slot")
	}
	for _, slot := range []string{"case/1:repeat/2", "case/1:judge/1"} {
		if err := boundedSend(slotClient(t, p, slot, s), target, chat("same", false)); err != nil {
			t.Fatal(err)
		}
	}
	if len(bodies) != 3 || bodies[0] != bodies[1] || bodies[1] != bodies[2] {
		t.Fatalf("bodies changed or incorrect sends: %v", bodies)
	}
	db, err := sql.Open("sqlite", ledger)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var slots, hashes, n int
	if err = db.QueryRow("SELECT count(*),count(DISTINCT call_slot),count(DISTINCT request_hash) FROM model_attempts").Scan(&n, &slots, &hashes); err != nil {
		t.Fatal(err)
	}
	if n != 3 || slots != 3 || hashes != 1 {
		t.Fatalf("attribution: %d %d %d", n, slots, hashes)
	}
}

// Independent SQLite connections must serialize before credentials/dispatch, not just within Policy.mu.
func TestPlannedSlotsConcurrentPolicies(t *testing.T) {
	path, _ := plannedPolicyConfig(t)
	p, q := openPlannedPolicy(t, path), openPlannedPolicy(t, path)
	var sends atomic.Int32
	entered, release := make(chan struct{}), make(chan struct{})
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if sends.Add(1) == 1 {
			close(entered)
		}
		<-release
		io.WriteString(w, usageResponse)
	}))
	defer s.Close()
	a, b := slotClient(t, p, "case/1:repeat/1", s), slotClient(t, q, "case/1:repeat/1", s)
	var wg sync.WaitGroup
	done := make(chan error, 1)
	wg.Go(func() { done <- boundedSend(a, s.URL+"/openai/v1/chat/completions", chat("same", false)) })
	<-entered
	err := boundedSend(b, s.URL+"/openai/v1/chat/completions", chat("changed", false))
	close(release)
	wg.Wait()
	if err == nil {
		t.Fatal("concurrent slot reused")
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if sends.Load() != 1 {
		t.Fatal("duplicate send")
	}
	if err = boundedSend(b, s.URL+"/openai/v1/chat/completions", chat("same", false)); err == nil {
		t.Fatal("completed concurrent slot reused")
	}
}

func TestPlannedSlotsUnknownStopsRun(t *testing.T) {
	path, _ := plannedPolicyConfig(t)
	p := openPlannedPolicy(t, path)
	var sends atomic.Int32
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { sends.Add(1); io.WriteString(w, `{"choices":[]}`) }))
	defer s.Close()
	target := s.URL + "/openai/v1/chat/completions"
	if err := boundedSend(slotClient(t, p, "case/1:repeat/1", s), target, chat("same", false)); err == nil {
		t.Fatal("unknown accepted")
	}
	p.Close()
	p = openPlannedPolicy(t, path)
	if err := boundedSend(slotClient(t, p, "case/1:repeat/2", s), target, chat("same", false)); err == nil {
		t.Fatal("unknown bypassed")
	}
	if sends.Load() != 1 {
		t.Fatal("resent after uncertainty")
	}
}

// An empty ledger is still bound: switching profile/slot inventory must never be a migration or reset.
func TestPlannedSlotsNoMigration(t *testing.T) {
	for _, mode := range []string{"v2-to-v3", "v3-to-v2", "changed-plan"} {
		t.Run(mode, func(t *testing.T) {
			var path, ledger string
			if mode == "v2-to-v3" {
				path, ledger = v2PolicyConfig(t)
			} else {
				path, ledger = plannedPolicyConfig(t)
			}
			p, err := OpenPolicyFile(path)
			if err != nil {
				t.Fatal(err)
			}
			p.Close()
			before, err := os.ReadFile(ledger)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "v2-to-v3":
				replacePolicy(t, path, `"version":2,`, `"version":3,`+slotDeclaration)
			case "v3-to-v2":
				replacePolicy(t, path, `"version":3,`+slotDeclaration, `"version":2,`)
			case "changed-plan":
				replacePolicy(t, path, "case/1:repeat/1", "different")
			}
			p, err = OpenPolicyFile(path)
			if p != nil {
				p.Close()
			}
			if err == nil {
				t.Fatal("adopted changed ledger")
			}
			after, err := os.ReadFile(ledger)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("refusal changed ledger")
			}
		})
	}
}

// SQLite TEXT affinity does not coerce BLOBs; Go string scanning must not hide that difference.
func TestPlannedSlotsRejectBlobIdentity(t *testing.T) {
	for _, column := range []string{"call_slot", "request_hash"} {
		t.Run(column, func(t *testing.T) {
			path, ledger := plannedPolicyConfig(t)
			p := openPlannedPolicy(t, path)
			var sends atomic.Int32
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				sends.Add(1)
				io.WriteString(w, usageResponse)
			}))
			defer s.Close()
			target := s.URL + "/openai/v1/chat/completions"
			if err := boundedSend(slotClient(t, p, "case/1:repeat/1", s), target, chat("same", false)); err != nil {
				t.Fatal(err)
			}
			p.Close()
			db, err := sql.Open("sqlite", ledger)
			if err != nil {
				t.Fatal(err)
			}
			// Column names are the fixed test table above, never external input.
			if _, err = db.Exec("UPDATE model_attempts SET " + column + "=CAST(" + column + " AS BLOB)"); err != nil {
				t.Fatal(err)
			}
			db.Close()
			p, err = OpenPolicyFile(path)
			if err == nil {
				defer p.Close()
				reuseErr := boundedSend(slotClient(t, p, "case/1:repeat/1", s), target, chat("same", false))
				t.Fatalf("BLOB identity accepted; reuse error=%v sends=%d", reuseErr, sends.Load())
			}
			if sends.Load() != 1 {
				t.Fatal("altered identity dispatched")
			}
		})
	}
}

func TestPlannedSlotsRefuseAlteredState(t *testing.T) {
	for _, stmt := range []string{
		`CREATE INDEX extra ON model_attempts(request_hash)`,
		`CREATE TRIGGER extra AFTER INSERT ON model_attempts BEGIN SELECT 1; END`,
		`CREATE VIEW extra AS SELECT * FROM model_attempts`,
		`DROP TABLE model_attempts; CREATE TABLE model_attempts(id INTEGER PRIMARY KEY,call_slot TEXT NOT NULL,request_hash TEXT NOT NULL,started_at TEXT NOT NULL,finished_at TEXT,outcome TEXT NOT NULL,input_tokens INTEGER,output_tokens INTEGER,reasoning_tokens INTEGER)`,
		`INSERT INTO model_attempts(call_slot,request_hash,started_at,outcome) VALUES('unknown','` + strings.Repeat("a", 64) + `','time','reserved')`,
		`INSERT INTO model_attempts(call_slot,request_hash,started_at,outcome) VALUES('case/1:repeat/1','invalid','time','reserved')`,
	} {
		t.Run(stmt, func(t *testing.T) {
			path, ledger := plannedPolicyConfig(t)
			p := openPlannedPolicy(t, path)
			p.Close()
			db, err := sql.Open("sqlite", ledger)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = db.Exec(stmt); err != nil {
				t.Fatal(err)
			}
			db.Close()
			p, err = OpenPolicyFile(path)
			if p != nil {
				p.Close()
			}
			if err == nil {
				t.Fatal("altered state accepted")
			}
		})
	}
}
