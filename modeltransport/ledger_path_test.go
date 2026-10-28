package modeltransport

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLedgerLiteralFilename(t *testing.T) {
	for _, name := range []string{"plain.sqlite", "literal?mode=memory", "literal#hash%25.sqlite", "literal?x=1&_pragma=journal_mode(MEMORY)", "世界.sqlite"} {
		t.Run(name, func(t *testing.T) {
			c := runConfig(t, 1)
			c.LedgerPath = filepath.Join(filepath.Dir(c.LedgerPath), name)
			p, err := OpenRunPolicy(c)
			if err != nil {
				t.Fatalf("OpenRunPolicy: %v", err)
			}
			if err := p.Close(); err != nil {
				t.Fatal(err)
			}
			st, err := os.Stat(c.LedgerPath)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("literal ledger bytes=%d", st.Size())
			if st.Size() == 0 {
				t.Error("declared literal ledger is empty: no durable SQLite budget at checked path")
			}
			p, err = OpenRunPolicy(c)
			if err != nil {
				t.Errorf("reopen exact frozen policy: %v", err)
			} else {
				_ = p.Close()
			}
		})
	}
}

func TestLedgerRawFilenameCompatibility(t *testing.T) {
	for version := 1; version <= 4; version++ {
		for _, name := range []string{"plain.sqlite", "hash#percent%25.sqlite"} {
			t.Run(fmt.Sprintf("v%d/%s", version, name), func(t *testing.T) {
				c := runConfig(t, 1)
				path := filepath.Join(filepath.Dir(c.LedgerPath), name)
				f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
				if e != nil {
					t.Fatal(e)
				}
				if e = f.Close(); e != nil {
					t.Fatal(e)
				}
				db, e := sql.Open("sqlite", path)
				if e != nil {
					t.Fatal(e)
				}
				schema := `CREATE TABLE model_attempts(id INTEGER PRIMARY KEY,request_hash TEXT NOT NULL UNIQUE,started_at TEXT NOT NULL,finished_at TEXT,outcome TEXT NOT NULL,input_tokens INTEGER,output_tokens INTEGER,reasoning_tokens INTEGER)`
				var slots []string
				if version >= 3 {
					schema = plannedAttemptsSchema
					slots = []string{"slot-a", "slot-b", "slot-c"}
				}
				snapshot := fmt.Sprintf("unchanged-v%d", version)
				for _, q := range []string{budgetSchema, schema} {
					if _, e = db.Exec(q); e != nil {
						t.Fatal(e)
					}
				}
				if _, e = db.Exec("INSERT INTO model_budget VALUES(1,?)", snapshot); e != nil {
					t.Fatal(e)
				}
				columns := "request_hash,started_at,outcome"
				values := "'" + strings.Repeat("a", 64) + "','then','succeeded'"
				if version >= 3 {
					columns += ",call_slot"
					values += ",'slot-a'"
				}
				if _, e = db.Exec("INSERT INTO model_attempts(" + columns + ") VALUES(" + values + ")"); e != nil {
					t.Fatal(e)
				}
				if e = db.Close(); e != nil {
					t.Fatal(e)
				}
				before, e := os.ReadFile(path)
				if e != nil {
					t.Fatal(e)
				}
				l, e := openBudgetLedger(path, snapshot, 3, 8192, slots)
				if e != nil {
					t.Fatal(e)
				}
				var count int
				if e = l.db.QueryRow("SELECT count(*) FROM model_attempts WHERE outcome='succeeded'").Scan(&count); e != nil || count != 1 {
					t.Fatalf("reservation lost: %d %v", count, e)
				}
				if e = l.db.Close(); e != nil {
					t.Fatal(e)
				}
				after, e := os.ReadFile(path)
				if e != nil || string(before) != string(after) {
					t.Fatal("rewrote legacy bytes")
				}
			})
		}
	}
}

func TestLedgerLiteralSidecarAndOldEmptyRefusal(t *testing.T) {
	c := runConfig(t, 1)
	c.LedgerPath = filepath.Join(filepath.Dir(c.LedgerPath), "literal?mode=memory")
	sidecar := c.LedgerPath + "-journal"
	if e := os.WriteFile(sidecar, []byte("untouched"), 0644); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(sidecar, 0644); e != nil {
		t.Fatal(e)
	}
	if p, e := OpenRunPolicy(c); e == nil {
		p.Close()
		t.Fatal("ignored literal sidecar guard")
	}
	if b, e := os.ReadFile(sidecar); e != nil || string(b) != "untouched" {
		t.Fatal("mutated sidecar")
	}
	if e := os.Remove(sidecar); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(c.LedgerPath, nil, 0600); e != nil {
		t.Fatal(e)
	}
	if p, e := OpenRunPolicy(c); e == nil {
		p.Close()
		t.Fatal("adopted old empty ledger")
	}
}
