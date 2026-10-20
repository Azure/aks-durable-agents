package sessionfixture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Existing state is recovery, never permission to recreate lost dedup history.
func TestExecutorRecoveryRejectsEmptyOrTruncatedDatabase(t *testing.T) {
	for _, populated := range []bool{false, true} {
		t.Run(map[bool]string{false: "existing-empty", true: "truncated-publication"}[populated], func(t *testing.T) {
			dir := privateTempDir(t)
			path := filepath.Join(dir, "publications.db")
			if populated {
				ex, err := newExecutor(dir)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := ex.execute(t.Context(), toolScope("durable-session"), publication()); err != nil {
					ex.close()
					t.Fatal(err)
				}
				if err := ex.close(); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(path, nil, 0600); err != nil {
				t.Fatal(err)
			}
			ex, err := newExecutor(dir)
			if err == nil {
				ex.close()
				t.Fatal("existing empty database silently reinitialized")
			}
			if !strings.Contains(err.Error(), "reconcile") {
				t.Fatalf("missing recovery context: %v", err)
			}
			info, err := os.Stat(path)
			if err != nil || info.Size() != 0 {
				t.Fatalf("refused database was rewritten: %v %v", info, err)
			}
		})
	}
}

func TestExecutorRecoveryRejectsMissingSchemaWithoutRepair(t *testing.T) {
	for _, table := range []string{"publications", "receipts"} {
		t.Run(table, func(t *testing.T) {
			dir := privateTempDir(t)
			ex, err := newExecutor(dir)
			if err != nil {
				t.Fatal(err)
			}
			// Empty tables avoid a foreign-key failure in this corruption setup.
			if _, err := ex.db.Exec("DROP TABLE " + table); err != nil {
				ex.close()
				t.Fatal(err)
			}
			if err := ex.close(); err != nil {
				t.Fatal(err)
			}
			recovered, err := newExecutor(dir)
			if err == nil {
				recovered.close()
				t.Fatal("missing recovery table silently recreated")
			}
			if !strings.Contains(err.Error(), "reconcile") {
				t.Fatalf("missing recovery context: %v", err)
			}
			db, err := readOnlyDB(filepath.Join(dir, "publications.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var count int
			if err := db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&count); err != nil || count != 0 {
				t.Fatalf("refused recovery repaired table: count=%d err=%v", count, err)
			}
		})
	}
}

func TestExecutorRecoveryRejectsMissingColumns(t *testing.T) {
	dir := privateTempDir(t)
	ex, err := newExecutor(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ex.db.Exec("ALTER TABLE receipts DROP COLUMN output"); err != nil {
		ex.close()
		t.Fatal(err)
	}
	if err := ex.close(); err != nil {
		t.Fatal(err)
	}
	recovered, err := newExecutor(dir)
	if err == nil {
		recovered.close()
		t.Fatal("incomplete receipt schema accepted")
	}
	if !strings.Contains(err.Error(), "reconcile") {
		t.Fatalf("missing recovery context: %v", err)
	}
}
