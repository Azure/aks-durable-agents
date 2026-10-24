package qualification

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type recoveryFile struct {
	Mode os.FileMode
	Data string
}

func recoverySnapshot(t *testing.T, root string) map[string]recoveryFile {
	t.Helper()
	snapshot := map[string]recoveryFile{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		entry := recoveryFile{Mode: info.Mode()}
		if info.Mode().IsRegular() {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			entry.Data = string(data)
		}
		snapshot[rel] = entry
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}
func TestOpenWALPreservesRecoverySet(t *testing.T) {
	for _, foreign := range []bool{true, false} {
		name := "matching-lineage"
		if foreign {
			name = "foreign-lineage"
		}
		t.Run(name, func(t *testing.T) {
			s, dir := testStore(t)
			lineage := s.Lineage()
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			db, err := sql.Open("sqlite", dbURI(filepath.Join(dir, "records.db"), false))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			db.SetMaxOpenConns(1)
			var mode string
			if err = db.QueryRow("PRAGMA journal_mode=WAL").Scan(&mode); err != nil || mode != "wal" {
				t.Fatalf("WAL setup: %s %v", mode, err)
			}
			if foreign {
				if _, err = db.Exec("UPDATE metadata SET lineage='foreign'"); err != nil {
					t.Fatal(err)
				}
			}
			if err = db.Close(); err != nil {
				t.Fatal(err)
			}
			for _, suffix := range []string{"-wal", "-shm"} {
				if _, err = os.Stat(filepath.Join(dir, "records.db") + suffix); !os.IsNotExist(err) {
					t.Fatalf("closed WAL fixture has sidecar %s: %v", suffix, err)
				}
			}
			before := recoverySnapshot(t, dir)
			opened, err := Open(dir, lineage)
			if opened != nil {
				opened.Close()
			}
			if !errors.Is(err, ErrIntegrity) {
				t.Fatalf("WAL store accepted: %v", err)
			}
			after := recoverySnapshot(t, dir)
			if !reflect.DeepEqual(before, after) {
				t.Fatal("Open changed rejected WAL recovery set (names, modes or file bytes)")
			}
		})
	}
}
