//go:build squadproof

package squadproof

import (
	"bytes"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestProofJournalTreatsPathAsLiteralFilesystemName(t *testing.T) {
	for _, name := range []string{"case#1", "case?ignored=1", "case%231"} {
		t.Run(name, func(t *testing.T) {
			outer := t.TempDir()
			data := filepath.Join(outer, name)
			if err := os.Mkdir(data, 0700); err != nil {
				t.Fatal(err)
			}
			victim := filepath.Join(outer, "case")
			if name == "case%231" {
				victimDir := filepath.Join(outer, "case#1")
				if err := os.Mkdir(victimDir, 0700); err != nil {
					t.Fatal(err)
				}
				victim = filepath.Join(victimDir, "journal.db")
			}
			if err := os.WriteFile(victim, nil, 0600); err != nil {
				t.Fatal(err)
			}
			uri := url.URL{Scheme: "file", Path: victim}
			db, err := sql.Open("sqlite", uri.String())
			if err != nil {
				t.Fatal(err)
			}
			_, seedErr := db.Exec(`CREATE TABLE foreign_data(value TEXT); INSERT INTO foreign_data VALUES('keep outside unchanged')`)
			closeErr := db.Close()
			if seedErr != nil || closeErr != nil {
				t.Fatalf("seed outside database: %v %v", seedErr, closeErr)
			}
			before, err := os.ReadFile(victim)
			if err != nil {
				t.Fatal(err)
			}
			l, err := OpenLedger(filepath.Join(data, "proof.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			store, openErr := proofJournal(t.Context(), l, data)
			if store != nil {
				if err := store.Close(); err != nil {
					t.Error(err)
				}
			}
			if openErr != nil {
				t.Errorf("literal filesystem path refused: %v", openErr)
			}
			intended, err := os.Stat(filepath.Join(data, "journal.db"))
			if err != nil || intended.Size() == 0 {
				t.Errorf("intended journal was not initialized: %v", err)
			}
			after, err := os.ReadFile(victim)
			if err != nil || !bytes.Equal(before, after) {
				t.Errorf("database outside validated case changed: %v", err)
			}
		})
	}
}

func TestProofKnownJournalMarkerLifecycle(t *testing.T) {
	l, path := openTestLedger(t)
	data := filepath.Dir(path)
	for i := 0; i < 2; i++ {
		store, err := proofJournal(t.Context(), l, data)
		if err != nil {
			t.Fatalf("journal open%d: %v", i, err)
		}
		if err = store.Close(); err != nil {
			t.Fatal(err)
		}
	}
	journal := filepath.Join(data, "journal.db")
	before, err := os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = l.db.Exec(`UPDATE events SET operation='wrong-package' WHERE kind='runtime-host'`); err != nil {
		t.Fatal(err)
	}
	store, err := proofJournal(t.Context(), l, data)
	if store != nil {
		store.Close()
	}
	if !errors.Is(err, ErrForeign) {
		t.Fatalf("wrong marker accepted: %v", err)
	}
	after, err := os.ReadFile(journal)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("rejected journal modified: %v", err)
	}
}

func TestProofUnmarkedJournalSidecarsRemainUntouched(t *testing.T) {
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		t.Run(suffix, func(t *testing.T) {
			l, path := openTestLedger(t)
			data := filepath.Dir(path)
			journal := filepath.Join(data, "journal.db")
			target := filepath.Join(data, "foreign-evidence")
			before := []byte("foreign crash evidence must survive")
			if err := os.WriteFile(target, before, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, journal+suffix); err != nil {
				t.Fatal(err)
			}
			store, err := proofJournal(t.Context(), l, data)
			if store != nil {
				store.Close()
			}
			if !errors.Is(err, ErrForeign) {
				t.Errorf("sidecar not refused before SQLite: %v", err)
			}
			after, err := os.ReadFile(target)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("foreign evidence modified: %q %v", after, err)
			}
			if link, err := os.Readlink(journal + suffix); err != nil || link != target {
				t.Fatalf("foreign sidecar replaced: %q %v", link, err)
			}
			if _, err := os.Lstat(journal); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("new journal created beside foreign sidecar: %v", err)
			}
		})
	}
}
