//go:build squadproof

package squadproof

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

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
