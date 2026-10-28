package githubtools

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var testBinding = strings.Repeat("a", 64)

func testStore(t *testing.T) *Store {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s, err := Initialize(filepath.Join(root, "private", "github.db"), "host-lineage", testBinding)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// Catches accidental create-on-open, identity adoption and loss of the writer lock.
func TestStoreIdentity(t *testing.T) {
	s := testStore(t)
	path, id := s.path, s.ID()
	if _, err := Open(path, id, "host-lineage", testBinding); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("duplicate writer: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ id, lineage, binding string }{{"other", "host-lineage", testBinding}, {id, "other", testBinding}, {id, "host-lineage", strings.Repeat("b", 64)}} {
		if _, err := Open(path, tc.id, tc.lineage, tc.binding); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("adopted foreign store: %v", err)
		}
	}
	if _, err := Initialize(path, "host-lineage", testBinding); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("reinitialize: %v", err)
	}
	reopened, err := Open(path, id, "host-lineage", testBinding)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.ID() != id {
		t.Fatal("identity changed")
	}
	for _, p := range []string{filepath.Dir(path), path, path + ".lock"} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		want := os.FileMode(0600)
		if p == filepath.Dir(path) {
			want = 0700
		}
		if info.Mode().Perm() != want {
			t.Fatalf("%s permissions %v", p, info.Mode())
		}
	}
}

func TestStoreRefusesUnsafeState(t *testing.T) {
	for _, kind := range []string{"parent-mode", "file-mode", "sidecar-mode", "sidecar-link", "parent-link", "file-link", "missing-lock", "missing-db", "empty-db", "schema-version", "metadata-version", "added-object", "missing-index", "invalid-row"} {
		t.Run(kind, func(t *testing.T) {
			s := testStore(t)
			path, id := s.path, s.ID()
			s.Close()
			switch kind {
			case "parent-mode":
				if err := os.Chmod(filepath.Dir(path), 0755); err != nil {
					t.Fatal(err)
				}
			case "file-mode":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "sidecar-mode":
				if err := os.WriteFile(path+"-journal", nil, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path+"-journal", 0644); err != nil {
					t.Fatal(err)
				}
			case "sidecar-link":
				if err := os.Symlink(path, path+"-journal"); err != nil {
					t.Fatal(err)
				}
			case "parent-link":
				link := filepath.Join(filepath.Dir(filepath.Dir(path)), "link")
				if err := os.Symlink(filepath.Dir(path), link); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(link, "github.db")
			case "file-link":
				copy := path + ".original"
				if err := os.Rename(path, copy); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(copy, path); err != nil {
					t.Fatal(err)
				}
			case "missing-lock":
				if err := os.Remove(path + ".lock"); err != nil {
					t.Fatal(err)
				}
			case "missing-db":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "empty-db":
				if err := os.Truncate(path, 0); err != nil {
					t.Fatal(err)
				}
			default:
				db, err := sql.Open("sqlite", path)
				if err != nil {
					t.Fatal(err)
				}
				stmt := map[string]string{"schema-version": "PRAGMA user_version=9", "metadata-version": "UPDATE metadata SET schema_version=9", "added-object": "CREATE TABLE extra(id)", "missing-index": "DROP INDEX one_active_key", "invalid-row": "INSERT INTO approvals VALUES('bad','bad','s','k','active','{}')"}[kind]
				_, err = db.Exec(stmt)
				db.Close()
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := Open(path, id, "host-lineage", testBinding); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("unsafe open: %v", err)
			}
		})
	}
	root := filepath.Join(t.TempDir(), "missing")
	if _, err := Open(filepath.Join(root, "absent.db"), "id", "host-lineage", testBinding); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing open: %v", err)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("Open created parent")
	}
	if _, err := Initialize("relative", "host-lineage", testBinding); !errors.Is(err, ErrInvalid) {
		t.Fatalf("relative: %v", err)
	}
}

// Closing a duplicate SQLite descriptor must not unlock an admitted transaction.
func TestStoreCloseDrainsOperations(t *testing.T) {
	s := testStore(t)
	ctx := t.Context()
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() { done <- s.transaction(ctx, func(*sql.Conn) error { close(entered); <-release; return nil }) }()
	<-entered
	closed := make(chan error, 1)
	go func() { closed <- s.Close() }()
	deadline := time.After(5 * time.Second)
	for {
		s.lifecycle.Lock()
		closing := s.closing
		s.lifecycle.Unlock()
		if closing {
			break
		}
		select {
		case <-deadline:
			t.Fatal("Close did not start")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if _, err := Open(s.path, s.ID(), "host-lineage", testBinding); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("lock released early: %v", err)
	}
	if err := s.transaction(ctx, func(*sql.Conn) error { t.Error("admitted after Close"); return nil }); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
}

func TestStoreReplacementConnectionDurability(t *testing.T) {
	s := testStore(t)
	s.db.SetConnMaxLifetime(time.Nanosecond)
	for range 2 {
		if err := s.transaction(t.Context(), func(c *sql.Conn) error {
			for pragma, want := range map[string]int{"synchronous": 3, "foreign_keys": 1} {
				var got int
				if err := c.QueryRowContext(t.Context(), "PRAGMA "+pragma).Scan(&got); err != nil {
					return err
				}
				if got != want {
					t.Errorf("%s=%d want %d", pragma, got, want)
				}
			}
			var mode string
			if err := c.QueryRowContext(t.Context(), "PRAGMA journal_mode").Scan(&mode); err != nil {
				return err
			}
			if mode != "delete" {
				t.Errorf("mode=%s", mode)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}
