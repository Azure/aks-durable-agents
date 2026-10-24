package targetversions

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

func storageTestPath(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "private", "versions.db")
}

func storageSyncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	err = dir.Sync()
	closeErr := dir.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func TestStorageCreateSyncsContainingDirectoryOnRetry(t *testing.T) {
	for _, retry := range []bool{false, true} {
		t.Run(map[bool]string{false: "new", true: "retry"}[retry], func(t *testing.T) {
			path := storageTestPath(t)
			parent := filepath.Dir(path)
			if retry {
				if err := os.Mkdir(parent, 0700); err != nil {
					t.Fatal(err)
				}
			}
			var synced []string
			s, err := openStoreWithSync(path, "", true, func(dir string) error {
				synced = append(synced, dir)
				return storageSyncDirectory(dir)
			})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if want := []string{filepath.Dir(parent), parent}; !reflect.DeepEqual(synced, want) {
				t.Fatalf("directory persistence order=%v, want %v", synced, want)
			}
		})
	}
}

func TestStorageCreateFailureCleanup(t *testing.T) {
	for _, failure := range []string{"containing-directory-sync", "file-directory-sync", "sql-initialization"} {
		t.Run(failure, func(t *testing.T) {
			path := storageTestPath(t)
			parent := filepath.Dir(path)
			privateErr := &os.PathError{Op: "sync", Path: path, Err: errors.New("private storage diagnostic")}
			s, err := openStoreWithSync(path, "", true, func(dir string) error {
				if failure == "containing-directory-sync" && dir == filepath.Dir(parent) || failure == "file-directory-sync" && dir == parent {
					return privateErr
				}
				if failure == "sql-initialization" && dir == parent {
					db, err := sql.Open("sqlite", path)
					if err != nil {
						t.Fatal(err)
					}
					_, err = db.Exec("CREATE TABLE metadata (already_exists TEXT)")
					closeErr := db.Close()
					if err != nil || closeErr != nil {
						t.Fatalf("prepare initialization failure: %v, close: %v", err, closeErr)
					}
				}
				return storageSyncDirectory(dir)
			})
			if s != nil {
				s.Close()
				t.Fatal("Create succeeded despite injected storage failure")
			}
			if err == nil || errors.Unwrap(err) != nil || strings.Contains(err.Error(), path) || strings.Contains(err.Error(), "private storage diagnostic") {
				t.Fatalf("non-private refusal: %v", err)
			}
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				t.Fatalf("failed Create left database behind: %v", err)
			}
			// The failed initializer must not prevent a clean retry.
			s, err = Create(path)
			if err != nil {
				t.Fatal("retry after failed Create", err)
			}
			s.Close()
		})
	}
}

func TestStorageCreateCleanupPreservesOtherFiles(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(map[bool]string{false: "preexisting", true: "replacement"}[replace], func(t *testing.T) {
			path := storageTestPath(t)
			if err := os.Mkdir(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			const unrelated = "unrelated file must remain"
			if !replace {
				if err := os.WriteFile(path, []byte(unrelated), 0600); err != nil {
					t.Fatal(err)
				}
			}
			s, err := openStoreWithSync(path, "", true, func(dir string) error {
				if replace && dir == filepath.Dir(path) {
					if err := os.Rename(path, path+".moved"); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, []byte(unrelated), 0600); err != nil {
						t.Fatal(err)
					}
					return errors.New("injected directory sync failure")
				}
				return storageSyncDirectory(dir)
			})
			if s != nil || err == nil {
				if s != nil {
					s.Close()
				}
				t.Fatal("Create did not fail")
			}
			got, err := os.ReadFile(path)
			if err != nil || string(got) != unrelated {
				t.Fatalf("Create removed or changed unrelated path: %q (%v)", got, err)
			}
		})
	}
}

func storageSQLiteFailure(t *testing.T, kind string) error {
	t.Helper()
	path := ":memory:"
	if kind == "cantopen" {
		path = filepath.Join(privateTempDir(t), "missing", "store.db")
	}
	if kind == "notadb" {
		path = filepath.Join(privateTempDir(t), "not-a-database.db")
		if err := os.WriteFile(path, []byte(strings.Repeat("not a database", 100)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var stmt string
	switch kind {
	case "full":
		if _, err := db.Exec("PRAGMA page_size=512; CREATE TABLE data (value BLOB); PRAGMA max_page_count=2"); err != nil {
			t.Fatal(err)
		}
		stmt = "INSERT INTO data VALUES(zeroblob(4096))"
	case "readonly":
		if _, err := db.Exec("CREATE TABLE data (value BLOB); PRAGMA query_only=ON"); err != nil {
			t.Fatal(err)
		}
		stmt = "INSERT INTO data VALUES('x')"
	case "constraint":
		if _, err := db.Exec("CREATE TABLE data (value TEXT PRIMARY KEY); INSERT INTO data VALUES('x')"); err != nil {
			t.Fatal(err)
		}
		stmt = "INSERT INTO data VALUES('x')"
	default:
		stmt = "SELECT * FROM missing"
	}
	_, err = db.Exec(stmt)
	if err == nil {
		t.Fatal("SQLite fault setup did not fail")
	}
	return err
}

func TestStorageSQLiteFailureClasses(t *testing.T) {
	for _, tc := range []struct {
		kind string
		code int
		want error
	}{
		{"full", sqlite3.SQLITE_FULL, ErrUnavailable},
		{"readonly", sqlite3.SQLITE_READONLY, ErrUnavailable},
		{"cantopen", sqlite3.SQLITE_CANTOPEN, ErrUnavailable},
		{"missing-table", sqlite3.SQLITE_ERROR, ErrIntegrity},
		{"notadb", sqlite3.SQLITE_NOTADB, ErrIntegrity},
		{"constraint", sqlite3.SQLITE_CONSTRAINT, ErrIntegrity},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			raw := storageSQLiteFailure(t, tc.kind)
			var sqliteErr *sqlite.Error
			if !errors.As(raw, &sqliteErr) || sqliteErr.Code()&255 != tc.code {
				t.Fatalf("fault setup: got %v, want SQLite code %d", raw, tc.code)
			}
			if got := normalizeError(ctx, fmt.Errorf("private diagnostic: %w", raw)); got != tc.want {
				t.Fatalf("classification: %v, want %v", got, tc.want)
			}
		})
	}
}

func TestStorageOperationalVerificationFailureDoesNotLatch(t *testing.T) {
	for _, kind := range []string{"full", "readonly", "cantopen"} {
		t.Run(kind, func(t *testing.T) {
			s, _ := newStore(t)
			raw := storageSQLiteFailure(t, kind)
			if err := s.transaction(ctx, true, func(query) error { return raw }); err != ErrUnavailable {
				t.Fatalf("operational verification failure: %v", err)
			}
			if s.bad.Load() {
				t.Fatal("operational failure latched corruption")
			}
			if _, err := s.RegisterTarget(ctx, "after-storage-recovery"); err != nil {
				t.Fatal("handle unusable after operational failure", err)
			}
		})
	}
}

func TestStorageFixedClassesAndContext(t *testing.T) {
	for _, class := range []error{ErrUnavailable, ErrOccupied} {
		if got := normalizeError(ctx, fmt.Errorf("private diagnostic: %w", class)); got != class {
			t.Fatalf("lost fixed class: %v, want %v", got, class)
		}
	}
	if got := normalizeError(ctx, errors.New("driver closed: private path")); got != ErrUnavailable {
		t.Fatalf("unknown operational failure: %v", got)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if got := normalizeError(canceled, storageSQLiteFailure(t, "full")); got != context.Canceled {
		t.Fatalf("context precedence over operational failure: %v", got)
	}
}

func TestStorageMalformedJSONRemainsIntegrity(t *testing.T) {
	for _, payload := range []string{"{", `{"Revision":"not-a-number"}`, `[1]`} {
		t.Run(payload, func(t *testing.T) {
			s, _ := newStore(t)
			target := register(t, s, "agent")
			if _, err := s.db.Exec("UPDATE targets SET data=? WHERE id=?", payload, target.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := s.ReadTarget(ctx, target.ID); err != ErrIntegrity {
				t.Fatalf("malformed stored JSON: %v", err)
			}
		})
	}
	s, _ := newStore(t)
	if _, err := load[Version](ctx, s.db, "SELECT ?", `{"CreatedAt":"not-a-time"}`); err != ErrIntegrity {
		t.Fatalf("malformed JSON timestamp: %v", err)
	}
	var value Target
	parseErr := json.Unmarshal([]byte("{"), &value)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if got := normalizeError(canceled, parseErr); got != ErrIntegrity {
		t.Fatalf("confirmed JSON parse failure masked by cancellation: %v", got)
	}
}

func TestStorageBasicVerifyPropagatesQueryFailures(t *testing.T) {
	s, _ := newStore(t)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := s.basicVerify(canceled, s.db); err != context.Canceled {
		t.Fatalf("integrity_check query error replaced with corruption: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := normalizeError(ctx, s.basicVerify(ctx, s.db)); err != ErrUnavailable {
		t.Fatalf("closed-driver verification query: %v", err)
	}
}

func TestStorageTargetOccupiedIsNotSQLiteBusy(t *testing.T) {
	s, _ := newStore(t)
	target := register(t, s, "agent")
	begin(t, s, request(target, "first"))
	if _, err := s.Begin(ctx, request(target, "second")); err != ErrOccupied || errors.Is(err, ErrBusy) {
		t.Fatalf("target occupied must not be SQLite contention: %v", err)
	}
}

func TestStorageExtraOnReplacementConnections(t *testing.T) {
	s, _ := newStore(t)
	for _, replace := range []bool{false, true} {
		if replace {
			s.db.SetMaxIdleConns(0)
		}
		var synchronous int
		if err := s.db.QueryRow("PRAGMA synchronous").Scan(&synchronous); err != nil {
			t.Fatal(err)
		}
		if synchronous != 3 {
			t.Fatalf("replacement=%t: synchronous=%d, want EXTRA (3)", replace, synchronous)
		}
	}
}
