package qualification

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

type codedStorageFailure int

func (e codedStorageFailure) Error() string { return "private storage details" }
func (e codedStorageFailure) Code() int     { return int(e) }
func TestStorageErrorClassification(t *testing.T) {
	for code, want := range map[int]error{sqlite3.SQLITE_FULL: ErrUnavailable, sqlite3.SQLITE_IOERR_READ: ErrUnavailable, sqlite3.SQLITE_IOERR_FSYNC: ErrUnavailable, sqlite3.SQLITE_CANTOPEN: ErrUnavailable, sqlite3.SQLITE_CORRUPT: ErrIntegrity, sqlite3.SQLITE_NOTADB: ErrIntegrity, sqlite3.SQLITE_ERROR: ErrIntegrity, sqlite3.SQLITE_IOERR_DATA: ErrIntegrity, sqlite3.SQLITE_IOERR_CORRUPTFS: ErrIntegrity, sqlite3.SQLITE_READONLY_ROLLBACK: ErrIntegrity, sqlite3.SQLITE_READONLY_DBMOVED: ErrIntegrity} {
		if got := databaseError(fmt.Errorf("private path: %w", codedStorageFailure(code))); got != want {
			t.Errorf("SQLite %d: %v, want %v", code, got, want)
		}
	}
	for _, err := range []error{context.Canceled, context.DeadlineExceeded} {
		if got := databaseError(err); got != err {
			t.Errorf("context classification: %v", got)
		}
	}
	for _, err := range []error{syscall.EIO, syscall.ENOSPC, syscall.EMFILE} {
		if got := fileError(&os.PathError{Op: "read", Path: "private", Err: err}); got != ErrUnavailable {
			t.Errorf("IO classification leaked/misclassified: %v", got)
		}
	}
	for _, err := range []error{os.ErrNotExist, syscall.EISDIR, syscall.ENXIO, syscall.EACCES, syscall.EPERM} {
		if fileError(err) != ErrIntegrity {
			t.Errorf("unsafe/missing path misclassified: %v", err)
		}
	}
	if databaseError(sql.ErrNoRows) != ErrIntegrity {
		t.Fatal("missing retained row is not an ordinary outage")
	}
}

type storageFaultKey struct{}
type storageFault struct {
	prefix string
	err    error
}
type storageFaultDriver struct{}
type storageFaultConn struct{ driver.Conn }

func (storageFaultDriver) Open(name string) (driver.Conn, error) {
	c, e := (&sqlite.Driver{}).Open(name)
	if e != nil {
		return nil, e
	}
	return storageFaultConn{c}, nil
}
func (c storageFaultConn) ExecContext(ctx context.Context, q string, a []driver.NamedValue) (driver.Result, error) {
	if f, ok := ctx.Value(storageFaultKey{}).(storageFault); ok && strings.HasPrefix(q, f.prefix) {
		return nil, f.err
	}
	return c.Conn.(driver.ExecerContext).ExecContext(ctx, q, a)
}
func (c storageFaultConn) QueryContext(ctx context.Context, q string, a []driver.NamedValue) (driver.Rows, error) {
	if f, ok := ctx.Value(storageFaultKey{}).(storageFault); ok && strings.HasPrefix(q, f.prefix) {
		return nil, f.err
	}
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, q, a)
}

var registerStorageFaultDriver sync.Once

func TestStorageIOFailuresUnavailable(t *testing.T) {
	for _, prefix := range []string{"BEGIN IMMEDIATE", "SELECT id FROM records", "INSERT INTO records", "COMMIT"} {
		t.Run(prefix, func(t *testing.T) {
			s, dir := testStore(t)
			if err := s.db.Close(); err != nil {
				t.Fatal(err)
			}
			registerStorageFaultDriver.Do(func() { sql.Register("qualification-storage-fault", storageFaultDriver{}) })
			db, err := sql.Open("qualification-storage-fault", dbURI(filepath.Join(dir, "records.db"), false))
			if err != nil {
				t.Fatal(err)
			}
			db.SetMaxOpenConns(1)
			s.db = db
			ctx := context.WithValue(context.Background(), storageFaultKey{}, storageFault{prefix, fmt.Errorf("private IO: %w", syscall.EIO)})
			_, err = s.Admit(ctx, Request{Key: "fault", Requester: "caller", Plan: testPlan()})
			if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrIntegrity) || err.Error() != ErrUnavailable.Error() {
				t.Fatalf("IO error misclassified or exposed: %v", err)
			}
			if _, err = s.Admit(context.Background(), Request{Key: "after", Requester: "caller", Plan: testPlan()}); err != nil {
				t.Fatalf("failed transaction retained locks: %v", err)
			}
		})
	}
}
