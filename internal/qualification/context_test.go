package qualification

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"modernc.org/sqlite"
)

type lookupCancelKey struct{}
type lookupCancelDriver struct{}
type lookupCancelConn struct{ driver.Conn }

func (lookupCancelDriver) Open(name string) (driver.Conn, error) {
	c, err := (&sqlite.Driver{}).Open(name)
	if err != nil {
		return nil, err
	}
	return lookupCancelConn{c}, nil
}
func (c lookupCancelConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	return c.Conn.(driver.ExecerContext).ExecContext(ctx, query, args)
}
func (c lookupCancelConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if strings.HasPrefix(query, "SELECT id FROM records WHERE") {
		if cancel, ok := ctx.Value(lookupCancelKey{}).(context.CancelFunc); ok {
			cancel()
		}
	}
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, query, args)
}

var registerLookupCancelDriver sync.Once

func TestAdmitLookupCancellation(t *testing.T) {
	s, dir := testStore(t)
	if err := s.db.Close(); err != nil {
		t.Fatal(err)
	}
	registerLookupCancelDriver.Do(func() { sql.Register("qualification-lookup-cancel", lookupCancelDriver{}) })
	db, err := sql.Open("qualification-lookup-cancel", dbURI(filepath.Join(dir, "records.db"), false))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	s.db = db
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx = context.WithValue(ctx, lookupCancelKey{}, cancel)
	_, err = s.Admit(ctx, Request{Key: "cancelled", Requester: "caller", Plan: testPlan()})
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrIntegrity) {
		t.Fatalf("lookup cancellation reported as integrity failure: %v", err)
	}
	if _, err = s.Admit(context.Background(), Request{Key: "after-cancel", Requester: "caller", Plan: testPlan()}); err != nil {
		t.Fatalf("cancelled transaction not released: %v", err)
	}
}
