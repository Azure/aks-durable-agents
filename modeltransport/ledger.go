package modeltransport

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
	_ "modernc.org/sqlite"
)

type budgetLedger struct {
	db          *sql.DB
	maxAttempts int
	inputLimit  int
}

func openBudgetLedger(path, snapshot string, maxAttempts, inputLimit int) (*budgetLedger, error) {
	// The final directory is scenario-only and private. Refuse symlinks at every
	// existing path component; never chmod an operator's existing directory/file.
	parent := filepath.Dir(path)
	if err := os.Mkdir(parent, 0700); err != nil && !os.IsExist(err) {
		return nil, ledgerError()
	}
	for cur := parent; ; cur = filepath.Dir(cur) {
		st, err := os.Lstat(cur)
		if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return nil, ledgerError()
		}
		if cur == parent && st.Mode().Perm() != 0700 {
			return nil, ledgerError()
		}
		if cur == filepath.Dir(cur) {
			break
		}
	}
	// SQLite may open recovery sidecars before interpreting the main file.
	for _, suffix := range []string{"-journal", "-wal", "-shm"} {
		st, err := os.Lstat(path + suffix)
		if err != nil && !os.IsNotExist(err) {
			return nil, ledgerError()
		}
		if err == nil && (!st.Mode().IsRegular() || st.Mode().Perm() != 0600) {
			return nil, ledgerError()
		}
	}
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	created := err == nil
	if errors.Is(err, unix.EEXIST) {
		fd, err = unix.Open(path, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	}
	if err != nil {
		return nil, ledgerError()
	}
	file := os.NewFile(uintptr(fd), path)
	st, err := file.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 {
		file.Close()
		return nil, ledgerError()
	}
	// Do not silently reset an existing empty/truncated ledger after a crash.
	if !created && st.Size() == 0 {
		file.Close()
		return nil, ledgerError()
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return nil, ledgerError()
	}
	file.Close()
	dir, err := os.Open(parent)
	if err != nil {
		return nil, ledgerError()
	}
	err = dir.Sync()
	dir.Close()
	if err != nil {
		return nil, ledgerError()
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, ledgerError()
	}
	db.SetMaxOpenConns(1)
	fail := func() (*budgetLedger, error) { db.Close(); return nil, ledgerError() }
	// DELETE avoids long-lived WAL/SHM files, and FULL makes each committed
	// reservation/dispatch survive process restart before a possible POST.
	for _, stmt := range []string{"PRAGMA busy_timeout=5000", "PRAGMA journal_mode=DELETE", "PRAGMA synchronous=FULL"} {
		if _, err = db.Exec(stmt); err != nil {
			return fail()
		}
	}
	conn, err := db.Conn(context.Background())
	if err != nil {
		return fail()
	}
	defer conn.Close()
	if _, err = conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
		return fail()
	}
	defer conn.ExecContext(context.Background(), "ROLLBACK")
	if created {
		for _, stmt := range []string{
			`CREATE TABLE model_budget(id INTEGER PRIMARY KEY CHECK(id=1),snapshot TEXT NOT NULL)`,
			`CREATE TABLE model_attempts(id INTEGER PRIMARY KEY,request_hash TEXT NOT NULL UNIQUE,started_at TEXT NOT NULL,finished_at TEXT,outcome TEXT NOT NULL,input_tokens INTEGER,output_tokens INTEGER,reasoning_tokens INTEGER)`,
		} {
			if _, err = conn.ExecContext(context.Background(), stmt); err != nil {
				return fail()
			}
		}
		if _, err = conn.ExecContext(context.Background(), "INSERT INTO model_budget(id,snapshot) VALUES(1,?)", snapshot); err != nil {
			return fail()
		}
	} else {
		var stored string
		var count int
		if err = conn.QueryRowContext(context.Background(), "SELECT count(*) FROM model_budget").Scan(&count); err != nil || count != 1 {
			return fail()
		}
		if err = conn.QueryRowContext(context.Background(), "SELECT snapshot FROM model_budget WHERE id=1").Scan(&stored); err != nil || stored != snapshot {
			return fail()
		}
		// Read the fixed schema now, not only on the first send.
		if err = conn.QueryRowContext(context.Background(), "SELECT count(*) FROM model_attempts WHERE request_hash IS NULL OR started_at IS NULL OR outcome NOT IN ('reserved','dispatching','succeeded','failed','unknown')").Scan(&count); err != nil || count != 0 {
			return fail()
		}
	}
	if _, err = conn.ExecContext(context.Background(), "COMMIT"); err != nil {
		return fail()
	}
	return &budgetLedger{db: db, maxAttempts: maxAttempts, inputLimit: inputLimit}, nil
}

func (l *budgetLedger) reserve(hash string) (int64, error) {
	ctx := context.Background()
	conn, err := l.db.Conn(ctx)
	if err != nil {
		return 0, ledgerError()
	}
	defer conn.Close()
	if _, err = conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return 0, ledgerError()
	}
	defer conn.ExecContext(ctx, "ROLLBACK")
	var count, bad int
	if err = conn.QueryRowContext(ctx, "SELECT count(*),coalesce(sum(CASE WHEN outcome != 'succeeded' OR finished_at IS NULL OR input_tokens IS NULL OR output_tokens IS NULL OR input_tokens < 0 OR input_tokens > ? OR output_tokens < 0 OR output_tokens > ? OR reasoning_tokens < 0 OR reasoning_tokens > output_tokens THEN 1 ELSE 0 END),0) FROM model_attempts", l.inputLimit, maxOutputTokens).Scan(&count, &bad); err != nil || count >= l.maxAttempts || bad != 0 {
		return 0, ledgerError()
	}
	result, err := conn.ExecContext(ctx, "INSERT INTO model_attempts(request_hash,started_at,outcome) VALUES(?,?,'reserved')", hash, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, ledgerError()
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, ledgerError()
	}
	if _, err = conn.ExecContext(ctx, "COMMIT"); err != nil {
		return 0, ledgerError()
	}
	return id, nil
}
func (l *budgetLedger) change(id int64, outcome string, usage tokenUsage) error {
	var finished any
	if outcome != "dispatching" {
		finished = time.Now().UTC().Format(time.RFC3339Nano)
	}
	result, err := l.db.Exec(`UPDATE model_attempts SET outcome=?,finished_at=?,input_tokens=?,output_tokens=?,reasoning_tokens=? WHERE id=? AND (outcome='reserved' OR outcome='dispatching')`, outcome, finished, usage.Input, usage.Output, usage.Reasoning, id)
	if err != nil {
		return ledgerError()
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return ledgerError()
	}
	return nil
}
