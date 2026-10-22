package squadproof

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"syscall"

	_ "modernc.org/sqlite"
)

const applicationID = 1397837873

var schema = []string{
	`CREATE TABLE operations(id TEXT PRIMARY KEY, parent TEXT NOT NULL, session_uid TEXT UNIQUE, state TEXT NOT NULL, record BLOB NOT NULL)`,
	`CREATE TABLE inputs(ordinal INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE, target TEXT NOT NULL REFERENCES operations(id), state TEXT NOT NULL, execution_id TEXT, record BLOB NOT NULL, UNIQUE(target,execution_id))`,
	`CREATE TABLE tool_results(uid TEXT NOT NULL, key TEXT NOT NULL, fingerprint TEXT NOT NULL, result BLOB NOT NULL, PRIMARY KEY(uid,key))`,
	`CREATE TABLE effects(uid TEXT NOT NULL, key TEXT NOT NULL, body BLOB NOT NULL, PRIMARY KEY(uid,key))`,
	`CREATE TABLE context(root TEXT NOT NULL REFERENCES operations(id), key TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY(root,key))`,
	`CREATE TABLE events(ordinal INTEGER PRIMARY KEY, kind TEXT NOT NULL, operation TEXT NOT NULL)`,
}

// Ledger owns a fresh proof database. It never migrates or repairs an existing file.
type Ledger struct{ db *sql.DB }

func OpenLedger(path string) (*Ledger, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrInvalid
	}
	parent := filepath.Dir(path)
	real, err := filepath.EvalSymlinks(parent)
	if err != nil || real != parent {
		return nil, ErrInvalid
	}
	st, err := os.Stat(parent)
	if err != nil || !st.IsDir() || st.Mode().Perm() != 0700 {
		return nil, ErrInvalid
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || int(owner.Uid) != os.Getuid() {
		return nil, ErrInvalid
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	created := err == nil
	if errors.Is(err, os.ErrExist) {
		f, err = os.OpenFile(path, os.O_RDWR|syscall.O_NOFOLLOW, 0)
	}
	if err != nil {
		return nil, ErrInvalid
	}
	st, err = f.Stat()
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return nil, ErrInvalid
	}
	owner, ok = st.Sys().(*syscall.Stat_t)
	if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || !ok || int(owner.Uid) != os.Getuid() {
		return nil, ErrInvalid
	}
	// No persistent PRAGMA or schema write before an existing file's identity check.
	// Use DELETE journaling; this small single-case fixture needs no WAL adoption.
	u := url.URL{Scheme: "file", Path: path, RawQuery: url.Values{"mode": {"rw"}, "_pragma": {"busy_timeout(5000)", "synchronous(FULL)", "foreign_keys(1)"}}.Encode()}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	l := &Ledger{db: db}
	fail := func(err error) (*Ledger, error) { _ = db.Close(); return nil, err }
	if created {
		err = l.transaction(context.Background(), func(c *sql.Conn) error {
			for _, q := range schema {
				if _, err := c.ExecContext(context.Background(), q); err != nil {
					return err
				}
			}
			_, err := c.ExecContext(context.Background(), `PRAGMA application_id=1397837873; PRAGMA user_version=1`)
			return err
		})
		if err != nil {
			return fail(err)
		}
	} else {
		var app, version int
		if db.QueryRow("PRAGMA application_id").Scan(&app) != nil || db.QueryRow("PRAGMA user_version").Scan(&version) != nil || app != applicationID || version != 1 {
			return fail(ErrForeign)
		}
		for _, q := range []string{
			`SELECT id,parent,session_uid,state,record FROM operations LIMIT 0`,
			`SELECT ordinal,id,target,state,execution_id,record FROM inputs LIMIT 0`,
			`SELECT uid,key,fingerprint,result FROM tool_results LIMIT 0`,
			`SELECT uid,key,body FROM effects LIMIT 0`,
			`SELECT root,key,value FROM context LIMIT 0`,
			`SELECT ordinal,kind,operation FROM events LIMIT 0`,
		} {
			rows, err := db.Query(q)
			if err != nil {
				return fail(ErrForeign)
			}
			if err = rows.Close(); err != nil {
				return fail(err)
			}
		}
	}
	return l, nil
}

func (l *Ledger) Close() error { return l.db.Close() }
func (l *Ledger) transaction(ctx context.Context, fn func(*sql.Conn) error) error {
	c, err := l.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	if _, err = c.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return err
	}
	defer c.ExecContext(context.Background(), "ROLLBACK")
	if err = fn(c); err != nil {
		return err
	}
	_, err = c.ExecContext(ctx, "COMMIT")
	return err
}

type queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func readOperation(ctx context.Context, q queryer, id string) (Operation, error) {
	var raw []byte
	if err := q.QueryRowContext(ctx, `SELECT record FROM operations WHERE id=?`, id).Scan(&raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Operation{}, ErrNotFound
		}
		return Operation{}, err
	}
	var op Operation
	if err := json.Unmarshal(raw, &op); err != nil {
		return Operation{}, ErrForeign
	}
	return op, nil
}
func saveOperation(ctx context.Context, c *sql.Conn, op Operation) error {
	raw, err := json.Marshal(op)
	if err != nil {
		return err
	}
	_, err = c.ExecContext(ctx, `UPDATE operations SET session_uid=NULLIF(?,''),state=?,record=? WHERE id=?`, op.SessionUID, op.State, raw, op.ID)
	return err
}
func event(ctx context.Context, c *sql.Conn, kind, id string) error {
	_, err := c.ExecContext(ctx, `INSERT INTO events(kind,operation) VALUES(?,?)`, kind, id)
	return err
}
func (l *Ledger) Counts(ctx context.Context) (Stats, error) {
	var s Stats
	err := l.db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM operations),(SELECT count(*) FROM inputs),(SELECT count(*) FROM tool_results),(SELECT count(*) FROM effects),(SELECT count(*) FROM events)`).Scan(&s.Operations, &s.Inputs, &s.ToolResults, &s.Effects, &s.Events)
	return s, err
}
