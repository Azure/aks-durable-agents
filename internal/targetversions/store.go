package targetversions

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

type Store struct {
	db                   *sql.DB
	bad                  atomic.Bool
	ID, BackendLineageID string
	now                  func() time.Time
}
type query interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

var schema = []string{
	`CREATE TABLE metadata (singleton INTEGER PRIMARY KEY CHECK(singleton=1),schema_version INTEGER NOT NULL,store_id TEXT NOT NULL,backend_id TEXT NOT NULL)`,
	`CREATE TABLE targets (id TEXT PRIMARY KEY,data BLOB NOT NULL)`,
	`CREATE TABLE operations (id TEXT PRIMARY KEY,target TEXT NOT NULL REFERENCES targets(id),decision_store TEXT NOT NULL,decision_id TEXT NOT NULL,data BLOB NOT NULL,UNIQUE(decision_store,decision_id))`,
	`CREATE TABLE operation_state (id TEXT PRIMARY KEY REFERENCES operations(id),data BLOB NOT NULL)`,
	`CREATE TABLE versions (id TEXT PRIMARY KEY,target TEXT NOT NULL REFERENCES targets(id),operation TEXT NOT NULL UNIQUE REFERENCES operations(id),data BLOB NOT NULL)`,
	`CREATE TABLE request_keys (target TEXT NOT NULL REFERENCES targets(id),key TEXT NOT NULL,kind TEXT NOT NULL,operation TEXT NOT NULL REFERENCES operations(id),fingerprint TEXT NOT NULL,PRIMARY KEY(target,key))`,
	`CREATE TABLE events (target TEXT NOT NULL REFERENCES targets(id),sequence INTEGER NOT NULL,data BLOB NOT NULL,PRIMARY KEY(target,sequence))`,
	`CREATE TABLE links (kind TEXT NOT NULL,from_id TEXT NOT NULL,to_id TEXT NOT NULL,PRIMARY KEY(kind,from_id,to_id))`,
	`CREATE TABLE tombstones (operation TEXT PRIMARY KEY REFERENCES operations(id),intent TEXT NOT NULL UNIQUE)`,
	`CREATE TABLE decision_claims (store_id TEXT NOT NULL,id TEXT NOT NULL,operation TEXT NOT NULL REFERENCES operations(id),kind TEXT NOT NULL,PRIMARY KEY(store_id,id))`,
	`CREATE TABLE qualifications (store_id TEXT NOT NULL,id TEXT NOT NULL,data BLOB NOT NULL,PRIMARY KEY(store_id,id))`,
	`CREATE TABLE abandonments (id TEXT PRIMARY KEY,operation TEXT NOT NULL UNIQUE REFERENCES operations(id),data BLOB NOT NULL)`,
}

func privatePath(path string, create bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrInvalid
	}
	parent := filepath.Dir(path)
	for p := parent; ; p = filepath.Dir(p) {
		st, e := os.Lstat(p)
		if e != nil {
			if p == parent && create && os.IsNotExist(e) {
				continue
			}
			return ErrIntegrity
		}
		if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return ErrIntegrity
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	if create {
		if e := os.Mkdir(parent, 0700); e != nil && !os.IsExist(e) {
			return e
		}
	}
	st, e := os.Lstat(parent)
	if e != nil || st.Mode().Perm() != 0700 {
		return ErrIntegrity
	}
	if u, ok := st.Sys().(*unix.Stat_t); ok && int(u.Uid) != os.Getuid() {
		return ErrIntegrity
	}
	for _, suffix := range []string{"-journal", "-wal", "-shm"} {
		st, e := os.Lstat(path + suffix)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 {
			return ErrIntegrity
		}
		if u, ok := st.Sys().(*unix.Stat_t); ok && int(u.Uid) != os.Getuid() {
			return ErrIntegrity
		}
	}
	if !create {
		// Closing any plain descriptor for this inode releases the process's
		// POSIX locks, including another SQLite handle's transaction locks.
		// Inspect existing files without opening/closing an extra descriptor.
		var stat unix.Stat_t
		if err := unix.Lstat(path, &stat); err != nil {
			return err
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0777 != 0600 || stat.Size == 0 || int(stat.Uid) != os.Getuid() || stat.Nlink != 1 {
			return ErrIntegrity
		}
		return nil
	}
	flags := unix.O_RDWR | unix.O_NOFOLLOW | unix.O_CLOEXEC
	if create {
		flags |= unix.O_CREAT | unix.O_EXCL
	}
	fd, e := unix.Open(path, flags, 0600)
	if e != nil {
		return e
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, e = f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || (!create && st.Size() == 0) {
		return ErrIntegrity
	}
	var stat unix.Stat_t
	if e = unix.Fstat(fd, &stat); e != nil || int(stat.Uid) != os.Getuid() || stat.Nlink != 1 {
		return ErrIntegrity
	}
	if create {
		if e = f.Sync(); e != nil {
			return e
		}
		dir, e := os.Open(parent)
		if e != nil {
			return e
		}
		defer dir.Close()
		return dir.Sync()
	}
	return nil
}
func Create(path string) (*Store, error) { return openStore(path, "", true) }
func Open(path, expectedStoreID string) (*Store, error) {
	if !keyOK(expectedStoreID) {
		return nil, ErrInvalid
	}
	return openStore(path, expectedStoreID, false)
}
func openStore(path, expected string, create bool) (*Store, error) {
	if e := privatePath(path, create); e != nil {
		return nil, fmt.Errorf("%w: private path: %v", ErrIntegrity, e)
	}
	// DELETE is SQLite's initial persistent mode. Open checks it without changing
	// it, so an unsupported schema is never converted from a different journal mode.
	params := url.Values{"mode": {"rw"}, "_pragma": {"busy_timeout(5000)", "synchronous(FULL)", "foreign_keys(1)"}}
	u := url.URL{Scheme: "file", Path: path, RawQuery: params.Encode()}
	db, e := sql.Open("sqlite", u.String())
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, now: func() time.Time { return time.Now().UTC() }}
	if create {
		s.ID = rand.Text()
		s.BackendLineageID = rand.Text()
	}
	e = s.transact(context.Background(), func(q query) error {
		if create {
			for _, stmt := range schema {
				if _, e := q.ExecContext(context.Background(), stmt); e != nil {
					return e
				}
			}
			_, e := q.ExecContext(context.Background(), "INSERT INTO metadata VALUES(1,1,?,?)", s.ID, s.BackendLineageID)
			return e
		}
		var v int
		if e := q.QueryRowContext(context.Background(), "SELECT schema_version,store_id,backend_id FROM metadata WHERE singleton=1").Scan(&v, &s.ID, &s.BackendLineageID); e != nil {
			return e
		}
		if v != 1 {
			return ErrUnsupported
		}
		if s.ID != expected {
			return ErrIntegrity
		}
		return s.verify(context.Background(), q)
	})
	if e != nil {
		db.Close()
		return nil, e
	}
	return s, nil
}
func (s *Store) Close() error { return s.db.Close() }
func (s *Store) transact(ctx context.Context, fn func(query) error) (err error) {
	defer func() {
		if err == nil {
			return
		}
		if ctx.Err() != nil {
			err = ctx.Err()
			return
		}
		var sqliteErr *sqlite.Error
		if errors.As(err, &sqliteErr) && (sqliteErr.Code()&255 == sqlite3.SQLITE_BUSY || sqliteErr.Code()&255 == sqlite3.SQLITE_LOCKED) {
			err = fmt.Errorf("%w: %w", ErrBusy, err)
			return
		}
		if !errors.Is(err, ErrConflict) && !errors.Is(err, ErrBusy) && !errors.Is(err, ErrIntegrity) && !errors.Is(err, ErrUnsupported) && !errors.Is(err, ErrInvalid) {
			err = fmt.Errorf("%w: %v", ErrIntegrity, err)
		}
	}()
	if s.bad.Load() {
		return ErrIntegrity
	}
	c, e := s.db.Conn(ctx)
	if e != nil {
		return e
	}
	defer c.Close()
	if _, e = c.ExecContext(ctx, "BEGIN IMMEDIATE"); e != nil {
		return e
	}
	defer c.ExecContext(context.Background(), "ROLLBACK")
	if e = fn(c); e == nil {
		_, e = c.ExecContext(ctx, "COMMIT")
	}
	return e
}
func put(ctx context.Context, q query, sql string, args ...any) error {
	_, e := q.ExecContext(ctx, sql, args...)
	return e
}
func encoded(v any) []byte { b, _ := json.Marshal(v); return b }
func load[T any](ctx context.Context, q query, stmt string, args ...any) (T, error) {
	var v T
	var b []byte
	e := q.QueryRowContext(ctx, stmt, args...).Scan(&b)
	if e == nil {
		e = json.Unmarshal(b, &v)
	}
	return v, e
}
func target(ctx context.Context, q query, id string) (Target, error) {
	t, err := load[Target](ctx, q, "SELECT data FROM targets WHERE id=?", id)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrConflict
	}
	return t, err
}
func operation(ctx context.Context, q query, id string) (Operation, error) {
	o, err := load[Operation](ctx, q, "SELECT data FROM operation_state WHERE id=?", id)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrConflict
	}
	return o, err
}
func (s *Store) ReadTarget(ctx context.Context, id string) (Target, error) {
	return target(ctx, s.db, id)
}
func (s *Store) ReadOperation(ctx context.Context, id string) (Operation, error) {
	return operation(ctx, s.db, id)
}
func (s *Store) RegisterTarget(ctx context.Context, id string) (out Target, err error) {
	if !keyOK(id) {
		return out, ErrInvalid
	}
	err = s.transact(ctx, func(q query) error {
		t, e := target(ctx, q, id)
		if e == nil {
			out = t
			return nil
		}
		if !errors.Is(e, ErrConflict) {
			return e
		}
		out = Target{ID: id, Kind: "ordinary", StoreID: s.ID, GenesisID: rand.Text(), Revision: 1, Availability: "unavailable"}
		out.Predecessor = PredecessorRef{"genesis", out.GenesisID}
		if e = put(ctx, q, "INSERT INTO targets VALUES(?,?)", id, encoded(out)); e != nil {
			return e
		}
		return s.event(ctx, q, out, nil, "", nil, "")
	})
	return
}
func (s *Store) event(ctx context.Context, q query, t Target, o *Operation, from string, links []Link, tomb string) error {
	ev := Event{BackendLineageID: s.BackendLineageID, Sequence: t.Revision, TargetID: t.ID, At: s.now(), Target: t, Operation: o, FromPhase: from, Links: links, Tombstone: tomb}
	if o != nil {
		ev.OperationID = o.ID
		ev.ToPhase = o.Phase
	}
	for _, l := range links {
		if e := put(ctx, q, "INSERT INTO links VALUES(?,?,?)", l.Kind, l.FromID, l.ToID); e != nil {
			return e
		}
	}
	return put(ctx, q, "INSERT INTO events VALUES(?,?,?)", t.ID, t.Revision, encoded(ev))
}
func pair(kind, from, to string) []Link {
	return []Link{{kind, from, to}, {kind + "_reverse", to, from}}
}
func (s *Store) save(ctx context.Context, q query, t Target, o Operation, from string, links []Link, tomb string) error {
	previous, e := operation(ctx, q, o.ID)
	if e != nil {
		return e
	}
	if previous.Revision != o.Revision || previous.Phase != from {
		return ErrConflict
	}
	t.Revision++
	o.Revision++
	if e := put(ctx, q, "UPDATE targets SET data=? WHERE id=?", encoded(t), t.ID); e != nil {
		return e
	}
	res, e := q.ExecContext(ctx, "UPDATE operation_state SET data=? WHERE id=? AND data=?", encoded(o), o.ID, encoded(previous))
	if e != nil {
		return e
	}
	n, e := res.RowsAffected()
	if e != nil || n != 1 {
		return ErrConflict
	}
	return s.event(ctx, q, t, &o, from, links, tomb)
}

func (s *Store) Begin(ctx context.Context, r Request) (out Operation, err error) {
	if !bounded(r) || !keyOK(r.TargetID) || !keyOK(r.Key) {
		return out, ErrInvalid
	}
	fp := r.fingerprint()
	err = s.transact(ctx, func(q query) error {
		var kind, id, stored string
		e := q.QueryRowContext(ctx, "SELECT kind,operation,fingerprint FROM request_keys WHERE target=? AND key=?", r.TargetID, r.Key).Scan(&kind, &id, &stored)
		if e == nil {
			if kind != "begin" || stored != fp {
				return ErrConflict
			}
			out, e = operation(ctx, q, id)
			return e
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		var used string
		e = q.QueryRowContext(ctx, "SELECT operation FROM decision_claims WHERE store_id=? AND id=?", r.DecisionRecord.StoreID, r.DecisionRecord.ID).Scan(&used)
		if e == nil {
			return ErrConflict
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		if !r.valid() {
			return ErrInvalid
		}
		t, e := target(ctx, q, r.TargetID)
		if e != nil {
			return e
		}
		if t.Kind != "ordinary" {
			return ErrUnsupported
		}
		if t.OperationID != "" {
			return ErrBusy
		}
		if t.Revision != r.ExpectedRevision || t.Generation >= uint64(1<<63-1) || t.Predecessor != r.Predecessor {
			return ErrConflict
		}
		source, e := s.source(ctx, q, t, r)
		if e != nil {
			return e
		}
		qual := r.Candidate.Qualification
		retained, e := load[Qualification](ctx, q, "SELECT data FROM qualifications WHERE store_id=? AND id=?", qual.StoreID, qual.ID)
		if e == nil {
			if !same(retained, qual) {
				return ErrConflict
			}
		} else if errors.Is(e, sql.ErrNoRows) {
			if e = put(ctx, q, "INSERT INTO qualifications VALUES(?,?,?)", qual.StoreID, qual.ID, encoded(qual)); e != nil {
				return e
			}
		} else {
			return e
		}
		id = rand.Text()
		v := Version{ID: rand.Text(), TargetID: t.ID, OperationID: id, ExecutionContextID: rand.Text(), Candidate: r.Candidate, CreatedAt: s.now()}
		out = Operation{ID: id, Fingerprint: fp, Revision: 1, Generation: t.Generation + 1, Phase: "preparing", Request: r, Version: v, FrozenSource: source}
		if e = put(ctx, q, "INSERT INTO operations VALUES(?,?,?,?,?)", id, t.ID, r.DecisionRecord.StoreID, r.DecisionRecord.ID, encoded(out)); e != nil {
			return e
		}
		if e = put(ctx, q, "INSERT INTO decision_claims VALUES(?,?,?,'begin')", r.DecisionRecord.StoreID, r.DecisionRecord.ID, id); e != nil {
			return e
		}
		if e = put(ctx, q, "INSERT INTO operation_state VALUES(?,?)", id, encoded(out)); e != nil {
			return e
		}
		if e = put(ctx, q, "INSERT INTO versions VALUES(?,?,?,?)", v.ID, t.ID, id, encoded(v)); e != nil {
			return e
		}
		if e = put(ctx, q, "INSERT INTO request_keys VALUES(?,?,'begin',?,?)", t.ID, r.Key, id, fp); e != nil {
			return e
		}
		t.Revision++
		t.Generation = out.Generation
		t.OperationID = id
		t.Availability = "fenced"
		if e = put(ctx, q, "UPDATE targets SET data=? WHERE id=?", encoded(t), t.ID); e != nil {
			return e
		}
		var links []Link
		if r.Predecessor.Kind == "abandonment" {
			links = append(links, pair("attempt", r.Predecessor.ID, id)...)
		}
		if r.SourceVersionID != "" {
			links = append(links, pair("source", r.SourceVersionID, v.ID)...)
		}
		return s.event(ctx, q, t, &out, "", links, "")
	})
	return
}
func (s *Store) source(ctx context.Context, q query, t Target, r Request) (*Version, error) {
	switch r.Predecessor.Kind {
	case "genesis":
		if r.Predecessor.ID == t.GenesisID && t.ActiveVersionID == "" && r.Intent == "activate" && r.SourceVersionID == "" {
			return nil, nil
		}
	case "version":
		if r.Predecessor.ID != t.ActiveVersionID || t.ActiveVersionID == "" {
			return nil, ErrConflict
		}
		v, e := committedVersion(ctx, q, t.ActiveVersionID, t.ID)
		if e != nil {
			return nil, e
		}
		if r.Intent == "activate" && r.SourceVersionID == "" {
			return &v, nil
		}
		if r.Intent == "rollback" && r.SourceVersionID != t.ActiveVersionID {
			source, e := committedVersion(ctx, q, r.SourceVersionID, t.ID)
			if e != nil {
				return nil, e
			}
			if retainedPackage(source.Candidate, r.Candidate) {
				return &v, nil
			}
		}
	case "abandonment":
		previous, e := terminal(ctx, q, r.Predecessor.ID)
		if e != nil {
			return nil, e
		}
		if previous.Request.TargetID != t.ID || t.ActiveVersionID != "" {
			return nil, ErrConflict
		}
		if previous.FrozenSource == nil {
			if r.Intent == "activate" && r.SourceVersionID == "" {
				return nil, nil
			}
		} else if r.Intent == "recover" && r.SourceVersionID == previous.FrozenSource.ID && retainedPackage(previous.FrozenSource.Candidate, r.Candidate) {
			source := *previous.FrozenSource
			return &source, nil
		}
	}
	return nil, ErrConflict
}
func retainedPackage(a, b Candidate) bool {
	x, y := a.Artifact, b.Artifact
	return a.SourceDigest == b.SourceDigest && x.SuiteDigest == y.SuiteDigest && x.Member == y.Member && x.Composition == y.Composition && x.Platform == y.Platform && x.InventoryDigest == y.InventoryDigest && x.CasesDigest == y.CasesDigest
}
func committedVersion(ctx context.Context, q query, id, targetID string) (Version, error) {
	v, e := load[Version](ctx, q, "SELECT data FROM versions WHERE id=?", id)
	if errors.Is(e, sql.ErrNoRows) {
		return v, ErrConflict
	}
	if e != nil {
		return v, e
	}
	o, e := operation(ctx, q, v.OperationID)
	if e != nil {
		return v, e
	}
	if o.Phase != "committed" || v.TargetID != targetID || !same(o.Version, v) {
		return v, ErrConflict
	}
	return v, nil
}
func terminal(ctx context.Context, q query, id string) (Operation, error) {
	var op string
	if e := q.QueryRowContext(ctx, "SELECT operation FROM abandonments WHERE id=?", id).Scan(&op); e != nil {
		if errors.Is(e, sql.ErrNoRows) {
			return Operation{}, ErrConflict
		}
		return Operation{}, e
	}
	o, e := operation(ctx, q, op)
	if e != nil {
		return o, e
	}
	if o.Phase != "abandoned-unavailable" || o.Abandonment == nil || o.Abandonment.ID != id {
		return o, ErrConflict
	}
	return o, nil
}
func (s *Store) basicVerify(ctx context.Context, q query) error {
	var check, mode string
	if e := q.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&check); e != nil || check != "ok" {
		return ErrIntegrity
	}
	if e := q.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); e != nil || mode != "delete" {
		return ErrIntegrity
	}
	rows, e := q.QueryContext(ctx, "PRAGMA foreign_key_check")
	if e != nil {
		return e
	}
	defer rows.Close()
	if rows.Next() {
		return ErrIntegrity
	}
	return rows.Err()
}
