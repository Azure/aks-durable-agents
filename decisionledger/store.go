package decisionledger

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/agent-primitives/sessions/api"
	"golang.org/x/sys/unix"
	_ "modernc.org/sqlite"
)

type Store struct {
	db                *sql.DB
	file              *os.File // separate lifetime lock file; never unlink while in use.
	path, id, lineage string
	now               func() time.Time
	lifecycle         sync.Mutex
	closing           bool
	active            sync.WaitGroup
	closeOnce         sync.Once
	closeErr          error
}

func randomID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(b[:])
}
func (s *Store) ID() string { return s.id }

// Close refuses new operations and drains admitted DB work before releasing the
// lifetime lock. sql.DB.Close alone does not drain connections from db.Conn.
func (s *Store) Close() error {
	s.closeOnce.Do(func() {
		s.lifecycle.Lock()
		s.closing = true
		s.lifecycle.Unlock()
		s.active.Wait()
		if err := s.db.Close(); err != nil {
			s.closeErr = ErrUnavailable
		}
		if err := s.file.Close(); err != nil {
			s.closeErr = ErrUnavailable
		}
	})
	return s.closeErr
}

// Initialize is the only operation allowed to create a new store identity.
// Its immediate parent is created privately; ancestors must already exist.
func Initialize(path, hostLineageID string) (*Store, error) {
	return openStore(path, "", hostLineageID, true)
}

// Open never creates, repairs or migrates state. Expected identity must come
// from a separately retained recovery configuration, not this database itself.
func Open(path, expectedStoreID, hostLineageID string) (*Store, error) {
	if !textOK(expectedStoreID, 256) {
		return nil, ErrInvalid
	}
	return openStore(path, expectedStoreID, hostLineageID, false)
}
func openStore(path, id, lineage string, create bool) (*Store, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !textOK(lineage, 256) {
		return nil, ErrInvalid
	}
	parent := filepath.Dir(path)
	if create {
		if err := os.Mkdir(parent, 0700); err != nil && !os.IsExist(err) {
			return nil, ErrUnavailable
		}
	}
	for p := parent; ; p = filepath.Dir(p) {
		st, err := os.Lstat(p)
		if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return nil, ErrUnavailable
		}
		if p == parent {
			// Ownership is checked through stat below; no permissions are repaired.
			var info unix.Stat_t
			if unix.Lstat(p, &info) != nil || info.Uid != uint32(os.Geteuid()) || st.Mode().Perm() != 0700 {
				return nil, ErrUnavailable
			}
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	for _, suffix := range []string{"-journal", "-wal", "-shm"} {
		st, err := os.Lstat(path + suffix)
		if err == nil {
			var info unix.Stat_t
			if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || unix.Lstat(path+suffix, &info) != nil || info.Uid != uint32(os.Geteuid()) {
				return nil, ErrUnavailable
			}
		} else if !os.IsNotExist(err) {
			return nil, ErrUnavailable
		}
	}
	// Acquire a different inode before touching the DB. Closing a duplicate DB
	// descriptor in this process would release SQLite's POSIX record locks.
	lock, err := privateFile(path+".lock", create, false)
	if err != nil {
		return nil, ErrUnavailable
	}
	if unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		lock.Close()
		return nil, ErrUnavailable
	}
	file, err := privateFile(path, create, true)
	if err != nil {
		lock.Close()
		return nil, ErrUnavailable
	}
	failFile := func() (*Store, error) { file.Close(); lock.Close(); return nil, ErrUnavailable }
	st, err := file.Stat()
	if err != nil || (!create && st.Size() == 0) {
		return failFile()
	}
	if create {
		if file.Sync() != nil || lock.Sync() != nil {
			return failFile()
		}
		dir, err := os.Open(parent)
		if err != nil {
			return failFile()
		}
		err = dir.Sync()
		dir.Close()
		if err != nil {
			return failFile()
		}
	}
	if file.Close() != nil {
		lock.Close()
		return nil, ErrUnavailable
	}
	u := url.URL{Scheme: "file", Path: path}
	q := url.Values{}
	for _, p := range []string{"busy_timeout(5000)", "journal_mode(DELETE)", "synchronous(FULL)", "foreign_keys(1)"} {
		q.Add("_pragma", p)
	}
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return failFile()
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, file: lock, path: path, id: id, lineage: lineage, now: time.Now}
	fail := func() (*Store, error) { s.Close(); return nil, ErrUnavailable }
	if create {
		s.id = randomID()
		if s.id == "" {
			return fail()
		}
		err = s.transaction(context.Background(), func(c *sql.Conn) error {
			for _, stmt := range []string{
				`PRAGMA user_version=1`,
				`CREATE TABLE metadata(id INTEGER PRIMARY KEY CHECK(id=1),schema_version INTEGER NOT NULL,store_id TEXT NOT NULL,lineage TEXT NOT NULL)`,
				`CREATE TABLE subjects(workspace TEXT NOT NULL,kind TEXT NOT NULL,subject_id TEXT NOT NULL,generation INTEGER NOT NULL,digest TEXT NOT NULL,snapshot TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('open','decided','superseded')),PRIMARY KEY(workspace,kind,subject_id,generation))`,
				`CREATE UNIQUE INDEX one_open ON subjects(workspace,kind,subject_id) WHERE state='open'`,
				`CREATE TABLE requests(workspace TEXT NOT NULL,issuer TEXT NOT NULL,oid TEXT NOT NULL,request_key TEXT NOT NULL,kind TEXT NOT NULL,subject_id TEXT NOT NULL,generation INTEGER NOT NULL,record_id TEXT NOT NULL UNIQUE,outcome TEXT NOT NULL CHECK(outcome IN ('recorded','refused')),record TEXT NOT NULL,PRIMARY KEY(workspace,issuer,oid,request_key),FOREIGN KEY(workspace,kind,subject_id,generation) REFERENCES subjects(workspace,kind,subject_id,generation))`,
				`CREATE UNIQUE INDEX one_decision ON requests(workspace,kind,subject_id,generation) WHERE outcome='recorded'`,
			} {
				if _, err := c.ExecContext(context.Background(), stmt); err != nil {
					return ErrUnavailable
				}
			}
			_, err := c.ExecContext(context.Background(), "INSERT INTO metadata VALUES(1,1,?,?)", s.id, lineage)
			return err
		})
		if err != nil {
			return fail()
		}
	}
	if err = s.verify(); err != nil {
		return fail()
	}
	return s, nil
}
func privateFile(path string, create, exclusive bool) (*os.File, error) {
	flags := unix.O_RDWR | unix.O_NOFOLLOW | unix.O_CLOEXEC
	if create {
		flags |= unix.O_CREAT
		if exclusive {
			flags |= unix.O_EXCL
		}
	}
	fd, err := unix.Open(path, flags, 0600)
	if err != nil {
		return nil, ErrUnavailable
	}
	file := os.NewFile(uintptr(fd), path)
	var info unix.Stat_t
	st, err := file.Stat()
	if err != nil || unix.Fstat(fd, &info) != nil || info.Uid != uint32(os.Geteuid()) || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 {
		file.Close()
		return nil, ErrUnavailable
	}
	return file, nil
}

// Admission and Close share a mutex so no WaitGroup.Add can race the drain.
// Operations remain admitted while waiting for a connection and until it closes.
func (s *Store) startOperation() error {
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()
	if s.closing {
		return ErrUnavailable
	}
	s.active.Add(1)
	return nil
}

func (s *Store) transaction(ctx context.Context, fn func(*sql.Conn) error) error {
	if err := s.startOperation(); err != nil {
		return err
	}
	defer s.active.Done()
	c, err := s.db.Conn(ctx)
	if err != nil {
		return ErrUnavailable
	}
	defer c.Close()
	if _, err = c.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return ErrUnavailable
	}
	defer c.ExecContext(context.Background(), "ROLLBACK")
	if err = fn(c); err != nil {
		return err
	}
	if _, err = c.ExecContext(ctx, "COMMIT"); err != nil {
		return ErrUnavailable
	}
	return nil
}

type querier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func decode(raw string, out any) error {
	if len(raw) > 65536 {
		return ErrUnavailable
	}
	d := json.NewDecoder(strings.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return ErrUnavailable
	}
	if d.Decode(new(any)) != io.EOF {
		return ErrUnavailable
	}
	return nil
}
func readSubject(ctx context.Context, q querier, ref SubjectRef) (Subject, string, error) {
	var raw, digest, state string
	err := q.QueryRowContext(ctx, "SELECT snapshot,digest,state FROM subjects WHERE workspace=? AND kind=? AND subject_id=? AND generation=?", ref.Workspace, ref.Kind, ref.ID, ref.Generation).Scan(&raw, &digest, &state)
	if errors.Is(err, sql.ErrNoRows) {
		return Subject{}, "", ErrNotFound
	}
	if err != nil {
		return Subject{}, "", ErrUnavailable
	}
	var subject Subject
	if decode(raw, &subject) != nil {
		return Subject{}, "", ErrUnavailable
	}
	got, err := subject.Reference()
	if err != nil || got.Workspace != ref.Workspace || got.Kind != ref.Kind || got.ID != ref.ID || got.Generation != ref.Generation || got.Digest != digest {
		return Subject{}, "", ErrUnavailable
	}
	if ref.Digest != digest {
		return Subject{}, "", ErrConflict
	}
	return subject, state, nil
}
func (s *Store) subject(ctx context.Context, ref SubjectRef) (Subject, string, error) {
	if err := s.startOperation(); err != nil {
		return Subject{}, "", err
	}
	defer s.active.Done()
	return readSubject(ctx, s.db, ref)
}
func (s *Store) RegisterSubject(ctx context.Context, subject Subject) (SubjectRef, error) {
	ref, err := subject.Reference()
	if err != nil {
		return SubjectRef{}, err
	}
	raw, err := json.Marshal(subject)
	if err != nil || len(raw) > 65536 {
		return SubjectRef{}, ErrInvalid
	}
	err = s.transaction(ctx, func(c *sql.Conn) error {
		_, _, err := readSubject(ctx, c, ref)
		if err == nil {
			return nil
		}
		if !errors.Is(err, ErrNotFound) {
			return err
		}
		var max uint64
		var open int
		if c.QueryRowContext(ctx, "SELECT coalesce(max(generation),0),coalesce(sum(state='open'),0) FROM subjects WHERE workspace=? AND kind=? AND subject_id=?", ref.Workspace, ref.Kind, ref.ID).Scan(&max, &open) != nil {
			return ErrUnavailable
		}
		if open != 0 || ref.Generation <= max {
			return ErrConflict
		}
		_, err = c.ExecContext(ctx, "INSERT INTO subjects VALUES(?,?,?,?,?,?,'open')", ref.Workspace, ref.Kind, ref.ID, ref.Generation, ref.Digest, string(raw))
		if err != nil {
			return ErrUnavailable
		}
		return nil
	})
	if err != nil {
		return SubjectRef{}, err
	}
	return ref, nil
}
func (s *Store) Supersede(ctx context.Context, ref SubjectRef) error {
	if !ref.valid() {
		return ErrInvalid
	}
	return s.transaction(ctx, func(c *sql.Conn) error {
		_, state, err := readSubject(ctx, c, ref)
		if err != nil {
			return err
		}
		if state == "superseded" {
			return nil
		}
		if state != "open" {
			return ErrConflict
		}
		_, err = c.ExecContext(ctx, "UPDATE subjects SET state='superseded' WHERE workspace=? AND kind=? AND subject_id=? AND generation=? AND state='open'", ref.Workspace, ref.Kind, ref.ID, ref.Generation)
		if err != nil {
			return ErrUnavailable
		}
		return nil
	})
}
func (s *Store) readRecord(ctx context.Context, q querier, actor api.CallerIdentity, workspace, key string) (DecisionRecord, error) {
	var raw, id, outcome string
	var kind Kind
	var subjectID string
	var generation uint64
	err := q.QueryRowContext(ctx, "SELECT record,record_id,outcome,kind,subject_id,generation FROM requests WHERE workspace=? AND issuer=? AND oid=? AND request_key=?", workspace, actor.Issuer, actor.Subject, key).Scan(&raw, &id, &outcome, &kind, &subjectID, &generation)
	if errors.Is(err, sql.ErrNoRows) {
		return DecisionRecord{}, ErrNotFound
	}
	if err != nil {
		return DecisionRecord{}, ErrUnavailable
	}
	var r DecisionRecord
	if decode(raw, &r) != nil {
		return DecisionRecord{}, ErrUnavailable
	}
	hash, err := r.Request.fingerprint()
	if err != nil || hash != r.RequestDigest || r.Actor != actor || r.ID != id || r.StoreID != s.id || r.HostLineageID != s.lineage || r.Request.Workspace != workspace || r.Request.Key != key || r.Request.Subject.Kind != kind || r.Request.Subject.ID != subjectID || r.Request.Subject.Generation != generation || r.Outcome != outcome || r.Mode != NonExecutingMode || r.CommittedAt.IsZero() {
		return DecisionRecord{}, ErrUnavailable
	}
	_, state, err := readSubject(ctx, q, r.Request.Subject)
	if err != nil {
		return DecisionRecord{}, ErrUnavailable
	}
	if r.Outcome == "recorded" {
		if state != "decided" || r.RefusalCode != "" || r.Authorization == nil || !validAction(kind, r.Request.Action) || !r.Authorization.valid(actor, r.Request.Subject, r.Request.Action, []string{r.Authorization.Role}) {
			return DecisionRecord{}, ErrUnavailable
		}
	} else if r.Outcome != "refused" || r.Authorization != nil || !refusalCode(r.RefusalCode) {
		return DecisionRecord{}, ErrUnavailable
	}
	return r, nil
}
func refusalCode(s string) bool {
	switch s {
	case "policy_denied", "subject_closed", "subject_expired", "invalid_action":
		return true
	}
	return false
}
func (s *Store) lookup(ctx context.Context, a api.CallerIdentity, w, k string) (DecisionRecord, error) {
	if err := s.startOperation(); err != nil {
		return DecisionRecord{}, err
	}
	defer s.active.Done()
	return s.readRecord(ctx, s.db, a, w, k)
}
func (s *Store) commit(ctx context.Context, actor api.CallerIdentity, validUntil time.Time, r DecideRequest, auth *Authorization, refusal string) (DecisionRecord, error) {
	hash, err := r.fingerprint()
	if err != nil {
		return DecisionRecord{}, err
	}
	if !actor.Valid() || (!refusalCode(refusal) && refusal != "") || (auth == nil && refusal == "") {
		return DecisionRecord{}, ErrInvalid
	}
	var result DecisionRecord
	err = s.transaction(ctx, func(c *sql.Conn) error {
		if !s.now().Before(validUntil) {
			return ErrUnauthenticated
		}
		old, err := s.readRecord(ctx, c, actor, r.Workspace, r.Key)
		if err == nil {
			if old.RequestDigest != hash {
				return ErrConflict
			}
			result = old
			return nil
		}
		if !errors.Is(err, ErrNotFound) {
			return err
		}
		subject, state, err := readSubject(ctx, c, r.Subject)
		if err != nil {
			return err
		}
		code := refusal
		if !validAction(subject.Kind, r.Action) {
			code = "invalid_action"
		} else if state != "open" {
			code = "subject_closed"
		} else if !s.now().Before(subject.ExpiresAt) {
			code = "subject_expired"
		}
		result = DecisionRecord{ID: randomID(), StoreID: s.id, HostLineageID: s.lineage, Request: r, RequestDigest: hash, Actor: actor, Outcome: "refused", RefusalCode: code, CommittedAt: s.now().UTC(), Mode: NonExecutingMode}
		if result.ID == "" {
			return ErrUnavailable
		}
		if code == "" {
			if auth == nil || !auth.valid(actor, r.Subject, r.Action, []string{auth.Role}) {
				return ErrDenied
			}
			result.Outcome = "recorded"
			copyAuth := *auth
			copyAuth.GrantIDs = append([]string(nil), auth.GrantIDs...)
			result.Authorization = &copyAuth
			res, err := c.ExecContext(ctx, "UPDATE subjects SET state='decided' WHERE workspace=? AND kind=? AND subject_id=? AND generation=? AND state='open'", r.Workspace, r.Subject.Kind, r.Subject.ID, r.Subject.Generation)
			if err != nil {
				return ErrUnavailable
			}
			n, err := res.RowsAffected()
			if err != nil || n != 1 {
				return ErrConflict
			}
		}
		raw, err := json.Marshal(result)
		if err != nil || len(raw) > 65536 {
			return ErrUnavailable
		}
		if _, err = c.ExecContext(ctx, "INSERT INTO requests VALUES(?,?,?,?,?,?,?,?,?,?)", r.Workspace, actor.Issuer, actor.Subject, r.Key, r.Subject.Kind, r.Subject.ID, r.Subject.Generation, result.ID, result.Outcome, string(raw)); err != nil {
			return ErrUnavailable
		}
		// This check is after policy and SQLite lock waits and immediately precedes
		// COMMIT. Expiry aborts the entire transaction, including the subject CAS.
		commitTime := s.now()
		if !commitTime.Before(validUntil) {
			return ErrUnauthenticated
		}
		if result.Outcome == "recorded" && !commitTime.Before(subject.ExpiresAt) {
			return ErrConflict
		}
		return nil
	})
	if err != nil {
		return DecisionRecord{}, err
	}
	out, err := s.lookup(ctx, actor, r.Workspace, r.Key)
	if err != nil {
		return DecisionRecord{}, ErrUnavailable
	}
	return out, nil
}

// verify runs only during construction, before the Store can be shared or closed.
func (s *Store) verify() error {
	ctx := context.Background()
	var version, count int
	var id, lineage string
	if s.db.QueryRow("PRAGMA user_version").Scan(&version) != nil || version != 1 {
		return ErrUnavailable
	}
	if s.db.QueryRow("SELECT count(*) FROM metadata").Scan(&count) != nil || count != 1 {
		return ErrUnavailable
	}
	if s.db.QueryRow("SELECT schema_version,store_id,lineage FROM metadata WHERE id=1").Scan(&version, &id, &lineage) != nil || version != 1 || id != s.id || lineage != s.lineage {
		return ErrUnavailable
	}
	var integrity string
	if s.db.QueryRow("PRAGMA integrity_check").Scan(&integrity) != nil || integrity != "ok" {
		return ErrUnavailable
	}
	rows, err := s.db.Query("PRAGMA foreign_key_check")
	if err != nil {
		return ErrUnavailable
	}
	bad := rows.Next()
	err = rows.Err()
	rows.Close()
	if bad || err != nil {
		return ErrUnavailable
	}
	rows, err = s.db.Query("SELECT workspace,kind,subject_id,generation,digest,state FROM subjects")
	if err != nil {
		return ErrUnavailable
	}
	type entry struct {
		ref   SubjectRef
		state string
	}
	var subjects []entry
	for rows.Next() {
		var e entry
		if rows.Scan(&e.ref.Workspace, &e.ref.Kind, &e.ref.ID, &e.ref.Generation, &e.ref.Digest, &e.state) != nil {
			rows.Close()
			return ErrUnavailable
		}
		subjects = append(subjects, e)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return ErrUnavailable
	}
	for _, e := range subjects {
		if !e.ref.valid() {
			return ErrUnavailable
		}
		if _, _, err := s.subject(ctx, e.ref); err != nil {
			return ErrUnavailable
		}
		if s.db.QueryRow("SELECT count(*) FROM requests WHERE workspace=? AND kind=? AND subject_id=? AND generation=? AND outcome='recorded'", e.ref.Workspace, e.ref.Kind, e.ref.ID, e.ref.Generation).Scan(&count) != nil {
			return ErrUnavailable
		}
		if (e.state == "decided" && count != 1) || (e.state != "decided" && count != 0) || (e.state != "open" && e.state != "decided" && e.state != "superseded") {
			return ErrUnavailable
		}
	}
	rows, err = s.db.Query("SELECT workspace,issuer,oid,request_key FROM requests")
	if err != nil {
		return ErrUnavailable
	}
	type lookup struct {
		w, k string
		a    api.CallerIdentity
	}
	var lookups []lookup
	for rows.Next() {
		var r lookup
		if rows.Scan(&r.w, &r.a.Issuer, &r.a.Subject, &r.k) != nil {
			rows.Close()
			return ErrUnavailable
		}
		lookups = append(lookups, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return ErrUnavailable
	}
	for _, r := range lookups {
		if _, err := s.lookup(ctx, r.a, r.w, r.k); err != nil {
			return ErrUnavailable
		}
	}
	return nil
}
