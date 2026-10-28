package qualification

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
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	_ "modernc.org/sqlite"
)

type Store struct {
	mu           sync.Mutex
	db           *sql.DB
	lock         *os.File
	dir, lineage string
	active       map[string]*runJob
	closing      bool
	closeDone    chan struct{}
	closeErr     error
}

// Serial tests override these seams; production uses the real identity and sync.
var (
	geteuid = os.Geteuid
	syncDir = syncDirectory
)

func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}
func currentOwner(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uint32(geteuid())
}
func privateDir(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrIntegrity
	}
	for cur := path; ; cur = filepath.Dir(cur) {
		st, err := os.Lstat(cur)
		if err != nil {
			return fileError(err)
		}
		if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return ErrIntegrity
		}
		if cur == path && (st.Mode().Perm() != 0700 || !currentOwner(st)) {
			return ErrIntegrity
		}
		if cur == filepath.Dir(cur) {
			return nil
		}
	}
}
func privateFile(path string, create bool) (*os.File, error) {
	flags := unix.O_RDWR | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
	if create {
		flags |= unix.O_CREAT | unix.O_EXCL
	}
	fd, err := unix.Open(path, flags, 0600)
	if err != nil {
		return nil, fileError(err)
	}
	f := os.NewFile(uintptr(fd), path)
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fileError(err)
	}
	if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || !currentOwner(st) {
		f.Close()
		return nil, ErrIntegrity
	}
	return f, nil
}
func syncDirectory(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return fileError(err)
	}
	err = f.Sync()
	closeErr := f.Close()
	if err != nil {
		return fileError(err)
	}
	return fileError(closeErr)
}
func dbURI(path string, readonly bool) string {
	u := url.URL{Scheme: "file", Path: path}
	q := url.Values{}
	if readonly {
		q.Set("mode", "ro")
	} else {
		q.Set("mode", "rw")
		q.Add("_pragma", "synchronous(EXTRA)")
		q.Add("_pragma", "journal_mode(DELETE)")
		q.Add("_pragma", "busy_timeout(5000)")
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// Create exclusively initializes a new private root. A partial failed creation
// is deliberately not adoptable by Open and is never automatically removed.
func Create(dir string) (*Store, error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return nil, ErrIntegrity
	}
	if err := privateDir(filepath.Dir(dir)); err != nil {
		return nil, err
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		return nil, fileError(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "evidence"), 0700); err != nil {
		return nil, fileError(err)
	}
	id := newID()
	for _, item := range []struct{ name, data string }{{"lock", ""}, {"lineage", id}, {"records.db", ""}} {
		f, err := privateFile(filepath.Join(dir, item.name), true)
		if err != nil {
			return nil, err
		}
		_, err = f.WriteString(item.data)
		if err == nil {
			err = f.Sync()
		}
		f.Close()
		if err != nil {
			return nil, fileError(err)
		}
	}
	s, err := lockStore(dir, id)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = s.Close()
		}
	}()
	s.db, err = sql.Open("sqlite", dbURI(filepath.Join(dir, "records.db"), false))
	if err != nil {
		return nil, databaseError(err)
	}
	s.db.SetMaxOpenConns(1)
	_, err = s.db.Exec(`BEGIN IMMEDIATE;
 CREATE TABLE metadata(version INTEGER NOT NULL,lineage TEXT NOT NULL);
 CREATE TABLE records(id TEXT PRIMARY KEY,workspace TEXT NOT NULL,target TEXT NOT NULL,request_key TEXT NOT NULL,body BLOB NOT NULL,UNIQUE(workspace,target,request_key));`)
	if err == nil {
		_, err = s.db.Exec("INSERT INTO metadata VALUES(1,?)", id)
	}
	if err == nil {
		_, err = s.db.Exec("COMMIT")
	}
	if err != nil {
		return nil, databaseError(err)
	}
	if err = syncDir(dir); err != nil {
		return nil, err
	}
	if err = syncDir(filepath.Dir(dir)); err != nil {
		return nil, err
	}
	return s, nil
}
func lockStore(dir, lineage string) (*Store, error) {
	if err := privateDir(dir); err != nil {
		return nil, err
	}
	if err := privateDir(filepath.Join(dir, "evidence")); err != nil {
		return nil, err
	}
	f, err := privateFile(filepath.Join(dir, "lock"), false)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrBusy
		}
		return nil, fileError(err)
	}
	return &Store{dir: dir, lineage: lineage, lock: f}, nil
}

// Open never initializes absent state. lineage must come from independently
// retained host configuration, not be inferred from the files being opened.
func Open(dir, lineage string) (_ *Store, err error) {
	if !validID(lineage) {
		return nil, ErrIntegrity
	}
	s, err := lockStore(dir, lineage)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = s.Close()
		}
	}()
	for _, name := range []string{"lineage", "records.db", "records.db-journal", "records.db-wal", "records.db-shm"} {
		path := filepath.Join(dir, name)
		if _, e := os.Lstat(path); os.IsNotExist(e) && name != "lineage" && name != "records.db" {
			continue
		} else if e != nil {
			return nil, fileError(e)
		} else if name == "records.db-wal" || name == "records.db-shm" {
			// DELETE-mode storage never owns WAL sidecars, even empty/private
			// ones; leave the entire recovery set untouched for inspection.
			return nil, ErrIntegrity
		}
		f, e := privateFile(path, false)
		if e != nil {
			return nil, e
		}
		st, e := f.Stat()
		if e != nil {
			f.Close()
			return nil, fileError(e)
		}
		if st.Size() == 0 && name == "records.db" {
			f.Close()
			return nil, ErrIntegrity
		}
		if name == "records.db" {
			// Even mode=ro can create WAL/SHM sidecars. Require the rollback
			// format before SQLite can touch the unverified recovery set.
			var header [20]byte
			if _, e = io.ReadFull(f, header[:]); e != nil {
				f.Close()
				return nil, fileError(e)
			}
			if string(header[:16]) != "SQLite format 3\x00" || header[18] != 1 || header[19] != 1 {
				f.Close()
				return nil, ErrIntegrity
			}
		}
		if name == "lineage" {
			data := make([]byte, 129)
			n, readErr := f.Read(data)
			if readErr != nil {
				f.Close()
				return nil, fileError(readErr)
			}
			if string(data[:n]) != lineage {
				f.Close()
				return nil, ErrIntegrity
			}
		}
		if e = f.Close(); e != nil {
			return nil, fileError(e)
		}
	}
	// Verify identity before journal_mode or any other writable PRAGMA.
	ro, e := sql.Open("sqlite", dbURI(filepath.Join(dir, "records.db"), true))
	if e != nil {
		return nil, databaseError(e)
	}
	var rawCount, rawVersion, rawLineage any
	e = ro.QueryRow("SELECT count(*),version,lineage FROM metadata").Scan(&rawCount, &rawVersion, &rawLineage)
	closeErr := ro.Close()
	if e != nil {
		return nil, databaseError(e)
	}
	if closeErr != nil {
		return nil, databaseError(closeErr)
	}
	count, countOK := rawCount.(int64)
	version, versionOK := rawVersion.(int64)
	saved, lineageOK := rawLineage.(string)
	if !countOK || !versionOK || !lineageOK || count != 1 || version != 1 || saved != lineage {
		return nil, ErrIntegrity
	}
	s.db, err = sql.Open("sqlite", dbURI(filepath.Join(dir, "records.db"), false))
	if err != nil {
		return nil, databaseError(err)
	}
	s.db.SetMaxOpenConns(1)
	rows, e := s.db.Query("SELECT id,workspace,target,request_key,CASE WHEN length(body)<=? THEN body ELSE NULL END FROM records", maxRecordBytes)
	if e != nil {
		return nil, databaseError(e)
	}
	for rows.Next() {
		var b []byte
		var r Record
		var id, workspace, target, key string
		if rows.Scan(&id, &workspace, &target, &key, &b) != nil || strictJSON(b, &r) != nil || checkRecord(r, lineage) != nil || r.ID != id || r.Request.Plan.Subject.Workspace != workspace || r.Request.Plan.Subject.Target != target || r.Request.Key != key {
			rows.Close()
			return nil, ErrIntegrity
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, databaseError(e)
	}
	return s, nil
}
func (s *Store) Lineage() string { return s.lineage }

// Close cancels and drains active Run calls before releasing storage ownership.
func (s *Store) Close() error {
	s.mu.Lock()
	if s.closeDone != nil {
		done := s.closeDone
		s.mu.Unlock()
		<-done
		return s.closeErr
	}
	s.closing = true
	s.closeDone = make(chan struct{})
	jobs := make([]*runJob, 0, len(s.active))
	for _, job := range s.active {
		jobs = append(jobs, job)
	}
	s.mu.Unlock()
	for _, job := range jobs {
		job.cancel()
	}
	for _, job := range jobs {
		<-job.done
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	defer close(s.closeDone)
	var err error
	if s.db != nil {
		err = s.db.Close()
		s.db = nil
	}
	if s.lock != nil {
		_ = unix.Flock(int(s.lock.Fd()), unix.LOCK_UN)
		if e := s.lock.Close(); err == nil {
			err = e
		}
		s.lock = nil
	}
	if err != nil {
		s.closeErr = ErrUnavailable
	}
	return s.closeErr
}
func (s *Store) read(ctx context.Context, id string) (Record, error) {
	var r Record
	var rawWorkspace, rawTarget, rawKey, rawBody any
	if s.db == nil {
		return r, ErrUnavailable
	}
	if err := s.db.QueryRowContext(ctx, "SELECT workspace,target,request_key,CASE WHEN length(body)<=? THEN body ELSE NULL END FROM records WHERE id=?", maxRecordBytes, id).Scan(&rawWorkspace, &rawTarget, &rawKey, &rawBody); err != nil {
		if ctx.Err() != nil {
			return r, ctx.Err()
		}
		return r, databaseError(err)
	}
	workspace, workspaceOK := rawWorkspace.(string)
	target, targetOK := rawTarget.(string)
	key, keyOK := rawKey.(string)
	b, bodyOK := rawBody.([]byte)
	if !workspaceOK || !targetOK || !keyOK || !bodyOK || strictJSON(b, &r) != nil || r.ID != id || checkRecord(r, s.lineage) != nil || r.Request.Plan.Subject.Workspace != workspace || r.Request.Plan.Subject.Target != target || r.Request.Key != key {
		return Record{}, ErrIntegrity
	}
	return r, nil
}
func (s *Store) Read(ctx context.Context, id string) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.read(ctx, id)
}
func (s *Store) save(ctx context.Context, r Record, insert bool) error {
	seal(&r)
	b, err := json.Marshal(r)
	if err != nil || len(b) > maxRecordBytes || checkRecord(r, s.lineage) != nil {
		return ErrInvalid
	}
	if insert {
		_, err = s.db.ExecContext(ctx, "INSERT INTO records(id,workspace,target,request_key,body) VALUES(?,?,?,?,?)", r.ID, r.Request.Plan.Subject.Workspace, r.Request.Plan.Subject.Target, r.Request.Key, b)
	} else {
		_, err = s.db.ExecContext(ctx, "UPDATE records SET body=? WHERE id=?", b, r.ID)
	}
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return databaseError(err)
	}
	return nil
}
func (s *Store) transaction(ctx context.Context, fn func() error) error {
	if s.db == nil {
		return ErrUnavailable
	}
	if _, err := s.db.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return databaseError(err)
	}
	defer s.db.ExecContext(context.Background(), "ROLLBACK") // also releases a transaction after cancellation
	if err := fn(); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, "COMMIT"); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return databaseError(err)
	}
	return nil
}
func (s *Store) Admit(ctx context.Context, req Request) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	req = normalize(req)
	if validateRequest(req) != nil {
		return Record{}, ErrInvalid
	}
	var result Record
	err := s.transaction(ctx, func() error {
		var rawID any
		e := s.db.QueryRowContext(ctx, "SELECT id FROM records WHERE workspace=? AND target=? AND request_key=?", req.Plan.Subject.Workspace, req.Plan.Subject.Target, req.Key).Scan(&rawID)
		if e == nil {
			id, ok := rawID.(string)
			if !ok {
				return ErrIntegrity
			}
			r, err := s.read(ctx, id)
			if err != nil {
				return err
			}
			if r.RequestDigest != objectDigest("qualification-request-v1", req) {
				return ErrConflict
			}
			result = r
			return nil
		}
		if !errors.Is(e, sql.ErrNoRows) {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return databaseError(e)
		}
		if !req.Plan.ExpiresAt.After(time.Now()) {
			return ErrInvalid
		}
		result = Record{ID: newID(), Lineage: s.lineage, Request: req, RequestDigest: objectDigest("qualification-request-v1", req), PlanDigest: objectDigest("qualification-plan-v1", req.Plan), State: Admitted}
		seal(&result)
		return s.save(ctx, result, true)
	})
	return result, err
}
func (s *Store) start(ctx context.Context, id string) (lease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var l lease
	err := s.transaction(ctx, func() error {
		r, e := s.read(ctx, id)
		if e != nil {
			return e
		}
		if r.State != Admitted {
			return ErrConflict
		}
		r.State = Running
		r.Generation++
		l = lease{r.ID, r.Generation}
		return s.save(ctx, r, false)
	})
	return l, err
}
func (s *Store) interrupt(ctx context.Context, l lease) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result Record
	err := s.transaction(ctx, func() error {
		r, e := s.read(ctx, l.ID)
		if e != nil {
			return e
		}
		if r.State == Incomplete && r.Reason == "interrupted" && r.Generation == l.Generation+1 {
			result = r
			return nil
		}
		if r.Generation != l.Generation || (r.State != Running && r.State != Verifying) {
			return ErrConflict
		}
		r.Generation++
		r.State = Incomplete
		r.Reason = "interrupted"
		r.CompletedAt = time.Now().UTC()
		seal(&r)
		result = r
		return s.save(ctx, r, false)
	})
	return result, err
}
