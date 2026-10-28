package githubtools

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	_ "modernc.org/sqlite"
)

type Store struct {
	db                         *sql.DB
	file                       *os.File // separate lifetime lock file; never unlink while in use.
	path, id, lineage, binding string
	now                        func() time.Time
	lifecycle                  sync.Mutex
	closing                    bool
	active                     sync.WaitGroup
	closeOnce                  sync.Once
	closeErr                   error
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
func Initialize(path, hostLineageID, bindingDigest string) (*Store, error) {
	return openStore(path, "", hostLineageID, bindingDigest, true)
}

// Open never creates, repairs or migrates state. Expected identity must come
// from a separately retained recovery configuration, not this database itself.
func Open(path, expectedStoreID, hostLineageID, bindingDigest string) (*Store, error) {
	if !textOK(expectedStoreID, 256) {
		return nil, ErrInvalid
	}
	return openStore(path, expectedStoreID, hostLineageID, bindingDigest, false)
}
func openStore(path, id, lineage, binding string, create bool) (*Store, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || (!textOK(lineage, 256) || !digestOK(binding)) {
		return nil, ErrInvalid
	}
	parent := filepath.Dir(path)
	if create {
		err := os.Mkdir(parent, 0700)
		if err != nil && !os.IsExist(err) {
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
	// Persist the parent entry even if a previous or concurrent initializer
	// created it. Validate ancestors first; never sync through a symlink.
	if create && syncDirectory(filepath.Dir(parent)) != nil {
		return nil, ErrUnavailable
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
		if syncDirectory(parent) != nil {
			return failFile()
		}
	}
	if file.Close() != nil {
		lock.Close()
		return nil, ErrUnavailable
	}
	u := url.URL{Scheme: "file", Path: path}
	q := url.Values{}
	for _, p := range []string{"busy_timeout(5000)", "journal_mode(DELETE)", "synchronous(EXTRA)", "foreign_keys(1)"} {
		q.Add("_pragma", p)
	}
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return failFile()
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, file: lock, path: path, id: id, lineage: lineage, binding: binding, now: time.Now}
	fail := func() (*Store, error) { s.Close(); return nil, ErrUnavailable }
	if create {
		s.id = randomID()
		if s.id == "" {
			return fail()
		}
		err = s.transaction(context.Background(), func(c *sql.Conn) error {
			if err := createSchema(context.Background(), c); err != nil {
				return err
			}
			_, err := c.ExecContext(context.Background(), "INSERT INTO metadata VALUES(1,1,?,?,?)", s.id, lineage, binding)
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
func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return ErrUnavailable
	}
	err = dir.Sync()
	closeErr := dir.Close()
	if err != nil || closeErr != nil {
		return ErrUnavailable
	}
	return nil
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
