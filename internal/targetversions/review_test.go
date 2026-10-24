package targetversions

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestUnknownReferencesAreConflicts(t *testing.T) {
	s, _ := newStore(t)
	_, err := s.Begin(ctx, request(Target{ID: "missing", GenesisID: "genesis", Revision: 1}, "missing"))
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("unknown target: %v", err)
	}
	_, err = s.StartAbort(ctx, Step{"missing", 1, 1}, "cancel")
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("unknown operation: %v", err)
	}
	if _, err = s.ReadTarget(ctx, "missing"); !errors.Is(err, ErrConflict) {
		t.Fatalf("read target: %v", err)
	}
	if _, err = s.ReadOperation(ctx, "missing"); !errors.Is(err, ErrConflict) {
		t.Fatalf("read operation: %v", err)
	}
}

func TestSourceReadFailureIsIntegrity(t *testing.T) {
	for _, terminalSource := range []bool{false, true} {
		t.Run(fmt.Sprint(terminalSource), func(t *testing.T) {
			s, _ := newStore(t)
			_, o := pendingWithPredecessor(t, s)
			var r Request
			var table string
			if terminalSource {
				o = abandonFinish(t, s, abandonStart(t, s, o, "abandon"))
				r = recoveryRequest(t, s, o, "recover")
				table = "abandonments"
			} else {
				o = retired(t, s, o)
				v, err := s.Commit(ctx, step(o), receipt(s, o, "commit"))
				_ = must(t, v, err)
				r = activeRequest(t, s, "agent", "next")
				table = "versions"
			}
			if _, err := s.db.Exec("DROP TABLE " + table); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Begin(ctx, r); !errors.Is(err, ErrIntegrity) || errors.Is(err, ErrConflict) {
				t.Fatalf("lost source read failure: %v", err)
			}
		})
	}
}

func TestBusyVerificationDoesNotLatchCorruption(t *testing.T) {
	s, p := newStore(t)
	other, err := Open(p, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err = other.db.Exec("PRAGMA busy_timeout=0"); err != nil {
		t.Fatal(err)
	}
	err = s.transact(ctx, func(q query) error {
		e := other.Verify(ctx)
		if !errors.Is(e, ErrBusy) || errors.Is(e, ErrIntegrity) {
			t.Errorf("busy is not corruption: %v", e)
		}
		if other.bad.Load() {
			t.Error("busy verification permanently fenced handle")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = other.RegisterTarget(ctx, "after-contention"); err != nil {
		t.Fatal("handle unusable after contention", err)
	}
}

func TestCommitBindingMismatchIsConflict(t *testing.T) {
	s, _ := newStore(t)
	o := retired(t, s, reserved(t, s, prepared(t, s, begin(t, s, request(register(t, s, "agent"), "a")))))
	for _, field := range []string{"fence", "context"} {
		r := receipt(s, o, "commit")
		if field == "fence" {
			r.FenceDigest = strings.Repeat("b", 64)
		} else {
			r.ContextDigest = strings.Repeat("b", 64)
		}
		if _, err := s.Commit(ctx, step(o), r); !errors.Is(err, ErrConflict) {
			t.Fatalf("%s mismatch: %v", field, err)
		}
	}
	if _, err := s.Commit(ctx, step(o), receipt(s, o, "commit")); err != nil {
		t.Fatal(err)
	}
}

func TestReserveOperationBinding(t *testing.T) {
	s, _ := newStore(t)
	o := prepared(t, s, begin(t, s, request(register(t, s, "agent"), "a")))
	for name, mutate := range map[string]func(*AuthorizationSnapshot){
		"operation":  func(a *AuthorizationSnapshot) { a.OperationID = "other" },
		"generation": func(a *AuthorizationSnapshot) { a.Generation++ },
		"revision":   func(a *AuthorizationSnapshot) { a.OperationRevision++ },
		"phase":      func(a *AuthorizationSnapshot) { a.Phase = "committed" },
	} {
		t.Run(name, func(t *testing.T) {
			a := authority(s, o)
			mutate(&a)
			if _, err := s.Reserve(ctx, step(o), a); !errors.Is(err, ErrConflict) {
				t.Fatalf("binding: %v", err)
			}
		})
	}
}

// A plain descriptor close on an existing DB inode drops the process's POSIX
// locks, even when the original descriptor is still open. Path validation must
// not perform that close while another handle is inside a SQLite transaction.
func TestExistingPathValidationPreservesLocks(t *testing.T) {
	s, p := newStore(t)
	_ = s
	fd, err := unix.Open(p, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	lock := unix.Flock_t{Type: unix.F_WRLCK, Whence: 0, Start: 0, Len: 1}
	if err = unix.FcntlFlock(uintptr(fd), unix.F_SETLK, &lock); err != nil {
		t.Fatal(err)
	}
	if err = privatePath(p, false); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestPathLockProbe$")
	cmd.Env = append(os.Environ(), "TARGETVERSIONS_LOCK_PROBE="+p)
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains("\n"+string(out), "\nLOCKED\n") {
		t.Fatalf("validation released another handle's lock: %s (%v)", out, err)
	}
}
func TestPathLockProbe(t *testing.T) {
	p := os.Getenv("TARGETVERSIONS_LOCK_PROBE")
	if p == "" {
		return
	}
	fd, err := unix.Open(p, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	lock := unix.Flock_t{Type: unix.F_WRLCK, Whence: 0, Start: 0, Len: 1}
	err = unix.FcntlFlock(uintptr(fd), unix.F_SETLK, &lock)
	if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EACCES) {
		fmt.Println("LOCKED")
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("UNLOCKED")
}
