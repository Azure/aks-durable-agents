package qualification

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPrivateFixtureUmask(t *testing.T) {
	if raw := os.Getenv("QUALIFICATION_FIXTURE_UMASK"); raw != "" {
		mask, err := strconv.Atoi(raw)
		if err != nil {
			t.Fatal(err)
		}
		// Umask is process-global: change it only inside this dedicated subprocess.
		unix.Umask(mask)
		ambient := t.TempDir()
		st, err := os.Stat(ambient)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("uid=%d gid=%d umask=%04o testing.TempDir=%04o owner=%d", os.Geteuid(), os.Getegid(), mask, st.Mode().Perm(), st.Sys().(*syscall.Stat_t).Uid)
		s, dir := testStore(t)
		for _, entry := range []struct {
			path string
			mode os.FileMode
		}{{filepath.Dir(dir), 0700}, {dir, 0700}, {filepath.Join(dir, "evidence"), 0700}, {filepath.Join(dir, "lock"), 0600}, {filepath.Join(dir, "lineage"), 0600}, {filepath.Join(dir, "records.db"), 0600}} {
			st, err := os.Stat(entry.path)
			if err != nil {
				t.Fatal(err)
			}
			if st.Mode().Perm() != entry.mode || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
				t.Fatalf("fixture mode/owner: %s mode=%04o uid=%d", entry.path, st.Mode().Perm(), st.Sys().(*syscall.Stat_t).Uid)
			}
		}
		lineage := s.Lineage()
		if err = s.Close(); err != nil {
			t.Fatal(err)
		}
		s, err = Open(dir, lineage)
		if err != nil {
			t.Fatal(err)
		}
		if err = s.Close(); err != nil {
			t.Fatal(err)
		}
		return
	}
	for _, mask := range []int{0022, 0002, 0077} {
		t.Run(fmt.Sprintf("%04o", mask), func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestPrivateFixtureUmask$", "-test.v")
			cmd.Env = append(os.Environ(), "QUALIFICATION_FIXTURE_UMASK="+strconv.Itoa(mask))
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("fixture under umask %04o: %v\n%s", mask, err, output)
			}
			t.Logf("%s", output)
		})
	}
}

func TestCreateRefusesNonPrivateParent(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0755); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(parent, "qualification")
	if _, err := Create(dir); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("nonprivate parent: %v", err)
	}
	st, err := os.Stat(parent)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0755 {
		t.Fatal("Create changed the operator's parent permissions")
	}
	if _, err = os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatalf("Create initialized state under refused parent: %v", err)
	}
}
