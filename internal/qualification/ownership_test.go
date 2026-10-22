package qualification

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPrivatePathsRequireCurrentOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("cross-UID integration requires root; exercised in isolated root container")
	}
	for _, name := range []string{".", "evidence", "lock", "lineage", "records.db"} {
		t.Run(name, func(t *testing.T) {
			s, dir := testStore(t)
			lineage := s.Lineage()
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, name)
			if err := os.Chown(path, 1, -1); err != nil {
				t.Fatal(err)
			}
			reopened, err := Open(dir, lineage)
			if reopened != nil {
				reopened.Close()
			}
			if !errors.Is(err, ErrIntegrity) {
				t.Fatalf("accepted foreign-owned %s: %v", name, err)
			}
		})
	}
	t.Run("creation parent", func(t *testing.T) {
		parent := privateTestDir(t)
		if err := os.Chown(parent, 1, -1); err != nil {
			t.Fatal(err)
		}
		s, err := Create(filepath.Join(parent, "store"))
		if s != nil {
			s.Close()
		}
		if !errors.Is(err, ErrIntegrity) {
			t.Fatalf("accepted foreign-owned parent: %v", err)
		}
	})
}
func TestPrivateFixtureResolvesSymlinkedTempRoot(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.Mkdir(real, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", link)
	t.Run("fixture", func(t *testing.T) {
		dir := privateTestDir(t)
		resolved, err := filepath.EvalSymlinks(dir)
		if err != nil {
			t.Fatal(err)
		}
		if dir != resolved {
			t.Fatalf("fixture has symlink ancestor: %s", dir)
		}
		s, err := Create(filepath.Join(dir, "store"))
		if err != nil {
			t.Fatal(err)
		}
		s.Close()
	})
}
