package qualification

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPrivatePathsRequireCurrentOwner(t *testing.T) {
	for _, name := range []string{".", "evidence", "lock", "lineage", "records.db"} {
		t.Run(name, func(t *testing.T) {
			s, dir := testStore(t)
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			original := geteuid
			geteuid = func() int { return original() + 1 }
			t.Cleanup(func() { geteuid = original })
			path := filepath.Join(dir, name)
			var err error
			if name == "." || name == "evidence" {
				err = privateDir(path)
			} else {
				var file *os.File
				file, err = privateFile(path, false)
				if file != nil {
					file.Close()
				}
			}
			if !errors.Is(err, ErrIntegrity) {
				t.Fatalf("accepted foreign-owned %s: %v", name, err)
			}
		})
	}
	t.Run("creation parent", func(t *testing.T) {
		parent := privateTestDir(t)
		original := geteuid
		geteuid = func() int { return original() + 1 }
		t.Cleanup(func() { geteuid = original })
		dir := filepath.Join(parent, "store")
		s, err := Create(dir)
		if s != nil {
			s.Close()
		}
		if !errors.Is(err, ErrIntegrity) {
			t.Fatalf("accepted foreign-owned parent: %v", err)
		}
		if _, err = os.Lstat(dir); !os.IsNotExist(err) {
			t.Fatalf("initialized state under refused parent: %v", err)
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
