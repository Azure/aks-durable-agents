package sessionfixture

import (
	"os"
	"testing"
)

func privateTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	// Fixture state has stricter permissions than testing.T's temporary dirs.
	// Normalize only this test-owned directory, never caller/retained data.
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}
