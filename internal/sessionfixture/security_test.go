package sessionfixture

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// Neither whitespace-only/control identities nor symlink ancestors may select
// an effect identity or cause creation outside the configured private directory.
func TestIdentityAndSymlinkAncestorsFailBeforeMutation(t *testing.T) {
	ex, err := newExecutor(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer ex.close()
	for _, uid := range []string{" ", "session\x01", " session", "session "} {
		if _, err = ex.execute(t.Context(), toolScope(uid), publication()); err == nil {
			t.Errorf("unsafe identity accepted: %q", uid)
		}
	}
	outside := privateTempDir(t)
	link := filepath.Join(privateTempDir(t), "symlink")
	if err = os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if _, err = newExecutor(filepath.Join(link, "created")); err == nil {
		t.Fatal("symlink ancestor accepted")
	}
	if _, err = os.Lstat(filepath.Join(outside, "created")); !os.IsNotExist(err) {
		t.Fatalf("refused path mutated outside root: %v", err)
	}
}

func TestExecutorAtomicRollbackAndCrossInstanceConcurrency(t *testing.T) {
	dir := privateTempDir(t)
	first, err := newExecutor(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer first.close()
	second, err := newExecutor(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer second.close()
	if _, err = first.db.Exec(`CREATE TRIGGER fail_receipt BEFORE INSERT ON receipts BEGIN SELECT RAISE(ABORT,'injected receipt failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err = first.execute(t.Context(), toolScope("atomic"), publication()); err == nil {
		t.Fatal("injected transaction did not fail")
	}
	p, r, err := first.counts()
	if err != nil || p != 0 || r != 0 {
		t.Fatalf("orphaned effect: %d %d %v", p, r, err)
	}
	if _, err = first.db.Exec("DROP TRIGGER fail_receipt"); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := range 24 {
		wg.Go(func() {
			ex := first
			if i%2 == 0 {
				ex = second
			}
			uid := "session-one"
			if i%3 == 0 {
				uid = "session-two"
			}
			if _, err := ex.execute(t.Context(), toolScope(uid), publication()); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	p, r, err = first.counts()
	if err != nil || p != 2 || r != 2 {
		t.Fatalf("cross-process-capable tuple dedup: %d %d %v", p, r, err)
	}
}
