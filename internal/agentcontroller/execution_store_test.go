package agentcontroller

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Azure/aks-durable-agents/internal/qualification"
	"github.com/agent-primitives/sessions/sqlitelog"
)

func durableConfig(t *testing.T, f *executionFixture) (qualification.ExecutionScope, DurableExecutionConfig) {
	t.Helper()
	return qualification.ExecutionScope{RunID: "sha256:" + strings.Repeat("a", 64), PlanDigest: f.budget.Config.PlanDigest}, DurableExecutionConfig{Directory: filepath.Join(t.TempDir(), "run?literal#%25"), Pricing: f.budget.Config.Bindings[0].Pricing, Credential: f.credential, Transport: f.config.Transport}
}

func TestDurableCandidateOwnership(t *testing.T) {
	f := newExecutionFixture(t, nil)
	scope, c := durableConfig(t, f)
	if err := os.Chmod(filepath.Dir(c.Directory), 0700); err != nil {
		t.Fatal(err)
	}
	x, err := NewDurableCandidateExecutor(f.pkg, f.expected, scope, c)
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	if f.sends.Load() != 0 || f.credential.calls.Load() != 0 {
		t.Fatal("construction dispatched")
	}
	before, err := os.ReadFile(filepath.Join(c.Directory, "scope.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Version  int
		Scope    qualification.ExecutionScope
		Info     qualification.ExecutionInfo
		Snapshot json.RawMessage
	}
	if json.Unmarshal(before, &manifest) != nil || manifest.Version != 1 || manifest.Scope != scope || manifest.Info != x.Info() || len(manifest.Snapshot) == 0 {
		t.Fatalf("manifest: %s", before)
	}
	var journals []qualification.ExecutionJournal
	for _, call := range x.Calls() {
		j, e := x.Execute(context.Background(), call.SlotID)
		if e != nil {
			t.Fatal(e)
		}
		journals = append(journals, j)
	}
	if len(journals) == 0 || int(f.sends.Load()) != len(x.Calls()) {
		t.Fatal("missing calls")
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		st, e := os.Stat(filepath.Join(c.Directory, "sessions.sqlite") + suffix)
		if e != nil || st.Mode().Perm() != 0600 {
			t.Fatalf("active SQL mode %s: %v", suffix, e)
		}
	}
	if err = x.Close(); err != nil {
		t.Fatal(err)
	}
	if err = x.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = x.Execute(context.Background(), x.Calls()[0].SlotID); err == nil {
		t.Fatal("closed executor sent")
	}
	after, err := os.ReadFile(filepath.Join(c.Directory, "scope.json"))
	if err != nil || string(before) != string(after) {
		t.Fatal("mutable manifest")
	}
	if _, err = NewDurableCandidateExecutor(f.pkg, f.expected, scope, c); !errors.Is(err, ErrCandidateExecution) {
		t.Fatalf("adopted root: %v", err)
	}
	if err = filepath.WalkDir(c.Directory, func(path string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		st, e := d.Info()
		if e != nil {
			return e
		}
		want := os.FileMode(0600)
		if d.IsDir() {
			want = 0700
		}
		if st.Mode().Perm() != want {
			t.Errorf("%s mode %o", path, st.Mode().Perm())
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	u := url.URL{Scheme: "file", Path: filepath.Join(c.Directory, "sessions.sqlite")}
	db, err := sqlitelog.Open(u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, j := range journals {
		records, e := db.Session(j.SessionID).Read(1)
		if e != nil || len(records) != j.Count || records[len(records)-1].Hash != j.HeadHash {
			t.Fatalf("readback: %v", e)
		}
	}
}

func TestDurableCandidateRefusesBeforeDispatch(t *testing.T) {
	for _, name := range []string{"existing", "symlink", "parent-link", "public-parent", "scope", "credential"} {
		t.Run(name, func(t *testing.T) {
			f := newExecutionFixture(t, nil)
			scope, c := durableConfig(t, f)
			if err := os.Chmod(filepath.Dir(c.Directory), 0700); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "existing":
				if err := os.Mkdir(c.Directory, 0700); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(t.TempDir(), c.Directory); err != nil {
					t.Fatal(err)
				}
			case "parent-link":
				link := filepath.Join(t.TempDir(), "link")
				if err := os.Symlink(filepath.Dir(c.Directory), link); err != nil {
					t.Fatal(err)
				}
				c.Directory = filepath.Join(link, "new")
			case "public-parent":
				if err := os.Chmod(filepath.Dir(c.Directory), 0755); err != nil {
					t.Fatal(err)
				}
			case "scope":
				scope.PlanDigest = "sha256:" + strings.Repeat("b", 64)
			case "credential":
				c.Credential = nil
			}
			if x, e := NewDurableCandidateExecutor(f.pkg, f.expected, scope, c); !errors.Is(e, ErrCandidateExecution) {
				if x != nil {
					_ = x.Close()
				}
				t.Fatalf("accepted %s: %v", name, e)
			}
			if f.sends.Load() != 0 || f.credential.calls.Load() != 0 {
				t.Fatal("refusal dispatched")
			}
		})
	}
}

func TestDurableCandidateDuplicateAndServingRoot(t *testing.T) {
	f := newExecutionFixture(t, nil)
	scope, c := durableConfig(t, f)
	if err := os.Chmod(filepath.Dir(c.Directory), 0700); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan qualification.Executor, 2)
	failures := make(chan error, 2)
	for range 2 {
		wg.Go(func() {
			x, e := NewDurableCandidateExecutor(f.pkg, f.expected, scope, c)
			if e != nil {
				failures <- e
			} else {
				results <- x
			}
		})
	}
	wg.Wait()
	close(results)
	close(failures)
	if len(results) != 1 || len(failures) != 1 {
		t.Fatal("duplicate ownership")
	}
	for x := range results {
		if err := x.Close(); err != nil {
			t.Fatal(err)
		}
	}
	// Directory reaches this real serving backing; exclusive creation protects it.
	c.Directory = filepath.Dir(f.budget.Config.LedgerPath)
	before, err := os.ReadFile(f.budget.Config.LedgerPath)
	if err != nil {
		t.Fatal(err)
	}
	if x, e := NewDurableCandidateExecutor(f.pkg, f.expected, scope, c); !errors.Is(e, ErrCandidateExecution) {
		if x != nil {
			x.Close()
		}
		t.Fatalf("serving root: %v", e)
	}
	after, err := os.ReadFile(f.budget.Config.LedgerPath)
	if err != nil || string(before) != string(after) {
		t.Fatal("modified serving budget")
	}
}

func TestDurableCandidateActiveClose(t *testing.T) {
	entered := make(chan struct{})
	cancelled := make(chan struct{})
	f := newExecutionFixture(t, func(w http.ResponseWriter, r *http.Request) { close(entered); <-r.Context().Done(); close(cancelled) })
	scope, c := durableConfig(t, f)
	if e := os.Chmod(filepath.Dir(c.Directory), 0700); e != nil {
		t.Fatal(e)
	}
	x, err := NewDurableCandidateExecutor(f.pkg, f.expected, scope, c)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, e := x.Execute(context.Background(), x.Calls()[0].SlotID); done <- e }()
	<-entered
	if err = x.Close(); err != nil {
		t.Fatal(err)
	}
	<-cancelled
	if err = <-done; err == nil {
		t.Fatal("cancel returned success")
	}
	if x.Close() != nil || f.sends.Load() != 1 {
		t.Fatal("close retry")
	}
	uri := url.URL{Scheme: "file", Path: filepath.Join(c.Directory, "sessions.sqlite")}
	db, err := sqlitelog.Open(uri.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	records, err := db.Session(qualification.CandidateSessionID(scope.RunID, x.Calls()[0].SlotID)).Read(1)
	if err != nil || len(records) == 0 || records[len(records)-1].Event.Err == nil {
		t.Fatalf("lost original error tail: %v", err)
	}
}
