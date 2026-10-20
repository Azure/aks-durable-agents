package sessionfixture

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/agent-primitives/sessions/api"
	"github.com/agent-primitives/sessions/controller"
)

func publication() api.ToolCall {
	return api.ToolCall{ID: "publish-e1", Tool: "publish_release_notes", Mediation: api.MediationRequiresApproval, IdempotencyKey: "e1/publish", Args: map[string]any{"draft": draftA, "destination": "release-notes-demo"}}
}

// Break caught: receipt lost across instances or concurrent callers produces duplicate effects.
func TestExecutorDurableIdempotenceAndSessionNamespace(t *testing.T) {
	dir := t.TempDir()
	ex, err := newExecutor(dir)
	if err != nil {
		t.Fatal(err)
	}
	call := publication()
	scope := controller.ToolCallContext{SessionUID: "parent"}
	first, err := ex.execute(t.Context(), scope, call)
	if err != nil {
		t.Fatal(err)
	}
	if first.Output["draft"] != draftA || first.Output["simulated"] != true {
		t.Fatalf("wrong local artifact: %#v", first)
	}
	restart, err := newExecutor(dir)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			again, e := restart.execute(context.Background(), scope, call)
			if e != nil {
				t.Error(e)
				return
			}
			a, _ := json.Marshal(first)
			b, _ := json.Marshal(again)
			if string(a) != string(b) {
				t.Errorf("duplicate receipt differs: %s != %s", a, b)
			}
		})
	}
	wg.Wait()
	entries := receipts(t, dir)
	err = nil
	if err != nil || len(entries) != 1 {
		t.Fatalf("want one atomic receipt artifact, got %v %v", entries, err)
	}
	info, err := os.Stat(filepath.Join(dir, "publications.db"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("private artifact: %v %v", info, err)
	}
	raw := []byte(entries[0])
	var stored map[string]any
	if json.Unmarshal(raw, &stored) != nil || stored["session_uid"] != "parent" {
		t.Fatalf("durable receipt identity: %s", raw)
	}
	if _, err = restart.execute(t.Context(), controller.ToolCallContext{SessionUID: "child"}, call); err != nil {
		t.Fatal(err)
	}
	entries = receipts(t, dir)
	if len(entries) != 2 {
		t.Fatalf("fork namespace collapsed: %v", entries)
	}
}

// Break caught: a reused key silently overwrites different content, or tool args become paths.
func TestExecutorConflictAndPathRefusal(t *testing.T) {
	dir := t.TempDir()
	ex, err := newExecutor(dir)
	if err != nil {
		t.Fatal(err)
	}
	call := publication()
	scope := controller.ToolCallContext{SessionUID: "s"}
	if _, err = ex.execute(t.Context(), scope, call); err != nil {
		t.Fatal(err)
	}
	call.Args["draft"] = "Changed announcement"
	if _, err = ex.execute(t.Context(), scope, call); err == nil {
		t.Fatal("content conflict accepted")
	}
	for _, change := range []func(*api.ToolCall){
		func(c *api.ToolCall) { c.Args["destination"] = "../escape" },
		func(c *api.ToolCall) { c.Args["path"] = "/tmp/escape" },
		func(c *api.ToolCall) { c.Args["draft"] = 42 },
		func(c *api.ToolCall) { c.Args["draft"] = "" },
		func(c *api.ToolCall) { c.Tool = "shell" },
		func(c *api.ToolCall) { c.Tool = "ask_pm" },
		func(c *api.ToolCall) { c.IdempotencyKey = "" },
		func(c *api.ToolCall) { c.Mediation = api.MediationInHarnessReported },
	} {
		c := publication()
		change(&c)
		if _, err = ex.execute(t.Context(), scope, c); err == nil {
			t.Fatalf("unsafe call accepted: %#v", c)
		}
	}
	if _, err = ex.execute(t.Context(), controller.ToolCallContext{}, publication()); err == nil {
		t.Fatal("unscoped effect accepted")
	}
	link := filepath.Join(t.TempDir(), "link")
	if err = os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if _, err = newExecutor(link); err == nil {
		t.Fatal("symlink root accepted")
	}
}
