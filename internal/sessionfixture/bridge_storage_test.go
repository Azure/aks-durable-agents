package sessionfixture

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agent-primitives/sessions/api"
	"github.com/agent-primitives/sessions/controller"
)

func bridgePublication() api.ToolCall {
	return api.ToolCall{ID: "bridge-call", Tool: "publish_release_notes", IdempotencyKey: "bridge-key", Mediation: api.MediationRequiresApproval, Args: map[string]any{"draft": bridgeTestDraft, "destination": "release-notes-demo", "config_sha256": "sha256:" + strings.Repeat("b", 64)}}
}
func TestBridgeStorageIsolationAndExclusiveInitialization(t *testing.T) {
	dir := privateTempDir(t)
	if err := initBridgeData(dir); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"scenario.json", "tools.json"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("not private: %s %v", name, err)
		}
	}
	if err := initBridgeData(dir); err == nil {
		t.Fatal("existing bridge state adopted")
	}
	for _, mode := range []string{"v1", "v2"} {
		if e, err := openExecutorScenario(filepath.Join(dir, "publications.db"), mode); err == nil {
			e.close()
			t.Fatal("old executor adopted bridge data")
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "publications.db")); !os.IsNotExist(err) {
		t.Fatal("refusal created database")
	}
	old := privateTempDir(t)
	if err := initScenarioMarker(old, "v2"); err != nil {
		t.Fatal(err)
	}
	if e, err := openExecutorScenario(filepath.Join(old, "publications.db"), bridgeScenario); err == nil {
		e.close()
		t.Fatal("bridge adopted old scenario")
	}
	emptyDB := privateTempDir(t)
	if err := initBridgeData(emptyDB); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(emptyDB, "publications.db"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if e, err := openExecutorScenario(filepath.Join(emptyDB, "publications.db"), bridgeScenario); err == nil {
		e.close()
		t.Fatal("empty retained database repaired")
	}
}
func TestBridgeStorageLostReplyRedriveAndPayloadConflict(t *testing.T) {
	dir := privateTempDir(t)
	if err := initBridgeData(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "publications.db")
	ex, err := openExecutorScenario(path, bridgeScenario)
	if err != nil {
		t.Fatal(err)
	}
	lost := errors.New("lost post-commit reply")
	ex.afterCommit = func() error { return lost }
	call := bridgePublication()
	scope := controller.ToolCallContext{SessionUID: "bridge-session"}
	if _, err := ex.execute(t.Context(), scope, call); !errors.Is(err, lost) {
		t.Fatalf("no lost reply: %v", err)
	}
	if p, r, err := ex.counts(); err != nil || p != 1 || r != 1 {
		t.Fatal("commit was not atomic")
	}
	if err := ex.close(); err != nil {
		t.Fatal(err)
	}
	ex, err = openExecutorScenario(path, bridgeScenario)
	if err != nil {
		t.Fatal(err)
	}
	defer ex.close()
	call.ID = "redrive"
	out, err := ex.execute(t.Context(), scope, call)
	if err != nil || out.ID != "redrive" || out.Output["local_demo"] != true || out.Output["draft"] != bridgeTestDraft || out.Output["config_sha256"] != call.Args["config_sha256"] {
		t.Fatalf("receipt not recovered: %+v %v", out, err)
	}
	if _, ok := out.Output["simulated"]; ok {
		t.Fatal("new local effect relabelled old simulation")
	}
	if p, r, err := ex.counts(); err != nil || p != 1 || r != 1 {
		t.Fatal("redrive duplicated effect")
	}
	call.Args["draft"] = "A changed draft."
	if _, err := ex.execute(t.Context(), scope, call); err == nil {
		t.Fatal("changed payload reused old receipt")
	}
	call.Args["draft"] = bridgeTestDraft
	second, err := ex.execute(t.Context(), controller.ToolCallContext{SessionUID: "other-session"}, call)
	if err != nil || second.Output["artifact"] == out.Output["artifact"] {
		t.Fatal("session namespace collapsed")
	}
}
func TestBridgeStorageRejectsInvalidPublication(t *testing.T) {
	dir := privateTempDir(t)
	if err := initBridgeData(dir); err != nil {
		t.Fatal(err)
	}
	ex, err := openExecutorScenario(filepath.Join(dir, "publications.db"), bridgeScenario)
	if err != nil {
		t.Fatal(err)
	}
	defer ex.close()
	for _, kind := range []string{"mediation", "tool", "destination", "config", "extra", "draft", "scope"} {
		t.Run(kind, func(t *testing.T) {
			c := bridgePublication()
			scope := controller.ToolCallContext{SessionUID: "s"}
			switch kind {
			case "mediation":
				c.Mediation = api.MediationControllerMediated
			case "tool":
				c.Tool = "other"
			case "destination":
				c.Args["destination"] = "../escape"
			case "config":
				c.Args["config_sha256"] = "bad"
			case "extra":
				c.Args["extra"] = "private"
			case "draft":
				c.Args["draft"] = "bad\x00draft"
			case "scope":
				scope.SessionUID = ""
			}
			if _, err := ex.execute(t.Context(), scope, c); err == nil {
				t.Fatal("unsafe publication accepted")
			}
		})
	}
	if p, r, err := ex.counts(); err != nil || p != 0 || r != 0 {
		t.Fatal("invalid proposals changed durable state")
	}
}
