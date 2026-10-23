package sessionfixture

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Azure/aks-durable-agents/internal/demobridge"
	"github.com/agent-primitives/sessions/api"
	"github.com/agent-primitives/sessions/controller"
	"github.com/agent-primitives/sessions/eventlog"
	"github.com/agent-primitives/sessions/sqlitelog"
)

func bridgeController(t *testing.T, log eventlog.Store, config []byte, model controller.ModelFunc, tool controller.ToolFunc) *controller.Controller {
	t.Helper()
	c, err := controller.New(log, model, controller.WithSessionUID("bridge-session"), controller.WithHarness(bridgeHarnessID), controller.WithStart(config, 0), controller.WithModelPolicy(api.ModelPolicy{Default: bridgeTestModel, Allowed: []string{bridgeTestModel}}), controller.WithModelDefault(bridgeTestModel), controller.WithToolExecutor(tool), controller.WithDurableDedup(func(tool string) bool { return tool == bridgeTool }))
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func completedBridge(t *testing.T, approved bool) (string, bridgeExpectation) {
	t.Helper()
	data := privateTempDir(t)
	if err := initBridgeData(data); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(data, "journal.db")
	store, err := sqlitelog.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ex, err := openExecutorScenario(filepath.Join(data, "publications.db"), bridgeScenario)
	if err != nil {
		t.Fatal(err)
	}
	modelCalls := 0
	model := func(_ context.Context, req api.ModelRequest) (api.ModelResponse, error) {
		modelCalls++
		if req.Model != bridgeTestModel || req.Messages[0].Text() != "Write release notes exactly as authored." {
			t.Fatal("runtime config/model changed")
		}
		return api.ModelResponse{Message: *api.TextMessage("assistant", bridgeTestDraft)}, nil
	}
	h := demobridge.WithApprovalMinimum(newBridgeHarness(bridgeTestModel), func(tool string) bool { return tool == bridgeTool })
	log := store.Session("bridge-session")
	c := bridgeController(t, log, bridgeTestConfig(), model, ex.execute)
	if err := c.Exec(t.Context(), h, []api.Message{*api.TextMessage("user", "Fictional release facts.")}, 0); !errors.Is(err, api.ErrApprovalParked) {
		t.Fatalf("not parked: %v", err)
	}
	if p, r, err := ex.counts(); err != nil || p != 0 || r != 0 || modelCalls != 1 {
		t.Fatal("effect before approval")
	}
	decision := pending(t, log)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ex.close(); err != nil {
		t.Fatal(err)
	}
	store, err = sqlitelog.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ex, err = openExecutorScenario(filepath.Join(data, "publications.db"), bridgeScenario)
	if err != nil {
		t.Fatal(err)
	}
	defer ex.close()
	log = store.Session("bridge-session")
	wrong := decision
	wrong.RequestSeq++
	wrong.Approved = true
	before := head(t, log)
	if _, err := controller.Approve(log, wrong); err == nil || head(t, log) != before {
		t.Fatal("stale approval accepted")
	}
	decision.Approved = approved
	if _, err := controller.Approve(log, decision); err != nil {
		t.Fatal(err)
	}
	if p, r, err := ex.counts(); err != nil || p != 0 || r != 0 {
		t.Fatal("Approve auto-resumed publication")
	}
	// Resume must use the original recorded invocation, never newly supplied Config.
	c = bridgeController(t, log, []byte(`{"system_prompt":"changed"}`), model, ex.execute)
	if _, err := c.Resume(t.Context(), h); err != nil {
		t.Fatal(err)
	}
	want := 0
	if approved {
		want = 1
	}
	if p, r, err := ex.counts(); err != nil || p != want || r != want || modelCalls != 1 {
		t.Fatal("recovery repeated model/effect")
	}
	return data, bridgeExpectation{ConfigSHA256: bridgeDigest(bridgeTestConfig()), Model: bridgeTestModel, Reference: "sha256:" + strings.Repeat("a", 64)}
}
func TestBridgeParkRestartApproveResumeAndStrictReplay(t *testing.T) {
	data, expected := completedBridge(t, true)
	before, err := inspectBridge(data)
	if err != nil || before.PublicationCount != 1 || before.ReceiptCount != 1 {
		t.Fatalf("invalid retained effect: %+v %v", before, err)
	}
	beforeBytes, _ := journalBytes(filepath.Join(data, "journal.db"))
	proof, err := verifyBridgeJournal(t.Context(), data, filepath.Join(data, "journal.db"), "bridge-session", expected)
	if err != nil || !proof.Completed || proof.ProviderCalls != 0 || proof.ExecutorCalls != 0 || proof.Artifact != before.Artifacts[0].Name {
		afterBytes, _ := journalBytes(filepath.Join(data, "journal.db"))
		t.Fatalf("strict replay: %+v %v; journal bytes %v -> %v", proof, err, beforeBytes, afterBytes)
	}
	after, err := inspectBridge(data)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("strict replay changed publication")
	}
	var out bytes.Buffer
	if err := runCLI(t.Context(), []string{"bridge-verify", "--data", data, "--journal", filepath.Join(data, "journal.db"), "--session", "bridge-session", "--model", expected.Model, "--config-sha256", expected.ConfigSHA256, "--reference", expected.Reference}, &out, io.Discard); err != nil || !strings.Contains(out.String(), `"bridge_only":true`) {
		t.Fatalf("CLI replay: %s %v", &out, err)
	}
	for _, kind := range []string{"config", "model", "reference"} {
		t.Run(kind, func(t *testing.T) {
			bad := expected
			switch kind {
			case "config":
				bad.ConfigSHA256 = "sha256:" + strings.Repeat("b", 64)
			case "model":
				bad.Model = "another-model"
			case "reference":
				bad.Reference = "sha256:" + strings.Repeat("c", 64)
			}
			if proof, err := verifyBridgeJournal(t.Context(), data, filepath.Join(data, "journal.db"), "bridge-session", bad); err == nil || proof.Completed {
				t.Fatal("substituted original binding accepted")
			}
		})
	}
}
func TestBridgeReplayRefusesUncheckpointedWalWithoutDiscardingIt(t *testing.T) {
	data, expected := completedBridge(t, true)
	path := filepath.Join(data, "journal.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; CREATE TABLE replay_probe(n)"); err != nil {
		t.Fatal(err)
	}
	before, err := journalBytes(path)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := verifyBridgeJournal(t.Context(), data, path, "bridge-session", expected)
	if err == nil || proof.Completed || !errors.Is(err, errBridgeNeedsCheckpoint) {
		t.Fatalf("uncertain WAL was not refused: %v", err)
	}
	after, err := journalBytes(path)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("verification discarded or changed retained WAL")
	}
}

func TestBridgeDeniedApprovalCannotQualifyPublication(t *testing.T) {
	data, expected := completedBridge(t, false)
	if proof, err := verifyBridgeJournal(t.Context(), data, filepath.Join(data, "journal.db"), "bridge-session", expected); err == nil || proof.Completed {
		t.Fatal("denied run qualified as published")
	}
}
