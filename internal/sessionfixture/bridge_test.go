package sessionfixture

import (
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
)

func TestBridgeConfigBounds(t *testing.T) {
	good := `{"system_prompt":"Authored instructions.","reference":"sha256:` + strings.Repeat("a", 64) + `"}`
	for _, raw := range []string{"null", good + "{}", strings.Replace(good, `"system_prompt":`, `"system_prompt":"PRIVATE", "system_prompt":`, 1), strings.Replace(good, "Authored instructions.", strings.Repeat("x", 256<<10+1), 1), strings.Replace(good, `"reference":`, `"model":"PRIVATE","reference":`, 1), strings.Replace(good, "sha256:", "bad:", 1)} {
		if _, err := decodeBridgeConfig([]byte(raw)); err == nil || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatalf("unsafe Config accepted: %v", err)
		}
	}
	if _, err := decodeBridgeConfig([]byte(good)); err != nil {
		t.Fatal(err)
	}
}

func TestBridgeLostReplyDedupAndLineage(t *testing.T) {
	data := privateTempDir(t)
	if err := initBridgeData(data); err != nil {
		t.Fatal(err)
	}
	if err := initBridgeData(data); err == nil {
		t.Fatal("adopted retained root")
	}
	path := filepath.Join(data, "publications.db")
	for _, old := range []string{"v1", "v2"} {
		if ex, err := openExecutorScenario(path, old); err == nil {
			ex.close()
			t.Fatal("legacy adopted bridge")
		}
	}
	ex, err := openExecutorScenario(path, bridgeScenario)
	if err != nil {
		t.Fatal(err)
	}
	call := scenarioCall("exec", bridgeTool, map[string]any{"destination": "release-notes-demo", "draft": "Verbatim draft.", "config_sha256": "sha256:" + strings.Repeat("a", 64)})
	ex.afterCommit = func() error { return io.ErrUnexpectedEOF }
	if _, err := ex.execute(t.Context(), toolScope("session"), call); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal("lost-reply injection failed")
	}
	ex.close()
	ex, err = openExecutorScenario(path, bridgeScenario)
	if err != nil {
		t.Fatal(err)
	}
	defer ex.close()
	if r, err := ex.execute(t.Context(), toolScope("session"), call); err != nil || r.Output["local_demo"] != true {
		t.Fatal("durable receipt not recovered")
	}
	if p, r, err := ex.counts(); err != nil || p != 1 || r != 1 {
		t.Fatal("duplicate effect")
	}
	call.Args["draft"] = "Changed."
	if _, err := ex.execute(t.Context(), toolScope("session"), call); err == nil {
		t.Fatal("changed payload accepted")
	}
}
