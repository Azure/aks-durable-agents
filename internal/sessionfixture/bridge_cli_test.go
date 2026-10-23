package sessionfixture

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestBridgeCLIInitAndInspectionAreSeparateFromNightly(t *testing.T) {
	dir := privateTempDir(t)
	var out, diag bytes.Buffer
	if err := runCLI(t.Context(), []string{"bridge-init", "--data", dir}, &out, &diag); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"bridge_only":true`) {
		t.Fatal("bridge not labelled")
	}
	out.Reset()
	if err := runCLI(t.Context(), []string{"bridge-inspect", "--data", dir}, &out, &diag); err != nil {
		t.Fatal(err)
	}
	var info struct {
		PublicationCount int `json:"publication_count"`
		ReceiptCount     int `json:"receipt_count"`
	}
	if err := json.Unmarshal(out.Bytes(), &info); err != nil || info.PublicationCount != 0 || info.ReceiptCount != 0 {
		t.Fatal("initial state not empty")
	}
	out.Reset()
	if err := runCLI(t.Context(), []string{"bridge-init", "--data", dir}, &out, &diag); err == nil || out.Len() != 0 {
		t.Fatal("repeat adopted state or claimed success")
	}
}
func TestBridgeCLIRefusesMissingOriginalBindingAndUnknownFlags(t *testing.T) {
	for _, args := range [][]string{{"bridge-harness"}, {"bridge-harness", "--model", bridgeTestModel, "--instructions", "PRIVATE"}, {"bridge-verify"}, {"bridge-verify", "--session", "s", "--model", bridgeTestModel}, {"bridge-unknown"}} {
		var out, diag bytes.Buffer
		if err := runCLI(t.Context(), args, &out, &diag); err == nil || out.Len() != 0 || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatalf("unsafe bridge refusal: %v", err)
		}
	}
}
func TestBridgeExecutorProtocolRequiresItsOwnHarnessRoute(t *testing.T) {
	c := bridgePublication()
	req := map[string]any{"version": 1, "session_uid": "s", "harness": bridgeHarnessID, "tool": c.Tool, "call_id": c.ID, "idempotency_key": c.IdempotencyKey, "arguments": c.Args}
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeExecutorRequestScenario(raw, bridgeScenario)
	if err != nil || decoded.Harness != bridgeHarnessID {
		t.Fatalf("bridge route not accepted: %v", err)
	}
	for _, mode := range []string{"v1", "v2"} {
		if _, err := decodeExecutorRequestScenario(raw, mode); err == nil {
			t.Fatal("legacy decoder adopted bridge")
		}
	}
	req["harness"] = "release-notes"
	raw, err = json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeExecutorRequestScenario(raw, bridgeScenario); err == nil {
		t.Fatal("bridge adopted old route")
	}
}
