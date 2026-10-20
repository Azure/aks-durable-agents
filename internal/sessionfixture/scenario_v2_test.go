package sessionfixture

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agent-primitives/sessions/api"
)

const validV2Draft = "Northwind Lantern v2.4 — 18 October 2026\nThis fictional release offers faster search and CSV export. This is an offline demo only; rollout pending approval. Review the proposed improvements before any decision.\n"

// Break caught: v2 init aliases historical data or fails to freeze a separate scenario.
func TestV2InitSeparateAndFrozen(t *testing.T) {
	old := privateTempDir(t)
	if err := initData(old, "/run/reference/publish.sock"); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(old, "instructions.txt"))
	if err := runCLI(t.Context(), []string{"init", "--scenario", "v2", "--data", old}, io.Discard, io.Discard); err == nil {
		t.Fatal("v2 initialized old root")
	}
	after, _ := os.ReadFile(filepath.Join(old, "instructions.txt"))
	if !bytes.Equal(before, after) {
		t.Fatal("old instructions changed")
	}
	data := privateTempDir(t)
	args := []string{"init", "--scenario", "v2", "--data", data}
	if err := runCLI(t.Context(), args, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := runCLI(t.Context(), args, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(data, "instructions.txt"))
	if !strings.Contains(string(raw), "Northwind Lantern v2.4") || bytes.Equal(raw, before) {
		t.Fatal("no real fictional scenario")
	}
	var tools struct {
		Executors []struct {
			Socket string `json:"socket"`
		} `json:"executors"`
	}
	raw, _ = os.ReadFile(filepath.Join(data, "tools.json"))
	if err := json.Unmarshal(raw, &tools); err != nil {
		t.Fatal(err)
	}
	if len(tools.Executors) != 1 || tools.Executors[0].Socket != filepath.Join(data, "publish.sock") {
		t.Fatalf("nonshared socket: %s", raw)
	}
	if err := runCLI(t.Context(), []string{"init", "--data", data}, io.Discard, io.Discard); err == nil {
		t.Fatal("v1 reused v2")
	}
	if err := os.WriteFile(filepath.Join(data, "instructions.txt"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := runCLI(t.Context(), args, io.Discard, io.Discard); err == nil {
		t.Fatal("changed v2 instructions accepted")
	}
}

// Break caught: open-ended real drafts bypass content/destination restrictions or v1 changes.
func TestV2DraftValidationAndDedup(t *testing.T) {
	data := privateTempDir(t)
	if err := initDataScenario(data, filepath.Join(data, "publish.sock"), "v2"); err != nil {
		t.Fatal(err)
	}
	ex, err := openExecutorScenario(filepath.Join(data, "publications.db"), "v2")
	if err != nil {
		t.Fatal(err)
	}
	defer ex.close()
	call := scenarioCall("exec", "publish_release_notes", map[string]any{"draft": validV2Draft, "destination": "release-notes-demo"})
	if err := validateTool(toolScope("s"), call); err == nil {
		t.Fatal("v1 accepted real draft")
	}
	for name, draft := range map[string]string{
		"arbitrary": validV2Draft, "case": strings.ToUpper(validV2Draft), "different": validV2Draft + "Editors may revise the wording.\n", "tabs": validV2Draft + "\tLocal preview.",
	} {
		t.Run(name, func(t *testing.T) {
			c := call
			c.Args = map[string]any{"draft": draft, "destination": "release-notes-demo"}
			if err := validateToolScenario(toolScope("s"), c, "v2"); err != nil {
				t.Fatal(err)
			}
		})
	}
	for name, draft := range map[string]string{
		"missing": strings.ReplaceAll(validV2Draft, "CSV export", "exports"), "too long": validV2Draft + strings.Repeat("x", 4096), "short": "Northwind Lantern", "utf8": validV2Draft + string([]byte{255}), "control": validV2Draft + "\r", "bidi": validV2Draft + "\u202e", "url": validV2Draft + "https://example.org", "bare domain": validV2Draft + "example.org", "markup": validV2Draft + "<b>preview</b>", "markdown": validV2Draft + "[preview](file:/tmp/x)", "credential": validV2Draft + " api_key=secret", "customer": validV2Draft + "Uses real customer data.", "deployment": validV2Draft + "Already deployed to production.",
	} {
		t.Run(name, func(t *testing.T) {
			c := call
			c.Args = map[string]any{"draft": draft, "destination": "release-notes-demo"}
			if err := validateToolScenario(toolScope("s"), c, "v2"); err == nil {
				t.Fatal("unsafe draft accepted")
			}
		})
	}
	for _, draft := range []string{validV2Draft, validV2Draft} {
		call.Args["draft"] = draft
		if _, err = ex.execute(t.Context(), toolScope("s"), call); err != nil {
			t.Fatal(err)
		}
	}
	call.Args["draft"] = validV2Draft + "Different wording."
	if _, err = ex.execute(t.Context(), toolScope("s"), call); err == nil {
		t.Fatal("changed dedup accepted")
	}
	if p, r, err := ex.counts(); err != nil || p != 1 || r != 1 {
		t.Fatalf("%d %d %v", p, r, err)
	}
	// Wire decoder must select the same validator as execution.
	req := executorRequest{Version: 1, Harness: "release-notes", SessionUID: "s", CallID: "call", Tool: call.Tool, Arguments: call.Args, Key: call.IdempotencyKey}
	raw, _ := json.Marshal(req)
	if _, err := decodeExecutorRequestScenario(raw, "v2"); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeExecutorRequest(raw); err == nil {
		t.Fatal("v1 wire accepted v2 draft")
	}
}

// Break caught: v2 starts without fresh placement or widens v1 listener policy.
func TestV2PlacementAndBind(t *testing.T) {
	data := privateTempDir(t)
	if err := initDataScenario(data, filepath.Join(data, "publish.sock"), "v2"); err != nil {
		t.Fatal(err)
	}
	instructions := filepath.Join(data, "instructions.txt")
	for _, extra := range [][]string{nil, {"--node-name", "node-a"}, {"--node-name", "node-a", "--pod-uid", "pod-a", "--addr", "10.0.0.1:9000"}} {
		args := append([]string{"harness", "--scenario", "v2", "--instructions", instructions}, extra...)
		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		err := runCLI(ctx, args, io.Discard, io.Discard)
		cancel()
		if err == nil {
			t.Fatalf("unsafe harness: %v", args)
		}
	}
	marker := filepath.Join(data, "fixture-node.json")
	if err := writePlacement(data, "node-a", "pod-old"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	reader, writer := io.Pipe()
	defer reader.Close()
	done := make(chan error, 1)
	go func() {
		defer writer.Close()
		done <- runCLI(ctx, []string{"harness", "--scenario", "v2", "--addr", "127.0.0.1:0", "--instructions", instructions, "--node-name", "node-a", "--pod-uid", "pod-new"}, writer, io.Discard)
	}()
	var ready map[string]any
	if err := json.NewDecoder(reader).Decode(&ready); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "{\"nodeName\":\"node-a\",\"podUID\":\"pod-new\"}\n" {
		t.Fatalf("stale placement: %s", raw)
	}
	info, _ := os.Lstat(marker)
	if info.Mode().Perm() != 0600 {
		t.Fatal(info.Mode())
	}
	if err := checkPlacement(data, "node-b"); err == nil {
		t.Fatal("wrong node accepted")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	os.Remove(marker)
	if err := os.Symlink(filepath.Join(data, "instructions.txt"), marker); err != nil {
		t.Fatal(err)
	}
	if err := writePlacement(data, "node-a", "pod-a"); err == nil {
		t.Fatal("marker symlink accepted")
	}
}

// Break caught: network probe invokes HTTP/inference or misreports expected connectivity.
func TestNetworkProbe(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := l.Addr().String()
	go func() {
		conn, err := l.Accept()
		if err == nil {
			defer conn.Close()
			buf := make([]byte, 1)
			n, _ := conn.Read(buf)
			if n != 0 {
				t.Error("probe sent application bytes")
			}
		}
	}()
	var out bytes.Buffer
	if err := runCLI(t.Context(), []string{"network-probe", "--address", address, "--expect", "allowed"}, &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	l.Close()
	out.Reset()
	if err := runCLI(t.Context(), []string{"network-probe", "--address", address, "--expect", "denied"}, &out, io.Discard); err == nil {
		t.Fatal("local connection refusal reported as a successful deny")
	}
	if out.Len() != 0 {
		t.Fatalf("connection refusal emitted a proof: %s", &out)
	}
	if err := runCLI(t.Context(), []string{"network-probe", "--address", address, "--expect", "allowed"}, io.Discard, io.Discard); err == nil {
		t.Fatal("failed connection reported allowed")
	}
	_ = api.MediationRequiresApproval
}
