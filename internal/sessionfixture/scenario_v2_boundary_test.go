package sessionfixture

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestV2BindExceptionIsExactAndExplicit(t *testing.T) {
	for _, tc := range []struct {
		address, scenario string
		explicit, want    bool
	}{
		{"0.0.0.0:9000", "v2", true, true}, {"0.0.0.0:9000", "v2", false, false},
		{"0.0.0.0:9001", "v2", true, false}, {"0.0.0.0:9000", "v1", true, false},
		{"[::]:9000", "v2", true, false}, {"10.0.0.1:9000", "v2", true, false},
		{"localhost:9000", "v2", true, false}, {"127.0.0.1:0", "v2", true, true},
	} {
		if err := harnessAddress(tc.address, tc.scenario, tc.explicit); (err == nil) != tc.want {
			t.Fatalf("%#v: %v", tc, err)
		}
	}
}

// Break caught: valid free-form headings or exact byte boundary are rejected, unsafe facts accepted.
func TestV2TextBoundaries(t *testing.T) {
	for _, draft := range []string{validV2Draft + "Notes: reviewers may revise this text.\n", validV2Draft + strings.Repeat("x", 4096-len(validV2Draft)), strings.ReplaceAll(validV2Draft, "18 October 2026", "18 October2026"), strings.ReplaceAll(validV2Draft, "pending approval", "pending human approval")} {
		if err := validateV2Draft(draft); err != nil {
			t.Fatal(err)
		}
	}
	for _, fact := range []string{"Northwind Lantern v2.4", "18 October 2026", "fictional", "faster search", "CSV export", "offline demo only", "pending approval"} {
		if err := validateV2Draft(strings.ReplaceAll(validV2Draft, fact, "omitted")); err == nil {
			t.Fatalf("missing %q accepted", fact)
		}
	}
	for _, extra := range []string{"\x00", "\x7f", "\u0085", "\ufeff", "javascript:alert(1)", "<script>alert(1)</script>", "Authorization: Bearer abc", "Now deployed.", "Real customer data."} {
		if err := validateV2Draft(validV2Draft + extra); err == nil {
			t.Fatalf("accepted %q", extra)
		}
	}
}

// Break caught: TCP probe treats an invalid configuration as a successful deny.
func TestNetworkProbeRejectsInvalidAddresses(t *testing.T) {
	for _, address := range []string{"127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:-1", ":9000", "127.0.0.1:not-a-port"} {
		if err := runCLI(t.Context(), []string{"network-probe", "--address", address, "--expect", "denied"}, io.Discard, io.Discard); err == nil {
			t.Fatalf("invalid address accepted: %s", address)
		}
	}
}

// Break caught: executor transport falls back to frozen v1 validation or loses restart dedup.
func TestV2ExecutorWireAndRestart(t *testing.T) {
	data := privateTempDir(t)
	if err := initDataScenario(data, filepath.Join(data, "publish.sock"), "v2"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(data, "publications.db")
	ex, err := openExecutorScenario(path, "v2")
	if err != nil {
		t.Fatal(err)
	}
	req := executorRequest{Version: 1, Harness: "release-notes", SessionUID: "s", CallID: "call", Tool: "publish_release_notes", Arguments: map[string]any{"draft": validV2Draft, "destination": "release-notes-demo"}, Key: "exec/publish_release_notes"}
	request := func(e *executor) executorResponse {
		t.Helper()
		server, client := net.Pipe()
		defer client.Close()
		client.SetDeadline(time.Now().Add(3 * time.Second))
		done := make(chan struct{})
		go func() { defer close(done); defer server.Close(); serveExecutorConn(t.Context(), server, e) }()
		if err := json.NewEncoder(client).Encode(req); err != nil {
			t.Fatal(err)
		}
		var response executorResponse
		if err := json.NewDecoder(client).Decode(&response); err != nil {
			t.Fatal(err)
		}
		<-done
		return response
	}
	first := request(ex)
	if first.IsError || first.Output["draft"] != validV2Draft {
		t.Fatalf("%#v", first)
	}
	ex.close()
	ex, err = openExecutorScenario(path, "v2")
	if err != nil {
		t.Fatal(err)
	}
	defer ex.close()
	req.CallID = "redrive"
	again := request(ex)
	a, _ := json.Marshal(first.Output)
	b, _ := json.Marshal(again.Output)
	if again.IsError || again.CallID != "redrive" || !bytes.Equal(a, b) {
		t.Fatalf("bad redrive: %#v", again)
	}
	req.Arguments["draft"] = validV2Draft + "Changed wording."
	if response := request(ex); !response.IsError {
		t.Fatal("changed draft accepted under same durable tuple")
	}
	if p, r, err := ex.counts(); err != nil || p != 1 || r != 1 {
		t.Fatalf("%d %d %v", p, r, err)
	}
}

func TestV2InstructionReadRejectsUnsafePermissions(t *testing.T) {
	data := privateTempDir(t)
	if err := initDataScenario(data, filepath.Join(data, "publish.sock"), "v2"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(data, "instructions.txt")
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := instructionBytesScenario(path, "v2"); err == nil {
		t.Fatal("nonprivate v2 instructions accepted")
	}
}
