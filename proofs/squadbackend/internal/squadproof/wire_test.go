//go:build squadproof

package squadproof

import (
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
)

func TestProofWireRequiresBoundRoleAndPackage(t *testing.T) {
	for _, name := range []string{"valid", "wrong-role", "wrong-package"} {
		t.Run(name, func(t *testing.T) {
			l, _ := openTestLedger(t)
			pkg := proofDigest()
			harness := "proof-lead"
			if name == "wrong-package" {
				pkg = strings.Repeat("a", 64)
			}
			if name == "wrong-role" {
				harness = "proof-member"
			}
			_, err := l.Admit(t.Context(), Operation{ID: "lead", Kind: "lead", Team: "proof-team", PackageDigest: pkg, Member: "lead", Epoch: 1, Payload: []byte(`{}`)})
			if err != nil {
				t.Fatal(err)
			}
			if err = l.BindSession(t.Context(), "lead", "bound-session"); err != nil {
				t.Fatal(err)
			}
			caller, server := net.Pipe()
			defer caller.Close()
			if err = caller.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() { defer close(done); defer server.Close(); serveTool(t.Context(), server, l) }()
			request := toolRequest{Version: 1, Harness: harness, SessionUID: "bound-session", CallID: "call-1", Tool: "checkpoint", Arguments: map[string]any{"epoch": 1}, Key: "key-1"}
			if err = json.NewEncoder(caller).Encode(request); err != nil {
				t.Fatal(err)
			}
			var response toolResponse
			if err = json.NewDecoder(caller).Decode(&response); err != nil {
				t.Fatal(err)
			}
			<-done
			wantError := name != "valid"
			if response.IsError != wantError || response.CallID != "call-1" {
				t.Fatalf("scope result: %+v wantError=%v", response, wantError)
			}
			stats, err := l.Counts(t.Context())
			wantResults := 1
			if wantError {
				wantResults = 0
			}
			if err != nil || stats.ToolResults != wantResults || stats.Effects != 0 || stats.Operations != 1 {
				t.Fatalf("forbidden scope changed state: %+v %v", stats, err)
			}
		})
	}
}
