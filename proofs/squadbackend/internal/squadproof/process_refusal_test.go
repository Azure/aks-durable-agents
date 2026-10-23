//go:build squadproof

package squadproof

import (
	"database/sql"
	"encoding/json"
	"errors"
	"maps"
	"net"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	v1 "github.com/agent-primitives/sessions/api/genpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (f *processCase) unixCall(req toolRequest) toolResponse {
	f.t.Helper()
	conn, err := net.Dial("unix", filepath.Join(f.data, "tools.sock"))
	if err != nil {
		f.t.Fatal(err)
	}
	defer conn.Close()
	if err = json.NewEncoder(conn).Encode(req); err != nil {
		f.t.Fatal(err)
	}
	var reply toolResponse
	if err = json.NewDecoder(conn).Decode(&reply); err != nil {
		f.t.Fatal(err)
	}
	return reply
}
func TestProofProcessScopeRefusalsAndKeyConflict(t *testing.T) {
	bin := buildProofBinary(t)
	for _, name := range []string{"role", "package", "member", "epoch", "context", "key-conflict"} {
		t.Run(name, func(t *testing.T) {
			f := newProcessCase(t, bin, "")
			f.mustStep()
			op := f.op("lead")
			req := toolRequest{Version: 1, Harness: "proof-lead", SessionUID: op.SessionUID, CallID: "synthetic/call", Tool: "dispatch_member", Key: "synthetic-key", Arguments: map[string]any{"epoch": 1, "member": "member", "task": "synthetic task"}}
			switch name {
			case "role":
				req.Harness = "proof-member"
			case "package":
				op.PackageDigest = strings.Repeat("0", 64)
				if err := f.l.transaction(f.ctx, func(c *sql.Conn) error { return saveOperation(f.ctx, c, op) }); err != nil {
					t.Fatal(err)
				}
			case "member":
				req.Arguments["member"] = "other"
			case "epoch":
				if err := f.l.AdvanceEpoch(f.ctx, "lead", 1, 2); err != nil {
					t.Fatal(err)
				}
			case "context":
				if _, err := f.l.Admit(f.ctx, Operation{ID: "foreign", Kind: "lead", Team: "other-team", PackageDigest: proofDigest(), Member: "lead", Epoch: 1, Payload: []byte(`{}`)}); err != nil {
					t.Fatal(err)
				}
				if err := f.l.SeedContext(f.ctx, "foreign", "secret", "not-shared"); err != nil {
					t.Fatal(err)
				}
				req.Tool = "read_context"
				req.Arguments = map[string]any{"epoch": 1, "key": "secret"}
			case "key-conflict":
				first := f.unixCall(req)
				if first.IsError || first.Output["handle"] == nil {
					t.Fatal("valid proposal not admitted")
				}
				second := f.unixCall(req)
				if second.IsError || second.Output["handle"] != first.Output["handle"] {
					t.Fatal("exact retry changed durable handle")
				}
				req.Arguments["task"] = "different payload"
			}
			reply := f.unixCall(req)
			if !reply.IsError || len(reply.Output) != 0 {
				t.Fatalf("invalid scope/payload accepted/leaked context: %+v", reply)
			}
			if f.count("attempt-rpc-create", "") != 1 || f.count("attempt-rpc-exec", "") != 0 || f.count("attempt-model", "") != 0 {
				t.Fatal("refusal performed a new Sessions/model action")
			}
			var effects int
			if err := f.ro.QueryRow(`SELECT count(*) FROM effects`).Scan(&effects); err != nil || effects != 0 {
				t.Fatal("refusal reached an effect")
			}
		})
	}
}

func TestWrongPackageWorkerRefusedBeforeCreate(t *testing.T) {
	bin := buildProofBinary(t)
	f := newProcessCase(t, bin, "")
	op := f.op("lead")
	op.PackageDigest = strings.Repeat("0", 64)
	if err := f.l.transaction(f.ctx, func(c *sql.Conn) error { return saveOperation(f.ctx, c, op) }); err != nil {
		t.Fatal(err)
	}
	out, err := f.step()
	if err == nil {
		t.Fatalf("wrong package allocated: %s", out)
	}
	if f.count("attempt-rpc-create", "") != 0 {
		t.Fatal("wrong package reached Create")
	}
}

func TestCompletedReplayCancelAndResultConflict(t *testing.T) {
	bin := buildProofBinary(t)
	f := newProcessCase(t, bin, "")
	f.drive(false)
	f.assertOneMember(1)
	for _, op := range f.ops() {
		before, err := f.c.GetSession(f.ctx, op.SessionUID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.c.Sessions().Cancel(f.ctx, &v1.CancelRequest{Session: op.SessionUID}); status.Code(err) != codes.Unimplemented {
			t.Fatalf("cancellation misrepresented: %v", err)
		}
		after, err := f.c.GetSession(f.ctx, op.SessionUID)
		if err != nil || before.GetLastSeq() != after.GetLastSeq() {
			t.Fatal("unsupported cancellation changed execution evidence")
		}
		if op.Kind == "dispatch" {
			if _, err = f.l.EnqueueResult(f.ctx, op.ID, []byte(`{"summary":"different content"}`)); !errors.Is(err, ErrConflict) {
				t.Fatal("changed terminal result created another input")
			}
		}
	}
	f.assertOneMember(1)
	f.stop()
	before := sourceDigests(t, f.data)
	out, err := exec.CommandContext(f.ctx, f.bin, "replay", "--proof-only", "--writers-stopped", "--data="+f.data).CombinedOutput()
	if err != nil {
		t.Fatalf("offline all-invocation replay: %v %s", err, out)
	}
	after := sourceDigests(t, f.data)
	if !maps.Equal(before, after) {
		t.Fatal("offline replay mutated original storage")
	}
}
