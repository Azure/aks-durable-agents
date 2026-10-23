//go:build squadproof

package squadproof

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/agent-primitives/sessions/api"
	"github.com/agent-primitives/sessions/client"
	"google.golang.org/protobuf/proto"
)

type ownedProcess struct {
	cmd    *exec.Cmd
	done   chan error
	stderr bytes.Buffer
}

func (p *ownedProcess) stop() {
	if p == nil {
		return
	}
	select {
	case <-p.done:
		return
	default:
	}
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-p.done:
	case <-time.After(12 * time.Second):
		_ = p.cmd.Process.Kill()
		<-p.done
	}
}

type processCase struct {
	t                 *testing.T
	ctx               context.Context
	bin, data, server string
	l                 *Ledger
	ro                *sql.DB
	c                 *client.Client
	roles             []*ownedProcess
}

func buildProofBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "squad-proof")
	cmd := exec.CommandContext(t.Context(), "go", "build", "-tags", "squadproof", "-o", bin, "../../cmd/squad-proof")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build proof roles: %v %s", err, out)
	}
	return bin
}
func newProcessCase(t *testing.T, bin, mode string) *processCase {
	t.Helper()
	data, err := os.MkdirTemp("", "sq-proof-")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	f := &processCase{t: t, ctx: ctx, bin: bin, data: data}
	f.l, err = OpenLedger(filepath.Join(data, "proof.db"))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]string{"kind": "start", "mode": mode})
	if _, err = f.l.Admit(ctx, Operation{ID: "lead", Kind: "lead", Team: "proof-team", PackageDigest: proofDigest(), Member: "lead", Epoch: 1, Payload: raw}); err != nil {
		t.Fatal(err)
	}
	if err = f.l.SeedContext(ctx, "lead", "routing", "member"); err != nil {
		t.Fatal(err)
	}
	u := url.URL{Scheme: "file", Path: filepath.Join(data, "proof.db"), RawQuery: "mode=ro&_pragma=busy_timeout(5000)"}
	f.ro, err = sql.Open("sqlite", u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.stop(); f.ro.Close(); f.l.Close(); cancel(); os.RemoveAll(data) })
	f.start()
	return f
}
func (f *processCase) role(args ...string) map[string]string {
	f.t.Helper()
	p := &ownedProcess{done: make(chan error, 1)}
	p.cmd = exec.CommandContext(f.ctx, f.bin, args...)
	stdout, err := p.cmd.StdoutPipe()
	if err != nil {
		f.t.Fatal(err)
	}
	p.cmd.Stderr = &p.stderr
	if err = p.cmd.Start(); err != nil {
		f.t.Fatal(err)
	}
	f.roles = append(f.roles, p)
	go func() { p.done <- p.cmd.Wait(); close(p.done) }()
	ready := make(chan map[string]string, 1)
	bad := make(chan error, 1)
	go func() {
		var value map[string]string
		if err := json.NewDecoder(stdout).Decode(&value); err != nil {
			bad <- err
		} else {
			ready <- value
		}
		_, _ = io.Copy(io.Discard, stdout)
	}()
	select {
	case value := <-ready:
		return value
	case err := <-bad:
		f.t.Fatalf("role %v readiness: %v", args, err)
	case err := <-p.done:
		f.t.Fatalf("role %v exited before readiness: %v %s", args, err, p.stderr.String())
	case <-f.ctx.Done():
		f.t.Fatal(f.ctx.Err())
	}
	return nil
}
func (f *processCase) start() {
	f.t.Helper()
	// Every retained OpenLedger happens with all execution writers stopped. No
	// RPC is sent until sequential readiness has finished; this is not hot restart.
	socket := filepath.Join(f.data, "tools.sock")
	if st, err := os.Lstat(socket); err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			f.t.Fatal("owned socket became a non-socket")
		}
		if err = os.Remove(socket); err != nil {
			f.t.Fatal(err)
		}
	}
	f.role("executor", "--proof-only", "--data="+f.data)
	lead := f.role("harness", "--proof-only", "--role=lead", "--addr=127.0.0.1:0")["address"]
	member := f.role("harness", "--proof-only", "--role=member", "--addr=127.0.0.1:0")["address"]
	f.server = f.role("host", "--proof-only", "--data="+f.data, "--addr=127.0.0.1:0", "--lead="+lead, "--member="+member)["address"]
	var err error
	f.c, err = client.Dial(f.server)
	if err != nil {
		f.t.Fatal(err)
	}
}
func (f *processCase) stop() {
	if f.c != nil {
		f.c.Close()
		f.c = nil
	}
	for i := len(f.roles) - 1; i >= 0; i-- {
		f.roles[i].stop()
	}
	f.roles = nil
}
func (f *processCase) restart() { f.stop(); f.start() }
func (f *processCase) stepCommand() *exec.Cmd {
	return exec.CommandContext(f.ctx, f.bin, "broker", "--proof-only", "--data="+f.data, "--server="+f.server)
}
func (f *processCase) step() (string, error) {
	out, err := f.stepCommand().CombinedOutput()
	if f.ctx.Err() != nil {
		f.t.Fatal(f.ctx.Err())
	}
	return string(out), err
}
func (f *processCase) mustStep() {
	f.t.Helper()
	out, err := f.step()
	if err != nil {
		f.t.Fatalf("broker step: %v %s", err, out)
	}
}
func (f *processCase) ops() []Operation {
	f.t.Helper()
	rows, err := f.ro.QueryContext(f.ctx, `SELECT record FROM operations ORDER BY id`)
	if err != nil {
		f.t.Fatal(err)
	}
	defer rows.Close()
	var ops []Operation
	for rows.Next() {
		var raw []byte
		var op Operation
		if err = rows.Scan(&raw); err != nil {
			f.t.Fatal(err)
		}
		if err = json.Unmarshal(raw, &op); err != nil {
			f.t.Fatal(err)
		}
		ops = append(ops, op)
	}
	if err = rows.Err(); err != nil {
		f.t.Fatal(err)
	}
	return ops
}
func (f *processCase) op(id string) Operation {
	for _, op := range f.ops() {
		if op.ID == id {
			return op
		}
	}
	return Operation{}
}
func (f *processCase) count(kind, id string) int {
	f.t.Helper()
	var n int
	if err := f.ro.QueryRowContext(f.ctx, `SELECT count(*) FROM events WHERE kind=? AND (?='' OR operation=?)`, kind, id, id).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}
func (f *processCase) waitCut(point string) {
	f.t.Helper()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		if f.count("fault.hit", point) > 0 {
			return
		}
		select {
		case <-f.ctx.Done():
			f.t.Fatal(f.ctx.Err())
		case <-ticker.C:
		}
	}
}
func (f *processCase) decide(op Operation, approved bool) {
	f.t.Helper()
	w := &Worker{Ledger: f.l, Sessions: f.c}
	v, err := w.Inspect(f.ctx, op.ID)
	if err != nil {
		f.t.Fatal(err)
	}
	if v.Request.RequestSeq == 0 {
		f.t.Fatal("no verified approval")
	}
	d := api.ApprovalDecision{ExecutionID: v.Request.ExecutionID, ToolCallID: v.Request.ToolCallID, RequestSeq: v.Request.RequestSeq, Approved: approved, Reason: "explicit synthetic case decision"}
	if err = w.Decide(f.ctx, op.ID, d); err != nil {
		f.t.Fatal(err)
	}
}
func (f *processCase) drive(denyMember bool) {
	f.t.Helper()
	for i := 0; i < 100; i++ {
		for _, op := range f.ops() {
			if op.State == "awaiting-approval" && op.Evidence.DecisionSeq == 0 {
				v, err := (&Worker{Ledger: f.l, Sessions: f.c}).Inspect(f.ctx, op.ID)
				if err != nil {
					f.t.Fatal(err)
				}
				if v.Evidence.DecisionSeq == 0 && v.Evidence.EndSeq == 0 {
					f.decide(op, !denyMember || op.Kind != "dispatch")
				}
			}
		}
		if f.complete() {
			return
		}
		f.mustStep()
	}
	f.t.Fatalf("bounded broker did not finish: %+v", f.ops())
}
func (f *processCase) complete() bool {
	ops := f.ops()
	if len(ops) != 2 {
		return false
	}
	for _, op := range ops {
		if op.State != "terminal" {
			return false
		}
	}
	inputs, err := f.l.Inputs(f.ctx, "lead")
	if err != nil {
		f.t.Fatal(err)
	}
	if len(inputs) < 2 {
		return false
	}
	for _, in := range inputs {
		if in.State != "delivered" {
			return false
		}
	}
	return true
}
func (f *processCase) strictReplay() {
	f.t.Helper()
	model, tools := f.count("attempt-model", ""), f.count("attempt-executor", "")
	for _, op := range f.ops() {
		records, err := f.c.Replay(f.ctx, op.SessionUID, 0, 0)
		if err != nil {
			f.t.Fatal(err)
		}
		mid := int64(len(records) / 2)
		prefix, err := f.c.Replay(f.ctx, op.SessionUID, 1, mid)
		if err != nil {
			f.t.Fatal(err)
		}
		suffix, err := f.c.Replay(f.ctx, op.SessionUID, mid+1, 0)
		if err != nil {
			f.t.Fatal(err)
		}
		reconnected := append(prefix, suffix...)
		if len(reconnected) != len(records) {
			f.t.Fatal("cursor reconnect lost or duplicated records")
		}
		for i := range records {
			if !proto.Equal(reconnected[i], records[i]) {
				f.t.Fatal("cursor reconnect changed committed transcript")
			}
		}
		proof, err := VerifyReplay(f.ctx, op.SessionUID, records, NewHarness(op.Member, proofDigest()))
		if err != nil || len(proof.Executions) == 0 || proof.Models != 0 || proof.Tools != 0 {
			f.t.Fatalf("full completed replay: %+v %v", proof, err)
		}
		after, err := f.c.GetSession(f.ctx, op.SessionUID)
		if err != nil || after.GetLastSeq() != proof.HeadSeq {
			f.t.Fatalf("replay changed journal: %v", err)
		}
	}
	if f.count("attempt-model", "") != model || f.count("attempt-executor", "") != tools {
		f.t.Fatal("replay called an external callback")
	}
}
func (f *processCase) assertOneMember(effect int) {
	f.t.Helper()
	ops := f.ops()
	if len(ops) != 2 || ops[0].SessionUID == ops[1].SessionUID {
		f.t.Fatalf("admission/session count: %+v", ops)
	}
	if f.count("attempt-rpc-create", "") != 2 {
		f.t.Fatal("duplicate session allocation")
	}
	var effects int
	if err := f.ro.QueryRow(`SELECT count(*) FROM effects`).Scan(&effects); err != nil || effects != effect {
		f.t.Fatalf("effects %d want%d: %v", effects, effect, err)
	}
	f.strictReplay()
}
func requireCutExit(t *testing.T, err error, out string) {
	t.Helper()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != cutExit {
		t.Fatalf("not the deterministic crash exit: %v %s", err, out)
	}
}

func TestMediatedAsyncLeadMember(t *testing.T) {
	bin := buildProofBinary(t)
	for _, deny := range []bool{false, true} {
		t.Run(fmt.Sprint(deny), func(t *testing.T) {
			f := newProcessCase(t, bin, "")
			f.drive(deny)
			effects := 1
			if deny {
				effects = 0
			}
			f.assertOneMember(effects)
			if deny && f.count("attempt-executor", "") != 2 {
				t.Fatal("denied publish reached the executor")
			}
		})
	}
}

func TestCreateExecUncertain(t *testing.T) {
	bin := buildProofBinary(t)
	for _, cut := range []string{"broker.after-create", "broker.before-ack", "broker.after-reserve"} {
		t.Run(cut, func(t *testing.T) {
			f := newProcessCase(t, bin, "")
			if err := f.l.ArmCut(f.ctx, cut, "crash"); err != nil {
				t.Fatal(err)
			}
			crashed := false
			for i := 0; i < 12; i++ {
				out, err := f.step()
				if err != nil {
					requireCutExit(t, err, out)
					crashed = true
					break
				}
			}
			if !crashed {
				t.Fatal("armed cut not reached")
			}
			f.restart()
			f.mustStep()
			root := f.op("lead")
			if root.State != "uncertain" {
				t.Fatalf("not uncertain: %+v", root)
			}
			creates, execs, models := f.count("attempt-rpc-create", ""), f.count("attempt-rpc-exec", ""), f.count("attempt-model", "")
			for i := 0; i < 2; i++ {
				f.restart()
				f.mustStep()
				if f.op("lead").State != "uncertain" {
					t.Fatal("uncertainty cleared")
				}
			}
			if f.count("attempt-rpc-create", "") != creates || f.count("attempt-rpc-exec", "") != execs || f.count("attempt-model", "") != models {
				t.Fatal("uncertain outcome retried")
			}
			for _, op := range f.ops() {
				if op.ParentID != "" && op.SessionUID != "" {
					t.Fatal("uncertain root dispatched member")
				}
			}
		})
	}
}
