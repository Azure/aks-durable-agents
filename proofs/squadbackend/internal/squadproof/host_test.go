//go:build squadproof

package squadproof

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/agent-primitives/sessions/api"
	v1 "github.com/agent-primitives/sessions/api/genpb"
	"github.com/agent-primitives/sessions/client"
	"github.com/agent-primitives/sessions/harnesswire"
	"google.golang.org/grpc"
)

func TestProofBuildBoundary(t *testing.T) {
	descriptor, err := NewHarness("lead", proofDigest()).Describe(t.Context())
	if err != nil || descriptor.ID != "proof-lead" {
		t.Fatalf("tagged harness unavailable: %+v %v", descriptor, err)
	}
}

func TestProofHostConfigRequiresExplicitBoundary(t *testing.T) {
	_, path := openTestLedger(t)
	data := filepath.Dir(path)
	for _, args := range [][]string{{"--data=" + data}, {"--proof-only", "--data=" + data, "--addr=0.0.0.0:8080"}, {"--proof-only", "--data=" + data, "--lead=example.org:9000"}, {"--proof-only", "--data=relative"}, {"--proof-only", "--data=" + data, "--model=https://other.invalid"}} {
		if _, err := HostConfig(args); !errors.Is(err, ErrInvalid) {
			t.Fatalf("unsafe config accepted: %v %v", args, err)
		}
	}
	if _, err := HostConfig([]string{"--proof-only", "--data=" + data, "--addr=127.0.0.1:0"}); err != nil {
		t.Fatal(err)
	}
}

func startProofHost(t *testing.T, l *Ledger, data string) (*client.Client, func()) {
	t.Helper()
	addresses := map[string]string{}
	for _, role := range []string{"lead", "member"} {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		server := grpc.NewServer()
		v1.RegisterHarnessServer(server, harnesswire.NewServer(NewHarness(role, proofDigest())))
		go server.Serve(listener)
		t.Cleanup(func() { server.Stop(); listener.Close() })
		addresses[role] = listener.Addr().String()
	}
	ctx, cancel := context.WithCancel(t.Context())
	socket := filepath.Join(data, "tools.sock")
	executor, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	executorDone := make(chan error, 1)
	go func() { executorDone <- ServeExecutor(ctx, executor, l) }()
	ready := make(chan string, 1)
	done := make(chan error, 1)
	cfg, err := HostConfig([]string{"--proof-only", "--data=" + data, "--addr=127.0.0.1:0", "--lead=" + addresses["lead"], "--member=" + addresses["member"]})
	if err != nil {
		t.Fatal(err)
	}
	go func() { done <- RunHost(ctx, cfg, func(address string) { ready <- address }) }()
	var address string
	select {
	case address = <-ready:
	case err := <-done:
		cancel()
		t.Fatalf("host startup: %v", err)
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("host readiness not reported")
	}
	c, err := client.Dial(address)
	if err != nil {
		t.Fatal(err)
	}
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		c.Close()
		cancel()
		executor.Close()
		if err := <-done; err != nil {
			t.Error(err)
		}
		if err := <-executorDone; err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(stop)
	return c, stop
}

func TestProofHostUsesRealMediatedSessions(t *testing.T) {
	l, path := openTestLedger(t)
	c, _ := startProofHost(t, l, filepath.Dir(path))
	ctx := t.Context()
	_, err := l.Admit(ctx, Operation{ID: "lead", Kind: "lead", Team: "proof-team", PackageDigest: proofDigest(), Member: "lead", Epoch: 1, Payload: []byte(`{"kind":"start"}`)})
	if err != nil {
		t.Fatal(err)
	}
	lead, err := c.CreateSession(ctx, &v1.Session{Harness: "proof-lead"})
	if err != nil {
		t.Fatal(err)
	}
	leadUID := lead.GetMetadata().GetUid()
	if err = l.BindSession(ctx, "lead", leadUID); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Exec(ctx, client.ExecOptions{Session: leadUID, Inputs: []string{`{"kind":"start"}`}}); err != nil {
		t.Fatal(err)
	}
	lead, err = c.GetSession(ctx, leadUID)
	if err != nil || lead.GetPendingApproval() == nil {
		t.Fatalf("lead did not park: %+v %v", lead, err)
	}
	var childID string
	if err = l.db.QueryRow(`SELECT id FROM operations WHERE parent='lead'`).Scan(&childID); err != nil {
		t.Fatalf("no async handle before member allocation: %v", err)
	}
	child, err := l.Operation(ctx, childID)
	if err != nil || child.SessionUID != "" || child.State != "admitted" {
		t.Fatalf("dispatch waited/ran member: %+v %v", child, err)
	}
	member, err := c.CreateSession(ctx, &v1.Session{Harness: "proof-member"})
	if err != nil {
		t.Fatal(err)
	}
	memberUID := member.GetMetadata().GetUid()
	if memberUID == leadUID {
		t.Fatal("roles share a session")
	}
	if err = l.BindSession(ctx, childID, memberUID); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Exec(ctx, client.ExecOptions{Session: memberUID, Inputs: []string{string(child.Payload)}}); err != nil {
		t.Fatal(err)
	}
	for _, uid := range []string{memberUID, leadUID} {
		parked, err := c.GetSession(ctx, uid)
		if err != nil || parked.GetPendingApproval() == nil {
			t.Fatalf("missing approval: %v", err)
		}
		request := parked.GetPendingApproval()
		decision, err := c.Approve(ctx, uid, api.ApprovalDecision{ExecutionID: request.GetExecutionId(), ToolCallID: request.GetToolCallId(), RequestSeq: request.GetRequestSeq(), Approved: true, Reason: "synthetic proof"})
		if err != nil || decision.GetDecision() == nil {
			t.Fatalf("approval missing decision record: %v", err)
		}
		current, err := c.GetSession(ctx, uid)
		if err != nil {
			t.Fatal(err)
		}
		head := current.GetLastSeq()
		if _, err = c.Sessions().Resume(ctx, &v1.ResumeRequest{Session: uid, ExpectedLastSeq: &head}); err != nil {
			t.Fatal(err)
		}
	}
	stats, err := l.Counts(ctx)
	if err != nil || stats.Operations != 2 || stats.Effects != 1 || stats.ToolResults != 3 {
		t.Fatalf("mediated counts: %+v %v", stats, err)
	}
	if n, err := l.attemptCount(ctx, "model"); err != nil || n != 4 {
		t.Fatalf("model prefix repeated on resume: %d %v", n, err)
	}
	if n, err := l.attemptCount(ctx, "executor"); err != nil || n != 3 {
		t.Fatalf("executor attempts: %d %v", n, err)
	}
	for _, item := range []struct{ uid, role string }{{leadUID, "lead"}, {memberUID, "member"}} {
		records, err := c.Replay(ctx, item.uid, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := VerifyReplay(ctx, item.uid, records, NewHarness(item.role, proofDigest()))
		if err != nil || proof.Models != 0 || proof.Tools != 0 || len(proof.Executions) != 1 {
			t.Fatalf("canonical full replay: %+v %v", proof, err)
		}
	}
}
