package sessionfixture

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agent-primitives/sessions/api"
	v1 "github.com/agent-primitives/sessions/api/genpb"
	"github.com/agent-primitives/sessions/client"
	"github.com/agent-primitives/sessions/controller"
	"github.com/agent-primitives/sessions/harnesswire"
	"github.com/agent-primitives/sessions/model/openai"
	"github.com/agent-primitives/sessions/placement"
	"github.com/agent-primitives/sessions/runtime/remote"
	"github.com/agent-primitives/sessions/session"
	"github.com/agent-primitives/sessions/sqlitelog"
	"google.golang.org/grpc"
)

func TestCLIRefusesUnsafeEndpoints(t *testing.T) {
	for _, args := range [][]string{
		{"harness", "--addr", "0.0.0.0:9000", "--instructions", "missing"},
		{"fake", "--addr", "example.org:9001", "--ledger", "missing"},
		{"verify-loop", "--phase", "park", "--server", "localhost:8080", "--data", "/tmp"},
		{"init", "--data", "relative"}, {"host"}, {"harness", "extra"},
	} {
		if err := runCLI(t.Context(), args, io.Discard, io.Discard); err == nil {
			t.Fatalf("unsafe/incomplete CLI accepted: %v", args)
		}
	}
}

// This test-only composition mirrors stock's public remote placement. Production
// fixture provides only Harness.Connect and the Unix executor, never a Sessions host.
func startRemoteTestSessions(t *testing.T, data string) (string, func()) {
	t.Helper()
	harnessListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hs := grpc.NewServer()
	v1.RegisterHarnessServer(hs, harnesswire.NewServer(newREFERENCE()))
	go hs.Serve(harnessListener)
	handler, err := newFakeHandler(filepath.Join(data, "fake-calls.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	fake := httptest.NewServer(handler)
	provider, err := openai.New(openai.WithBaseURL(fake.URL+"/v1"), openai.WithModel(modelID), openai.WithHTTPClient(&http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return io.ErrUnexpectedEOF }}))
	if err != nil {
		t.Fatal(err)
	}
	ex, err := newExecutor(data)
	if err != nil {
		t.Fatal(err)
	}
	store, err := sqlitelog.Open(filepath.Join(data, "journal.db"))
	if err != nil {
		t.Fatal(err)
	}
	backend := remote.New(harnessListener.Addr().String())
	registry, err := placement.NewRegistry("release-notes", map[string]*placement.Placer{"release-notes": placement.New(backend, controller.ModelFunc(provider.Model), placement.WithToolExecutor(ex.execute), placement.WithStreamingModel(provider.StreamModel))})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	v1.RegisterSessionsServer(srv, session.NewService(store, registry))
	go srv.Serve(listener)
	var once sync.Once
	stop := func() {
		once.Do(func() {
			srv.Stop()
			listener.Close()
			backend.Close()
			store.Close()
			ex.close()
			fake.Close()
			hs.Stop()
			harnessListener.Close()
		})
	}
	t.Cleanup(stop)
	return listener.Addr().String(), stop
}

// Catch accidental auto-resume, changed pending identities after replacement,
// provider re-execution, incomplete replay coverage and lost approval receipt stamps.
func TestRemoteRolesParkRestartCompleteStrictReplay(t *testing.T) {
	data := t.TempDir()
	if err := initData(data, filepath.Join(t.TempDir(), "publish.sock")); err != nil {
		t.Fatal(err)
	}
	addr, stop := startRemoteTestSessions(t, data)
	parked, err := verifyLoop(t.Context(), "park", data, addr, "")
	if err != nil {
		t.Fatal(err)
	}
	if parked.Session == "" || parked.FakeModelCalls != 2 || parked.PublicationCount != 0 || parked.ReceiptCount != 0 {
		t.Fatalf("park: %#v", parked)
	}
	stop()
	before, err := readEvidence(data)
	if err != nil {
		t.Fatal(err)
	}
	addr, _ = startRemoteTestSessions(t, data)
	after, err := readEvidence(data)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("replacement effects: %#v %v", after, err)
	}
	complete, err := verifyLoop(t.Context(), "complete", data, addr, parked.Session)
	if err != nil {
		t.Fatal(err)
	}
	if !complete.Published || !complete.Replay.Completed || complete.Replay.ProviderCalls != 0 || complete.Replay.ExecutorCalls != 0 || complete.FakeModelCalls != 2 || complete.PublicationCount != 1 || complete.ReceiptCount != 1 {
		t.Fatalf("complete: %#v", complete)
	}
	if !reflect.DeepEqual(complete.Replay.ExpectedExecutionIDs, complete.Replay.CoveredExecutionIDs) {
		t.Fatal("missing coverage")
	}
}

func TestActualJournalReplayRefusesPendingAndChangedInstructions(t *testing.T) {
	data := t.TempDir()
	if err := initData(data, "/run/reference/publish.sock"); err != nil {
		t.Fatal(err)
	}
	addr, _ := startRemoteTestSessions(t, data)
	c, err := client.Dial(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	turn, err := c.Exec(t.Context(), client.ExecOptions{Harness: "release-notes", Inputs: []string{"REFERENCE fictional proposal, variant A"}})
	if err != nil {
		t.Fatal(err)
	}
	uid := turn.Session.GetMetadata().GetUid()
	var out bytes.Buffer
	err = runCLI(t.Context(), []string{"verify-replay", "--journal", filepath.Join(data, "journal.db"), "--instructions", filepath.Join(data, "instructions.txt"), "--session", uid}, &out, io.Discard)
	var proof replayProof
	json.Unmarshal(out.Bytes(), &proof)
	if err == nil || proof.Completed || proof.HeadHash == "" || proof.ProviderCalls != 0 || proof.ExecutorCalls != 0 {
		t.Fatalf("pending verification: %s %v", out.String(), err)
	}
	os.WriteFile(filepath.Join(data, "instructions.txt"), []byte("changed"), 0600)
	if _, err = verifyJournal(context.Background(), filepath.Join(data, "journal.db"), filepath.Join(data, "instructions.txt"), uid); err == nil || !strings.Contains(err.Error(), "frozen") {
		t.Fatalf("changed instruction accepted: %v", err)
	}
}

// Readiness is exactly one line with the actual ephemeral listen address.
func TestHarnessRoleReadiness(t *testing.T) {
	data := t.TempDir()
	if err := initData(data, "/run/reference/publish.sock"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	reader, writer := io.Pipe()
	defer reader.Close()
	done := make(chan error, 1)
	go func() {
		defer writer.Close()
		done <- runCLI(ctx, []string{"harness", "--addr", "127.0.0.1:0", "--instructions", filepath.Join(data, "instructions.txt")}, writer, io.Discard)
	}()
	var ready struct{ Addr string }
	if err := json.NewDecoder(reader).Decode(&ready); err != nil {
		t.Fatal(err)
	}
	if ready.Addr == "" || strings.HasSuffix(ready.Addr, ":0") {
		t.Fatalf("readiness: %#v", ready)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("harness failed to stop")
	}
	_ = api.MediationRequiresApproval
}
