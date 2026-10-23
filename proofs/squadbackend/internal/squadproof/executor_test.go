package squadproof

import (
	"errors"
	"os"
	"os/exec"
	"reflect"
	"sync"
	"testing"

	"github.com/agent-primitives/sessions/api"
	"github.com/agent-primitives/sessions/controller"
)

func dispatchCall(key string) api.ToolCall {
	return api.ToolCall{ID: "call-" + key, IdempotencyKey: key, Tool: "dispatch_member", Mediation: api.MediationControllerMediated, Args: map[string]any{"epoch": 1, "member": "member", "task": "write result"}}
}

func seedMember(t *testing.T, l *Ledger) Operation {
	t.Helper()
	seedLead(t, l)
	child, err := l.Admit(testContext, Operation{ID: "child", Kind: "dispatch", ParentID: "lead", Team: "team-a", PackageDigest: packageDigest, Member: "member", Epoch: 1, Payload: []byte(`{"task":"work"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if err = l.BindSession(testContext, child.ID, "session-member"); err != nil {
		t.Fatal(err)
	}
	return child
}

func publishCall() api.ToolCall {
	return api.ToolCall{ID: "publish-call", IdempotencyKey: "publish-key", Tool: "publish", Mediation: api.MediationRequiresApproval, Args: map[string]any{"epoch": 1, "text": "simulated publication"}}
}

func TestExecutorCommitBeforeReceipt(t *testing.T) {
	l, path := openTestLedger(t)
	seedMember(t, l)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "-test.run=^TestExecutorCrashHelper$", "--", "proof-crash", path)
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 73 {
		t.Fatalf("child did not reach committed-result cut: %s %v", out, err)
	}
	l, err = OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	call := publishCall()
	call.ID = "new-correlation-id"
	got, err := (&Executor{Ledger: l}).Execute(testContext, controller.ToolCallContext{SessionUID: "session-member"}, call)
	if err != nil || got.ID != call.ID || got.Output["text"] != "simulated publication" {
		t.Fatalf("recovered result: %+v %v", got, err)
	}
	stats, err := l.Counts(testContext)
	if err != nil || stats.Effects != 1 || stats.ToolResults != 1 {
		t.Fatalf("recovery counts: %+v %v", stats, err)
	}
	call.Args["text"] = "changed publication"
	if _, err = (&Executor{Ledger: l}).Execute(testContext, controller.ToolCallContext{SessionUID: "session-member"}, call); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed retry accepted: %v", err)
	}
}

func TestExecutorCrashHelper(t *testing.T) {
	if len(os.Args) < 3 || os.Args[len(os.Args)-2] != "proof-crash" {
		t.Skip("subprocess-only crash cut")
	}
	l, err := OpenLedger(os.Args[len(os.Args)-1])
	if err != nil {
		t.Fatal(err)
	}
	if _, err = (&Executor{Ledger: l}).Execute(testContext, controller.ToolCallContext{SessionUID: "session-member"}, publishCall()); err != nil {
		t.Fatal(err)
	}
	os.Exit(73) // No Close/deferred cleanup, and no Sessions receipt or result delivery.
}

func TestConcurrentDispatchDeduplicates(t *testing.T) {
	l, path := openTestLedger(t)
	seedLead(t, l)
	other, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	start := make(chan struct{})
	var wg sync.WaitGroup
	handles := make(chan string, 8)
	for i := range 8 {
		wg.Go(func() {
			<-start
			db := l
			if i%2 == 1 {
				db = other
			}
			got, err := (&Executor{Ledger: db}).Execute(testContext, controller.ToolCallContext{SessionUID: "session-lead"}, dispatchCall("one"))
			if err != nil {
				t.Error(err)
				return
			}
			handles <- got.Output["handle"].(string)
		})
	}
	close(start)
	wg.Wait()
	close(handles)
	var first string
	for h := range handles {
		if first == "" {
			first = h
		}
		if h != first {
			t.Fatal("duplicate dispatch got another handle")
		}
	}
	stats, err := l.Counts(testContext)
	if err != nil || first == "" || stats.Operations != 2 || stats.ToolResults != 1 {
		t.Fatalf("dispatch counts: %+v %v", stats, err)
	}
	if _, err = (&Executor{Ledger: l}).Execute(testContext, controller.ToolCallContext{SessionUID: "session-lead"}, dispatchCall("second")); !errors.Is(err, ErrHeld) {
		t.Fatalf("unbounded child admission: %v", err)
	}
}

func TestContextReadAndCheckpoint(t *testing.T) {
	l, _ := openTestLedger(t)
	seedMember(t, l)
	if err := l.SeedContext(testContext, "lead", "routing", "member only"); err != nil {
		t.Fatal(err)
	}
	if err := l.SeedContext(testContext, "lead", "routing", "overwritten"); !errors.Is(err, ErrConflict) {
		t.Fatalf("context overwrite: %v", err)
	}
	executor := &Executor{Ledger: l}
	read := api.ToolCall{ID: "read", IdempotencyKey: "read-key", Tool: "read_context", Mediation: api.MediationControllerMediated, Args: map[string]any{"epoch": 1, "team": "team-a", "key": "routing"}}
	got, err := executor.Execute(testContext, controller.ToolCallContext{SessionUID: "session-member"}, read)
	if err != nil || got.Output["text"] != "member only" {
		t.Fatalf("scoped context read: %+v %v", got, err)
	}
	check := api.ToolCall{ID: "checkpoint", IdempotencyKey: "checkpoint-key", Tool: "checkpoint", Mediation: api.MediationRequiresApproval, Args: map[string]any{"epoch": 1}}
	got, err = executor.Execute(testContext, controller.ToolCallContext{SessionUID: "session-lead"}, check)
	if err != nil || got.Output["checkpoint"] != true {
		t.Fatalf("checkpoint: %+v %v", got, err)
	}
	stats, err := l.Counts(testContext)
	if err != nil || stats.ToolResults != 2 || stats.Effects != 0 {
		t.Fatalf("context/checkpoint effects: %+v %v", stats, err)
	}
}

func TestWrongMemberEpochAndContextScope(t *testing.T) {
	for _, kind := range []string{"member", "epoch", "team", "role", "unbound", "case-alias", "unknown-field"} {
		t.Run(kind, func(t *testing.T) {
			l, _ := openTestLedger(t)
			seedLead(t, l)
			if err := l.SeedContext(testContext, "lead", "routing", "only member"); err != nil {
				t.Fatal(err)
			}
			call, scope, want := dispatchCall("one"), controller.ToolCallContext{SessionUID: "session-lead"}, ErrInvalid
			switch kind {
			case "case-alias":
				call.Args["Member"] = call.Args["member"]
				delete(call.Args, "member")
			case "unknown-field":
				call.Args["ignored"] = "unexpected"
			case "member":
				call.Args["member"] = "unknown"
			case "epoch":
				if err := l.AdvanceEpoch(testContext, "lead", 1, 2); err != nil {
					t.Fatal(err)
				}
				want = ErrHeld
			case "team":
				call.Tool, call.Args = "read_context", map[string]any{"epoch": 1, "team": "other-team", "key": "routing"}
			case "role":
				call = publishCall()
			case "unbound":
				scope.SessionUID, want = "unknown-session", ErrNotFound
			}
			before, _ := l.Counts(testContext)
			got, err := (&Executor{Ledger: l}).Execute(testContext, scope, call)
			if !errors.Is(err, want) || !reflect.DeepEqual(got, api.ToolResult{}) {
				t.Fatalf("scope refusal: %+v %v", got, err)
			}
			after, _ := l.Counts(testContext)
			if before != after {
				t.Fatalf("refusal had effects: %+v -> %+v", before, after)
			}
		})
	}
}
