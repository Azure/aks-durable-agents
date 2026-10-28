package githubtools

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/agent-primitives/sessions/api"
	"github.com/agent-primitives/sessions/controller"
	"github.com/agent-primitives/sessions/eventlog"
	"github.com/agent-primitives/sessions/sqlitelog"
)

type githubHarness struct {
	calls           []api.ToolCall
	results         []api.ToolResult
	cancelCall      <-chan struct{}
	independentCall bool
}

func (*githubHarness) Describe(context.Context) (api.Descriptor, error) {
	return api.Descriptor{ID: "github-tools", Capabilities: api.Capabilities{Resumability: api.ResumabilityStatelessReplay}}, nil
}
func (h *githubHarness) Run(ctx context.Context, _ *api.Start, sink api.EventSink) error {
	for _, call := range h.calls {
		parent := ctx
		if h.independentCall {
			parent = context.Background()
		}
		callCtx, cancel := context.WithCancel(parent)
		if h.cancelCall != nil {
			go func() {
				select {
				case <-h.cancelCall:
					cancel()
				case <-callCtx.Done():
				}
			}()
		}
		result, err := sink.ToolCall(callCtx, call)
		cancel()
		if err != nil {
			return err
		}
		h.results = append(h.results, result)
	}
	return nil
}
func sdkController(t *testing.T, log eventlog.Store, tool controller.ToolFunc) *controller.Controller {
	t.Helper()
	c, err := controller.New(log, nil, controller.WithSessionUID("session"), controller.WithToolExecutor(tool), controller.WithDurableDedup(DurableDedup))
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func openJournal(t *testing.T, path string) *sqlitelog.Store {
	t.Helper()
	db, err := sqlitelog.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}
func findCall(log eventlog.Store, call api.ToolCall) (eventlog.Record, error) {
	rows, err := log.Read(1)
	if err != nil {
		return eventlog.Record{}, err
	}
	for _, r := range rows {
		if r.Event.Kind == api.EventToolCall && r.Event.ToolCall != nil && r.Event.ToolCall.ID == call.ID && r.Event.ToolCall.IdempotencyKey == call.IdempotencyKey {
			return r, nil
		}
	}
	return eventlog.Record{}, ErrNotFound
}
func diskLookup(log eventlog.Store, release *Evidence) Lookup {
	return func(_ context.Context, _ controller.ToolCallContext, call api.ToolCall) (Evidence, error) {
		if call.Tool == "comment_on_issue" && release != nil {
			return *release, nil
		}
		record, err := findCall(log, call)
		return Evidence{SessionUID: "session", Record: record, Requester: testApproval().Call.Requester}, err
	}
}
func nativeApprove(t *testing.T, s *Store, log eventlog.Store) Evidence {
	t.Helper()
	state, err := controller.InspectApproval(log, 0)
	if err != nil || state == nil || state.Request == nil {
		t.Fatalf("no native pending request: %+v %v", state, err)
	}
	record, err := findCall(log, *state.Call)
	if err != nil {
		t.Fatal(err)
	}
	a := testApproval()
	a.Call.ExecutionID = state.ExecutionID
	a.Call.CallID = state.Call.ID
	a.Call.Key = state.Call.IdempotencyKey
	a.Call.CallSeq = record.Seq
	a.Call.RequestSeq = state.Request.Seq
	a.Call.CallHash = record.Hash
	a.Call.OperationDigest, err = CommentDigest(*state.Call)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.PrepareApproval(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	decision, err := controller.Approve(log, api.ApprovalDecision{ExecutionID: state.ExecutionID, ToolCallID: state.Call.ID, RequestSeq: state.Request.Seq, Approved: true})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.CommitApproval(t.Context(), a.Call, a.Approver, decision.Seq); err != nil {
		t.Fatal(err)
	}
	return Evidence{SessionUID: "session", Record: record, Approval: a.Call, DecisionSeq: decision.Seq}
}

var errReceiptCut = errors.New("test receipt append cut")

type receiptCut struct {
	eventlog.Store
	lost bool
}

func (l *receiptCut) CheckWritable() error { return eventlog.CheckWritable(l.Store) }
func (l *receiptCut) Append(seq, fence int64, event api.Event) (eventlog.Record, error) {
	if event.Kind == api.EventToolResult && !l.lost {
		l.lost = true
		return eventlog.Record{}, errReceiptCut
	}
	return l.Store.Append(seq, fence, event)
}
func receipts(t *testing.T, log eventlog.Store) []api.ToolResult {
	t.Helper()
	records, err := log.Read(1)
	if err != nil {
		t.Fatal(err)
	}
	var result []api.ToolResult
	for _, r := range records {
		if r.Event.Kind == api.EventToolResult {
			result = append(result, *r.Event.Result)
		}
	}
	return result
}

func TestNativeWriteLostReceiptRepairsThenReadsWithoutReposting(t *testing.T) {
	s, client, counts := executorProvider(t, "")
	path := filepath.Join(t.TempDir(), "journal.db")
	db := openJournal(t, path)
	log := db.Session("session")
	write, read := executorCall(true), executorCall(false)
	read.ID = "read-after-write"
	read.IdempotencyKey = "read-key"
	read.Args["issue_number"] = 7
	h := &githubHarness{calls: []api.ToolCall{write, read}}
	access, err := client.Preflight(t.Context(), "read")
	if err != nil {
		t.Fatal(err)
	}
	c := sdkController(t, log, NewExecutor(t.Context(), s, access, diskLookup(log, nil)))
	if err = c.Exec(t.Context(), h, nil, 0); !errors.Is(err, api.ErrApprovalParked) {
		t.Fatalf("initial call did not park: %v", err)
	}
	release := nativeApprove(t, s, log)
	// Fresh access is acquired outside the executor before each recovery.
	access, err = client.Preflight(t.Context(), "write")
	if err != nil {
		t.Fatal(err)
	}
	cut := &receiptCut{Store: log}
	attempts := 0
	tool := NewExecutor(t.Context(), s, access, diskLookup(log, &release))
	c = sdkController(t, cut, func(ctx context.Context, scope controller.ToolCallContext, call api.ToolCall) (api.ToolResult, error) {
		attempts++
		return tool(ctx, scope, call)
	})
	if resumed, err := c.Resume(t.Context(), h); !resumed || !errors.Is(err, errReceiptCut) {
		t.Fatalf("receipt loss: %v %v", resumed, err)
	}
	if counts.posts.Load() != 1 || counts.gets.Load() != 0 || len(receipts(t, log)) != 0 {
		t.Fatal("wrong crash cut")
	}
	intent, err := s.Intent(t.Context(), release.Approval)
	if err != nil || intent.Outcome == nil || intent.Outcome.Status != "succeeded" {
		t.Fatalf("provider success not durable before receipt: %+v %v", intent, err)
	}
	db.Close()
	s = reopenNative(t, s)
	db = openJournal(t, path)
	log = db.Session("session")
	access, err = client.Preflight(t.Context(), "write")
	if err != nil {
		t.Fatal(err)
	}
	tool = NewExecutor(t.Context(), s, access, diskLookup(log, &release))
	c = sdkController(t, log, func(ctx context.Context, scope controller.ToolCallContext, call api.ToolCall) (api.ToolResult, error) {
		attempts++
		return tool(ctx, scope, call)
	})
	if resumed, err := c.Resume(t.Context(), h); !resumed || err != nil {
		t.Fatalf("repair Resume: %v %v", resumed, err)
	}
	got := receipts(t, log)
	if len(got) != 2 || got[0].IsError || got[0].ApprovalRequestSeq != release.Approval.RequestSeq || got[0].ApprovalDecisionSeq != release.DecisionSeq || got[1].ApprovalDecisionSeq != 0 || got[1].IsError {
		t.Fatalf("wrong native receipts: %+v", got)
	}
	if attempts != 3 || counts.posts.Load() != 1 || counts.gets.Load() != 1 || counts.mints.Load() != 3 {
		t.Fatalf("redrive effect counts: executor=%d post=%d get=%d mint=%d", attempts, counts.posts.Load(), counts.gets.Load(), counts.mints.Load())
	}
	if _, err = c.Replay(t.Context(), h); err != nil {
		t.Fatal(err)
	}
	if attempts != 3 || counts.posts.Load() != 1 || counts.gets.Load() != 1 || counts.mints.Load() != 3 {
		t.Fatal("read-only Replay performed live work")
	}
	if err = controller.VerifyJournal(log); err != nil {
		t.Fatal(err)
	}
}

func TestNativeApprovedErrorConsumesDecision(t *testing.T) {
	s, client, counts := executorProvider(t, "reject")
	db := openJournal(t, filepath.Join(t.TempDir(), "journal.db"))
	log := db.Session("session")
	h := &githubHarness{calls: []api.ToolCall{executorCall(true)}}
	access, err := client.Preflight(t.Context(), "read")
	if err != nil {
		t.Fatal(err)
	}
	c := sdkController(t, log, NewExecutor(t.Context(), s, access, diskLookup(log, nil)))
	if err = c.Exec(t.Context(), h, nil, 0); !errors.Is(err, api.ErrApprovalParked) {
		t.Fatal(err)
	}
	release := nativeApprove(t, s, log)
	access, err = client.Preflight(t.Context(), "write")
	if err != nil {
		t.Fatal(err)
	}
	attempts := 0
	tool := NewExecutor(t.Context(), s, access, diskLookup(log, &release))
	c = sdkController(t, log, func(ctx context.Context, scope controller.ToolCallContext, call api.ToolCall) (api.ToolResult, error) {
		attempts++
		return tool(ctx, scope, call)
	})
	if resumed, err := c.Resume(t.Context(), h); !resumed || err != nil {
		t.Fatalf("executor failure receipt: %v %v", resumed, err)
	}
	got := receipts(t, log)
	if len(got) != 1 || !got[0].IsError || got[0].Code != api.ToolResultCodeExecutorError || got[0].Error != ErrGitHubRejected.Error() || got[0].ApprovalDecisionSeq != release.DecisionSeq {
		t.Fatalf("decision was not consumed: %+v", got)
	}
	if resumed, err := c.Resume(t.Context(), h); resumed || err != nil {
		t.Fatalf("completed error re-entered: %v %v", resumed, err)
	}
	if _, err = c.Replay(t.Context(), h); err != nil {
		t.Fatal(err)
	}
	if attempts != 1 || counts.posts.Load() != 1 {
		t.Fatal("receipted error re-drove provider/executor")
	}
}

func TestNativeReadLookupMultipleAndLostReceipt(t *testing.T) {
	for _, cutFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "two-live-reads", true: "cached-recovery"}[cutFirst], func(t *testing.T) {
			s, client, counts := executorProvider(t, "")
			path := filepath.Join(t.TempDir(), "journal.db")
			db := openJournal(t, path)
			log := db.Session("session")
			first, second := executorCall(false), executorCall(false)
			first.Args["issue_number"] = 7
			second.ID = "second"
			second.IdempotencyKey = "second-key"
			h := &githubHarness{calls: []api.ToolCall{first, second}}
			access, err := client.Preflight(t.Context(), "read")
			if err != nil {
				t.Fatal(err)
			}
			var store eventlog.Store = log
			if cutFirst {
				store = &receiptCut{Store: log}
			}
			c := sdkController(t, store, NewExecutor(t.Context(), s, access, diskLookup(log, nil)))
			err = c.Exec(t.Context(), h, nil, 0)
			if cutFirst {
				if !errors.Is(err, errReceiptCut) || counts.gets.Load() != 1 || len(receipts(t, log)) != 0 {
					t.Fatalf("read receipt cut: %v", err)
				}
				db.Close()
				s = reopenNative(t, s)
				db = openJournal(t, path)
				log = db.Session("session")
				access, err = client.Preflight(t.Context(), "read")
				if err != nil {
					t.Fatal(err)
				}
				c = sdkController(t, log, NewExecutor(t.Context(), s, access, diskLookup(log, nil)))
				if resumed, err := c.Resume(t.Context(), h); !resumed || err != nil {
					t.Fatalf("read repair: %v %v", resumed, err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			got := receipts(t, log)
			if len(got) != 2 || got[0].IsError || got[1].IsError || got[0].ApprovalDecisionSeq != 0 || counts.gets.Load() != 2 {
				t.Fatalf("multiple reads/recovery: %+v get=%d", got, counts.gets.Load())
			}
			beforeMints := counts.mints.Load()
			if _, err = c.Replay(t.Context(), h); err != nil {
				t.Fatal(err)
			}
			if counts.gets.Load() != 2 || counts.mints.Load() != beforeMints {
				t.Fatal("Replay made read/preflight calls")
			}
		})
	}
}

func TestNativeHostCancelAllowsOnlySafeReadRedrive(t *testing.T) {
	for _, write := range []bool{false, true} {
		t.Run(map[bool]string{false: "read", true: "write"}[write], func(t *testing.T) {
			mode := "cancel-read"
			if write {
				mode = "cancel-write"
			}
			s, client, counts := executorProvider(t, mode)
			db := openJournal(t, filepath.Join(t.TempDir(), "journal.db"))
			log := db.Session("session")
			h := &githubHarness{calls: []api.ToolCall{executorCall(write)}, independentCall: true}
			access, err := client.Preflight(t.Context(), "read")
			if err != nil {
				t.Fatal(err)
			}
			var release *Evidence
			if write {
				c := sdkController(t, log, NewExecutor(t.Context(), s, access, diskLookup(log, nil)))
				if err = c.Exec(t.Context(), h, nil, 0); !errors.Is(err, api.ErrApprovalParked) {
					t.Fatal(err)
				}
				captured := nativeApprove(t, s, log)
				release = &captured
				access, err = client.Preflight(t.Context(), "write")
				if err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			c := sdkController(t, log, NewExecutor(ctx, s, access, diskLookup(log, release)))
			done := make(chan error, 1)
			go func() {
				if write {
					_, err := c.Resume(ctx, h)
					done <- err
				} else {
					done <- c.Exec(ctx, h, nil, 0)
				}
			}()
			<-counts.started
			cancel()
			if err = <-done; !errors.Is(err, context.Canceled) || len(receipts(t, log)) != 0 {
				t.Fatalf("host cancellation consumed the call: %v", err)
			}
			permission := "read"
			if write {
				permission = "write"
			}
			access, err = client.Preflight(t.Context(), permission)
			if err != nil {
				t.Fatal(err)
			}
			c = sdkController(t, log, NewExecutor(t.Context(), s, access, diskLookup(log, release)))
			if resumed, err := c.Resume(t.Context(), h); !resumed || err != nil {
				t.Fatalf("cancel recovery: %v %v", resumed, err)
			}
			got := receipts(t, log)
			if len(got) != 1 || got[0].IsError != write {
				t.Fatalf("wrong recovered outcome: %+v", got)
			}
			if write {
				if counts.posts.Load() != 1 || got[0].Error != ErrUnknownOutcome.Error() {
					t.Fatal("unknown write was reposted")
				}
			} else if counts.gets.Load() != 2 {
				t.Fatal("uncached safe read did not re-drive")
			}
		})
	}
}

func TestNativePerCallCancelIsReceiptedWhileHostLives(t *testing.T) {
	s, client, counts := executorProvider(t, "cancel-read")
	db := openJournal(t, filepath.Join(t.TempDir(), "journal.db"))
	log := db.Session("session")
	h := &githubHarness{calls: []api.ToolCall{executorCall(false)}, cancelCall: counts.started}
	access, err := client.Preflight(t.Context(), "read")
	if err != nil {
		t.Fatal(err)
	}
	c := sdkController(t, log, NewExecutor(t.Context(), s, access, diskLookup(log, nil)))
	err = c.Exec(t.Context(), h, nil, 0)
	got := receipts(t, log)
	if err != nil || len(got) != 1 || !got[0].IsError || got[0].Error != ErrGitHubRead.Error() {
		t.Fatalf("per-call cancellation used the host escape: %+v %v", got, err)
	}
	record, err := findCall(log, h.calls[0])
	if err != nil {
		t.Fatal(err)
	}
	call := testReadCall()
	call.CallID = h.calls[0].ID
	call.Key = h.calls[0].IdempotencyKey
	call.ExecutionID = record.Event.ExecutionID
	call.CallSeq = record.Seq
	call.CallHash = record.Hash
	cached, err := s.Read(t.Context(), call)
	if err != nil || cached.Outcome == nil || cached.Outcome.FailureCode != "read_unavailable" {
		t.Fatalf("per-call error was not durable: %+v %v", cached, err)
	}
}

func TestNativePerCallWriteCancelStaysUnknownAndConsumesDecision(t *testing.T) {
	s, client, counts := executorProvider(t, "cancel-write")
	db := openJournal(t, filepath.Join(t.TempDir(), "journal.db"))
	log := db.Session("session")
	h := &githubHarness{calls: []api.ToolCall{executorCall(true)}, cancelCall: counts.started}
	access, err := client.Preflight(t.Context(), "read")
	if err != nil {
		t.Fatal(err)
	}
	c := sdkController(t, log, NewExecutor(t.Context(), s, access, diskLookup(log, nil)))
	if err = c.Exec(t.Context(), h, nil, 0); !errors.Is(err, api.ErrApprovalParked) {
		t.Fatal(err)
	}
	release := nativeApprove(t, s, log)
	access, err = client.Preflight(t.Context(), "write")
	if err != nil {
		t.Fatal(err)
	}
	c = sdkController(t, log, NewExecutor(t.Context(), s, access, diskLookup(log, &release)))
	if resumed, err := c.Resume(t.Context(), h); !resumed || err != nil {
		t.Fatalf("per-call cancellation receipt: %v %v", resumed, err)
	}
	got := receipts(t, log)
	intent, err := s.Intent(t.Context(), release.Approval)
	if err != nil || len(got) != 1 || !got[0].IsError || got[0].Code != api.ToolResultCodeExecutorError || got[0].Error != ErrUnknownOutcome.Error() || intent.Outcome == nil || intent.Outcome.Status != "unknown" {
		t.Fatalf("cancelled POST was downgraded: %+v %+v %v", got, intent, err)
	}
	if resumed, err := c.Resume(t.Context(), h); resumed || err != nil || counts.posts.Load() != 1 {
		t.Fatalf("cancelled POST re-drove: %v %v", resumed, err)
	}
}

func TestNativeReadErrorsMustBeErrorResults(t *testing.T) {
	for _, production := range []bool{false, true} {
		t.Run(map[bool]string{false: "raw-Go-error-control", true: "receipted-error-result"}[production], func(t *testing.T) {
			s, client, counts := executorProvider(t, "read-error")
			db := openJournal(t, filepath.Join(t.TempDir(), "journal.db"))
			log := db.Session("session")
			h := &githubHarness{calls: []api.ToolCall{executorCall(false)}}
			access, err := client.Preflight(t.Context(), "read")
			if err != nil {
				t.Fatal(err)
			}
			tool := controller.ToolFunc(func(context.Context, controller.ToolCallContext, api.ToolCall) (api.ToolResult, error) {
				return api.ToolResult{}, ErrGitHubRead
			})
			if production {
				tool = NewExecutor(t.Context(), s, access, diskLookup(log, nil))
			}
			c := sdkController(t, log, tool)
			err = c.Exec(t.Context(), h, nil, 0)
			got := receipts(t, log)
			if !production {
				if err == nil || len(got) != 0 {
					t.Fatalf("Go error unexpectedly receipted: %+v %v", got, err)
				}
				return
			}
			if err != nil || len(got) != 1 || !got[0].IsError || got[0].Error != ErrGitHubRead.Error() || got[0].ApprovalRequestSeq != 0 || got[0].ApprovalDecisionSeq != 0 {
				t.Fatalf("terminal read error unanswered: %+v %v", got, err)
			}
			if _, err = c.Replay(t.Context(), h); err != nil {
				t.Fatal(err)
			}
			if counts.gets.Load() != 1 {
				t.Fatal("error receipt re-drove GET")
			}
		})
	}
}
