package githubtools

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agent-primitives/sessions/api"
	"github.com/agent-primitives/sessions/canon"
	"github.com/agent-primitives/sessions/controller"
	"github.com/agent-primitives/sessions/eventlog"
)

func executorCall(write bool) api.ToolCall {
	call := api.ToolCall{ID: "call", Tool: "get_issue", Mediation: api.MediationControllerMediated, IdempotencyKey: "key", Args: map[string]any{"app_id": "1", "installation_id": "2", "repository_id": "3", "issue_number": float64(7)}}
	if write {
		call.Tool = "comment_on_issue"
		call.Mediation = api.MediationRequiresApproval
		call.Args["body"] = "  exact <>& comment\n"
	}
	return call
}
func cloneTestCall(t *testing.T, call api.ToolCall) api.ToolCall {
	t.Helper()
	raw, err := json.Marshal(call)
	if err != nil {
		t.Fatal(err)
	}
	var next api.ToolCall
	if json.Unmarshal(raw, &next) != nil {
		t.Fatal("clone call")
	}
	return next
}
func callRecord(t *testing.T, call api.ToolCall) eventlog.Record {
	t.Helper()
	r := eventlog.Record{Seq: 3, PrevHash: strings.Repeat("a", 64), Event: api.Event{Kind: api.EventToolCall, ExecutionID: "execution", Timestamp: clientTime, ToolCall: &call}}
	hash, err := canon.HashRecord(r.PrevHash, r.Seq, r.Event)
	if err != nil {
		t.Fatal(err)
	}
	r.Hash = hash
	return r
}
func writeEvidence(t *testing.T, s *Store, call api.ToolCall) Evidence {
	t.Helper()
	record := callRecord(t, cloneTestCall(t, call))
	a := testApproval()
	a.Call.CallHash = record.Hash
	a.Call.CallID = call.ID
	a.Call.Key = call.IdempotencyKey
	digest, err := CommentDigest(call)
	if err != nil {
		t.Fatal(err)
	}
	a.Call.OperationDigest = digest
	if err = s.PrepareApproval(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	if err = s.CommitApproval(t.Context(), a.Call, a.Approver, 5); err != nil {
		t.Fatal(err)
	}
	return Evidence{SessionUID: a.Call.SessionUID, Record: record, Approval: a.Call, DecisionSeq: 5}
}

type providerCounts struct {
	mints, posts, gets atomic.Int32
	started            chan struct{}
}

func executorProvider(t *testing.T, mode string) (*Store, *Client, *providerCounts) {
	t.Helper()
	s := testStore(t)
	counts := &providerCounts{started: make(chan struct{})}
	client, _ := clientFixture(t, func(w http.ResponseWriter, r *http.Request, _ *rsa.PrivateKey) {
		if strings.HasSuffix(r.URL.Path, "/access_tokens") {
			counts.mints.Add(1)
			var request struct {
				Permissions map[string]string `json:"permissions"`
			}
			if json.NewDecoder(r.Body).Decode(&request) != nil {
				t.Error("invalid preflight body")
				w.WriteHeader(400)
				return
			}
			replyJSON(w, 201, tokenReply(request.Permissions["issues"]))
			return
		}
		if r.Method == "GET" {
			attempt := counts.gets.Add(1)
			if mode == "cancel-read" && attempt == 1 {
				close(counts.started)
				<-r.Context().Done()
				return
			}
			if mode == "read-error" {
				w.WriteHeader(404)
				return
			}
			replyJSON(w, 200, map[string]any{"number": 7, "title": "Issue title", "body": "read body\n", "html_url": "display"})
			return
		}
		var request struct {
			Body string `json:"body"`
		}
		if json.NewDecoder(r.Body).Decode(&request) != nil || request.Body != "  exact <>& comment\n" {
			t.Error("posted different body")
		}
		attempt := counts.posts.Add(1)
		if mode == "cancel-write" && attempt == 1 {
			close(counts.started)
			<-r.Context().Done()
			return
		}
		if mode == "drop" {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			conn.Close()
			return
		}
		if mode == "close-store" {
			s.Close()
		}
		if mode == "reject" {
			w.WriteHeader(403)
			return
		}
		replyJSON(w, 201, map[string]any{"id": 42, "html_url": "https://github.com/example/repo/issues/7?view=full#comment-42"})
	})
	return s, client, counts
}
func executorFixture(t *testing.T, mode string) (*Store, *Access, *providerCounts) {
	t.Helper()
	s, client, counts := executorProvider(t, mode)
	access, err := client.Preflight(t.Context(), "write")
	if err != nil {
		t.Fatal(err)
	}
	return s, access, counts
}
func fixedLookup(e Evidence) Lookup {
	return func(context.Context, controller.ToolCallContext, api.ToolCall) (Evidence, error) { return e, nil }
}

var executorScope = controller.ToolCallContext{SessionUID: "session"}

func TestExecutorExactBindingRefusesBeforePOST(t *testing.T) {
	for _, kind := range []string{"id", "key", "body", "account", "mediation", "scope", "execution", "prev-hash", "record-hash", "digest", "decision", "missing-approval", "lookup-error"} {
		t.Run(kind, func(t *testing.T) {
			s, access, counts := executorFixture(t, "")
			call := executorCall(true)
			e := writeEvidence(t, s, call)
			scope := executorScope
			switch kind {
			case "id":
				call.ID = "different"
			case "key":
				call.IdempotencyKey = "different"
			case "body":
				call.Args["body"] = "changed"
			case "account":
				copy := *access
				copy.account.RepositoryID = "4"
				access = &copy
			case "mediation":
				call.Mediation = api.MediationControllerMediated
			case "scope":
				scope.SessionUID = "other"
			case "execution":
				e.Approval.ExecutionID = "different"
			case "prev-hash":
				e.Record.PrevHash = strings.Repeat("c", 64)
			case "record-hash":
				e.Record.Hash = strings.Repeat("c", 64)
			case "digest":
				e.Approval.OperationDigest = strings.Repeat("c", 64)
			case "decision":
				e.DecisionSeq++
			case "missing-approval":
				e.Approval = Call{}
			}
			lookup := fixedLookup(e)
			if kind == "lookup-error" {
				lookup = func(context.Context, controller.ToolCallContext, api.ToolCall) (Evidence, error) {
					return Evidence{}, errors.New("sensitive-host-detail")
				}
			}
			run := NewExecutor(t.Context(), s, access, lookup)
			result, err := run(t.Context(), scope, call)
			if err == nil || result.Output != nil || strings.Contains(err.Error(), "sensitive-host-detail") {
				t.Fatalf("binding admitted: %+v %v", result, err)
			}
			if counts.posts.Load() != 0 || counts.mints.Load() != 1 {
				t.Fatalf("binding caused effect/refresh: posts=%d mints=%d", counts.posts.Load(), counts.mints.Load())
			}
		})
	}
}
func TestRequestParsingAndSemanticDigest(t *testing.T) {
	call := executorCall(true)
	first, err := CommentDigest(call)
	if err != nil {
		t.Fatal(err)
	}
	call.ID = "new"
	call.IdempotencyKey = "new-key"
	call.Args["issue_number"] = 7
	second, err := CommentDigest(call)
	if err != nil || first != second {
		t.Fatal("transport/numeric representation changed semantic digest")
	}
	call.Args["body"] = "different"
	third, _ := CommentDigest(call)
	if third == first {
		t.Fatal("body absent from semantic digest")
	}
	for _, kind := range []string{"extra", "fraction", "unsafe-number", "string-number", "missing-body", "wrong-id", "wrong-tool"} {
		t.Run(kind, func(t *testing.T) {
			call := executorCall(true)
			switch kind {
			case "extra":
				call.Args["url"] = "https://other.invalid"
			case "fraction":
				call.Args["issue_number"] = 7.5
			case "unsafe-number":
				call.Args["issue_number"] = float64(1 << 53)
			case "string-number":
				call.Args["issue_number"] = "7"
			case "missing-body":
				delete(call.Args, "body")
			case "wrong-id":
				call.Args["app_id"] = "01"
			case "wrong-tool":
				call.Tool = "other"
			}
			if _, err := ParseRequest(call); err == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
	if !DurableDedup("get_issue") || DurableDedup("other") || DurableDedup("comment_on_issue") {
		t.Fatal("incorrect ordinary recovery declaration")
	}
}
func TestExecutorWriteSingleOwnerAndSavedResult(t *testing.T) {
	s, access, counts := executorFixture(t, "")
	call := executorCall(true)
	e := writeEvidence(t, s, call)
	run := NewExecutor(t.Context(), s, access, fixedLookup(e))
	var work sync.WaitGroup
	for range 8 {
		work.Go(func() {
			_, err := run(t.Context(), executorScope, call)
			if err != nil && !errors.Is(err, ErrUnknownOutcome) {
				t.Errorf("concurrent release: %v", err)
			}
		})
	}
	work.Wait()
	first, err := run(t.Context(), executorScope, call)
	if err != nil {
		t.Fatal(err)
	}
	if first.Output["comment_id"] != "42" || counts.posts.Load() != 1 {
		t.Fatalf("wrong effect/result: %+v posts=%d", first, counts.posts.Load())
	}
	s = reopenNative(t, s)
	run = NewExecutor(t.Context(), s, access, fixedLookup(e))
	again, err := run(t.Context(), executorScope, call)
	if err != nil || !reflect.DeepEqual(first, again) || counts.posts.Load() != 1 || counts.mints.Load() != 1 {
		t.Fatalf("saved success changed/reposted: %+v %v", again, err)
	}
}
func TestExecutorUnknownAndLocalFailureCuts(t *testing.T) {
	for _, mode := range []string{"drop", "close-store", "reject", "expired", "wire-input", "before-reserve"} {
		t.Run(mode, func(t *testing.T) {
			s, access, counts := executorFixture(t, mode)
			call := executorCall(true)
			if mode == "wire-input" {
				call.Args["body"] = strings.Repeat("<", 180000)
			}
			e := writeEvidence(t, s, call)
			if mode == "expired" {
				now := clientTime
				access.now = func() time.Time { return now }
				s.now = func() time.Time { now = access.expiresAt; return clientTime }
			}
			if mode == "before-reserve" {
				s.Close()
			}
			_, err := NewExecutor(t.Context(), s, access, fixedLookup(e))(t.Context(), executorScope, call)
			if err == nil {
				t.Fatal("failure cut returned success")
			}
			if mode == "before-reserve" {
				if counts.posts.Load() != 0 {
					t.Fatal("posted without reserve")
				}
				return
			}
			if (mode == "expired" || mode == "wire-input") && counts.posts.Load() != 0 {
				t.Fatal("expired access posted")
			}
			if mode != "expired" && mode != "wire-input" && counts.posts.Load() != 1 {
				t.Fatalf("POST count=%d", counts.posts.Load())
			}
			s = reopenNative(t, s)
			if mode == "expired" {
				intent, _ := s.Intent(t.Context(), e.Approval)
				if intent.Outcome == nil || intent.Outcome.FailureCode != "access_unavailable" {
					t.Fatalf("false provider rejection: %+v", intent)
				}
			}
			_, againErr := NewExecutor(t.Context(), s, access, fixedLookup(e))(t.Context(), executorScope, call)
			if mode == "reject" {
				if !errors.Is(err, ErrGitHubRejected) || !errors.Is(againErr, ErrGitHubRejected) {
					t.Fatal("rejection was not immutable")
				}
			}
			if mode == "drop" || mode == "close-store" {
				if !errors.Is(againErr, ErrUnknownOutcome) {
					t.Fatalf("unknown became resend: %v", againErr)
				}
				next := cloneTestCall(t, call)
				next.ID = "next"
				next.IdempotencyKey = "next-key"
				a := testApproval()
				a.Call = e.Approval
				a.Call.CallID = next.ID
				a.Call.Key = next.IdempotencyKey
				a.Call.SessionUID = "other-session"
				record := callRecord(t, next)
				a.Call.CallHash = record.Hash
				if err := s.PrepareApproval(t.Context(), a); err != nil {
					t.Fatal(err)
				}
				if err := s.CommitApproval(t.Context(), a.Call, a.Approver, 5); err != nil {
					t.Fatal(err)
				}
				nextEvidence := Evidence{SessionUID: a.Call.SessionUID, Record: record, Approval: a.Call, DecisionSeq: 5}
				if _, err := NewExecutor(t.Context(), s, access, fixedLookup(nextEvidence))(t.Context(), controller.ToolCallContext{SessionUID: "other-session"}, next); !errors.Is(err, ErrUnknownOutcome) {
					t.Fatalf("new key/session bypassed unknown: %v", err)
				}
			}
			want := int32(1)
			if mode == "expired" || mode == "wire-input" {
				want = 0
			}
			if mode == "wire-input" && (!errors.Is(err, ErrGitHubInput) || !errors.Is(againErr, ErrGitHubInput)) {
				t.Fatal("pre-send input failure changed on re-entry")
			}
			if counts.posts.Load() != want || counts.mints.Load() != 1 {
				t.Fatal("failure re-entry reposted or refreshed")
			}
		})
	}
}
func TestExecutorIntentBeforeSendDoesNotAuthorizeRecovery(t *testing.T) {
	s, access, counts := executorFixture(t, "")
	call := executorCall(true)
	e := writeEvidence(t, s, call)
	if _, created, err := s.Reserve(t.Context(), e.Approval, e.DecisionSeq); err != nil || !created {
		t.Fatalf("initial reservation: %v %v", created, err)
	}
	s = reopenNative(t, s)
	if _, err := NewExecutor(t.Context(), s, access, fixedLookup(e))(t.Context(), executorScope, call); !errors.Is(err, ErrUnknownOutcome) || counts.posts.Load() != 0 {
		t.Fatalf("pre-send crash became automatic POST: %v", err)
	}
}

func TestExecutorReadRejectsWrongScope(t *testing.T) {
	s, access, counts := executorFixture(t, "")
	call := executorCall(false)
	e := Evidence{SessionUID: "session", Record: callRecord(t, call), Requester: testApproval().Call.Requester}
	result, err := NewExecutor(t.Context(), s, access, fixedLookup(e))(t.Context(), controller.ToolCallContext{SessionUID: "other"}, call)
	if err != nil || !result.IsError || result.Error != ErrConflict.Error() || counts.gets.Load() != 0 {
		t.Fatalf("read scope mismatch admitted: %+v %v", result, err)
	}
}

func TestExecutorReadCacheAndErrorResult(t *testing.T) {
	for _, mode := range []string{"", "read-error"} {
		t.Run(mode, func(t *testing.T) {
			s, access, counts := executorFixture(t, mode)
			call := executorCall(false)
			e := Evidence{SessionUID: "session", Record: callRecord(t, call), Requester: testApproval().Call.Requester}
			run := NewExecutor(t.Context(), s, access, fixedLookup(e))
			first, err := run(t.Context(), executorScope, call)
			if err != nil || first.IsError != (mode == "read-error") {
				t.Fatalf("read was not a receiptable result: %+v %v", first, err)
			}
			s = reopenNative(t, s)
			again, err := NewExecutor(t.Context(), s, access, fixedLookup(e))(t.Context(), executorScope, call)
			if err != nil || !reflect.DeepEqual(first, again) || counts.gets.Load() != 1 {
				t.Fatalf("read cache changed/repeated: %+v %v", again, err)
			}
			if mode == "" {
				if _, ok := again.Output["issue_number"].(float64); !ok {
					t.Fatal("result did not normalize JSON number")
				}
			}
			s.Close()
			failed, err := NewExecutor(t.Context(), s, access, fixedLookup(e))(t.Context(), executorScope, call)
			if err != nil || !failed.IsError || failed.Error != ErrUnavailable.Error() {
				t.Fatalf("cache error left read unanswered: %+v %v", failed, err)
			}
		})
	}
}
