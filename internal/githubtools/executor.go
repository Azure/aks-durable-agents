package githubtools

import (
	"context"
	"errors"

	"github.com/agent-primitives/sessions/api"
	"github.com/agent-primitives/sessions/controller"
	"github.com/agent-primitives/sessions/eventlog"
)

// Evidence is supplied by the trusted host, not the harness. A write's Approval
// and DecisionSeq must be the immutable tuple admitted before delegation. Reads
// have only a verified Requester and the newly committed TOOL_CALL record.
type Evidence struct {
	SessionUID  string
	Record      eventlog.Record
	Requester   api.CallerIdentity
	Approval    Call
	DecisionSeq int64
}

// Lookup inspects committed journal evidence by UID/call ID/key under the
// already-held host gate. It must not mint credentials, acquire another gate or
// call a Sessions RPC. The executor verifies binding, not journal membership.
type Lookup func(context.Context, controller.ToolCallContext, api.ToolCall) (Evidence, error)

// NewExecutor captures the original Exec/Resume host context and preflighted
// access once for that delegation, not a mutable
// current-call registry. Lookup supports first-live/multiple reads and a read
// after approved recovery. Serving authorization and head CAS remain host work.
func NewExecutor(hostCtx context.Context, store *Store, access *Access, lookup Lookup) controller.ToolFunc {
	if access != nil {
		copy := *access
		access = &copy
	}
	return func(ctx context.Context, scope controller.ToolCallContext, call api.ToolCall) (api.ToolResult, error) {
		if hostCtx.Err() != nil {
			return api.ToolResult{}, hostCtx.Err()
		}
		ioCtx, cancel := context.WithCancel(ctx)
		stop := context.AfterFunc(hostCtx, cancel)
		defer func() { stop(); cancel() }()
		if hostCtx.Err() != nil {
			cancel()
		}
		result, err := dispatch(ioCtx, hostCtx, store, access, lookup, scope, call)
		if hostCtx.Err() != nil {
			return api.ToolResult{}, hostCtx.Err()
		}
		// Ordinary ToolFunc Go errors leave unanswered calls in v0.3.0. Terminal
		// read errors instead need error results so they cannot silently re-drive.
		if call.Tool == "get_issue" && err != nil {
			return readError(call.ID, err), nil
		}
		return result, err
	}
}
func dispatch(ctx, recordCtx context.Context, s *Store, access *Access, lookup Lookup, scope controller.ToolCallContext, call api.ToolCall) (api.ToolResult, error) {
	request, err := ParseRequest(call)
	if err != nil {
		return api.ToolResult{}, err
	}
	call, err = snapshotCall(call)
	if err != nil {
		return api.ToolResult{}, err
	}
	if s == nil || lookup == nil {
		return api.ToolResult{}, ErrUnavailable
	}
	if access == nil {
		return api.ToolResult{}, ErrGitHubAccess
	}
	if !request.matches(access.account) {
		return api.ToolResult{}, ErrConflict
	}
	// Give the lookup its own copy: it cannot change the call we later dispatch.
	lookupCall, err := snapshotCall(call)
	if err != nil {
		return api.ToolResult{}, err
	}
	evidence, err := lookup(ctx, scope, lookupCall)
	if err != nil {
		return api.ToolResult{}, ErrUnavailable
	}
	if evidence.SessionUID != scope.SessionUID {
		return api.ToolResult{}, ErrConflict
	}
	record, err := matchedRecord(evidence.Record, call)
	if err != nil {
		return api.ToolResult{}, err
	}
	if call.Tool == "comment_on_issue" {
		bound := evidence.Approval
		digest, err := CommentDigest(call)
		if err != nil || !bound.valid() || scope.SessionUID != bound.SessionUID || record.Event.ExecutionID != bound.ExecutionID || record.Seq != bound.CallSeq || record.Hash != bound.CallHash || call.ID != bound.CallID || call.IdempotencyKey != bound.Key || digest != bound.OperationDigest || request.AppID != bound.AppID || request.InstallationID != bound.InstallationID || request.RepositoryID != bound.RepositoryID {
			return api.ToolResult{}, ErrConflict
		}
		return executeWrite(ctx, recordCtx, s, access, call.ID, bound, evidence.DecisionSeq, request)
	}
	if evidence.Approval != (Call{}) || evidence.DecisionSeq != 0 {
		return api.ToolResult{}, ErrConflict
	}
	read := ReadCall{SessionUID: evidence.SessionUID, ExecutionID: record.Event.ExecutionID, CallID: call.ID, Key: call.IdempotencyKey, CallSeq: record.Seq, CallHash: record.Hash, Requester: evidence.Requester, AppID: request.AppID, InstallationID: request.InstallationID, RepositoryID: request.RepositoryID, IssueNumber: request.IssueNumber}
	return executeRead(ctx, recordCtx, s, access, read)
}
func executeWrite(ctx, recordCtx context.Context, s *Store, access *Access, id string, call Call, decision int64, request Request) (api.ToolResult, error) {
	intent, created, err := s.Reserve(ctx, call, decision)
	if err != nil {
		return api.ToolResult{}, err
	}
	if created {
		comment, providerErr := access.CommentOnIssue(ctx, request.IssueNumber, request.Body)
		outcome := Outcome{Status: "unknown", FailureCode: "response_unknown"}
		switch {
		case providerErr == nil:
			outcome = Outcome{Status: "succeeded", CommentID: comment.ID, URL: comment.URL}
		case errors.Is(providerErr, ErrGitHubRejected):
			outcome = Outcome{Status: "failed", FailureCode: "provider_rejected"}
		case errors.Is(providerErr, ErrGitHubAccess):
			outcome = Outcome{Status: "failed", FailureCode: "access_unavailable"}
		case errors.Is(providerErr, ErrGitHubInput):
			outcome = Outcome{Status: "failed", FailureCode: "invalid_request"}
		}
		if err = s.Finish(recordCtx, call, intent.ReservationID, outcome); err != nil {
			return api.ToolResult{}, err
		}
		intent.Outcome = &outcome
	}
	if intent.Outcome == nil {
		return api.ToolResult{}, ErrUnknownOutcome
	}
	switch intent.Outcome.Status {
	case "succeeded":
		return api.ToolResult{ID: id, Output: map[string]any{"comment_id": intent.Outcome.CommentID, "url": intent.Outcome.URL}}, nil
	case "failed":
		switch intent.Outcome.FailureCode {
		case "provider_rejected":
			return api.ToolResult{}, ErrGitHubRejected
		case "access_unavailable":
			return api.ToolResult{}, ErrGitHubAccess
		case "invalid_request":
			return api.ToolResult{}, ErrGitHubInput
		}
	}
	return api.ToolResult{}, ErrUnknownOutcome
}
func executeRead(ctx, recordCtx context.Context, s *Store, access *Access, call ReadCall) (api.ToolResult, error) {
	record, err := s.PrepareRead(ctx, call)
	if err != nil {
		return api.ToolResult{}, err
	}
	if record.Outcome == nil {
		issue, providerErr := access.GetIssue(ctx, call.IssueNumber)
		outcome := ReadOutcome{Issue: issue}
		if providerErr != nil {
			outcome = ReadOutcome{FailureCode: "read_unavailable"}
			if errors.Is(providerErr, ErrGitHubAccess) {
				outcome.FailureCode = "access_unavailable"
			}
		}
		record, err = s.SaveRead(recordCtx, call, outcome)
		if err != nil {
			return api.ToolResult{}, err
		}
	}
	switch record.Outcome.FailureCode {
	case "read_unavailable":
		return readError(call.CallID, ErrGitHubRead), nil
	case "access_unavailable":
		return readError(call.CallID, ErrGitHubAccess), nil
	}
	issue := record.Outcome.Issue
	return api.ToolResult{ID: call.CallID, Output: map[string]any{"issue_number": float64(issue.Number), "title": issue.Title, "body": issue.Body, "url": issue.URL}}, nil
}
func readError(id string, err error) api.ToolResult {
	return api.ToolResult{ID: id, IsError: true, Error: err.Error(), Output: map[string]any{"error": err.Error()}}
}

// DurableDedup is only for unanswered ordinary reads. Native approved-write
// recovery already re-enters its exact call independently of this declaration.
func DurableDedup(tool string) bool { return tool == "get_issue" }
