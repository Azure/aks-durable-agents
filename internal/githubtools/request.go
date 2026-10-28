package githubtools

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"unicode/utf8"

	"github.com/agent-primitives/sessions/api"
	"github.com/agent-primitives/sessions/canon"
	"github.com/agent-primitives/sessions/eventlog"
)

// Request has no URL or repository-name selector: the preflighted account owns
// the destination. Opaque identifiers remain decimal strings across wire replay.
type Request struct {
	AppID, InstallationID, RepositoryID string
	IssueNumber                         int64
	Body                                string
}

func snapshotCall(call api.ToolCall) (api.ToolCall, error) {
	raw, err := json.Marshal(call)
	if err != nil {
		return api.ToolCall{}, ErrInvalid
	}
	var copy api.ToolCall
	if json.Unmarshal(raw, &copy) != nil {
		return api.ToolCall{}, ErrInvalid
	}
	return copy, nil
}
func ParseRequest(call api.ToolCall) (Request, error) {
	var r Request
	size := 4
	switch call.Tool {
	case "get_issue":
		if call.Mediation != api.MediationControllerMediated {
			return r, ErrInvalid
		}
	case "comment_on_issue":
		if call.Mediation != api.MediationRequiresApproval {
			return r, ErrInvalid
		}
		size = 5
	default:
		return r, ErrInvalid
	}
	if len(call.Args) != size {
		return r, ErrInvalid
	}
	for key, target := range map[string]*string{"app_id": &r.AppID, "installation_id": &r.InstallationID, "repository_id": &r.RepositoryID} {
		value, ok := call.Args[key].(string)
		if !ok || !decimalID(value) {
			return r, ErrInvalid
		}
		*target = value
	}
	if size == 5 {
		body, ok := call.Args["body"].(string)
		if !ok || !utf8.ValidString(body) || len(body) > githubBodyLimit {
			return r, ErrInvalid
		}
		r.Body = body
	}
	copy, err := snapshotCall(call)
	if err != nil {
		return r, err
	}
	number, ok := copy.Args["issue_number"].(float64)
	if !ok || math.IsNaN(number) || math.IsInf(number, 0) || number <= 0 || number > 1<<53-1 || math.Trunc(number) != number {
		return r, ErrInvalid
	}
	r.IssueNumber = int64(number)
	return r, nil
}

// CommentDigest excludes call IDs, keys and sessions so an unknown comment
// holds the same semantic operation even under new transport identities.
func CommentDigest(call api.ToolCall) (string, error) {
	r, err := ParseRequest(call)
	if err != nil || call.Tool != "comment_on_issue" {
		return "", ErrInvalid
	}
	raw, _ := json.Marshal([]any{call.Tool, r.AppID, r.InstallationID, r.RepositoryID, r.IssueNumber, r.Body})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
func matchedRecord(record eventlog.Record, call api.ToolCall) (eventlog.Record, error) {
	raw, err := json.Marshal(record)
	if err != nil {
		return record, ErrInvalid
	}
	var copy eventlog.Record
	if json.Unmarshal(raw, &copy) != nil || copy.Seq <= 0 || !digestOK(copy.Hash) || copy.Event.Kind != api.EventToolCall || copy.Event.ToolCall == nil || !textOK(copy.Event.ExecutionID, 256) {
		return copy, ErrInvalid
	}
	hash, err := canon.HashRecord(copy.PrevHash, copy.Seq, copy.Event)
	if err != nil || hash != copy.Hash {
		return copy, ErrConflict
	}
	copy.Event.ToolCall = &call
	hash, err = canon.HashRecord(copy.PrevHash, copy.Seq, copy.Event)
	if err != nil || hash != copy.Hash {
		return copy, ErrConflict
	}
	return copy, nil
}
func (r Request) matches(a GitHubAccount) bool {
	return r.AppID == a.AppID && r.InstallationID == a.InstallationID && r.RepositoryID == a.RepositoryID
}
