// Package githubtools retains native Sessions adapter and GitHub release evidence.
// It does not authenticate callers, apply native approvals or dispatch effects.
// This is not decisionledger: that package's records remain non-executing.
package githubtools

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/agent-primitives/sessions/api"
)

var (
	ErrInvalid        = errors.New("invalid GitHub call record")
	ErrConflict       = errors.New("GitHub call record conflict")
	ErrNotFound       = errors.New("GitHub call record not found")
	ErrUnavailable    = errors.New("GitHub call store unavailable; reconcile exact operation")
	ErrUnknownOutcome = errors.New("GitHub operation outcome unknown; do not repost")
)

// Call is evidence from the trusted host's serialized journal inspection, not
// permission supplied by a harness. OperationDigest excludes transport keys and
// binds the exact account/repository/issue/comment operation. CallHash is the
// journal's TOOL_CALL content hash. No credential belongs in this structure.
type Call struct {
	SessionUID, ExecutionID, CallID, Key string
	CallSeq, RequestSeq                  int64
	CallHash, OperationDigest            string
	Requester                            api.CallerIdentity
	AppID, InstallationID, RepositoryID  string
}

type Approval struct {
	Call     Call
	Approver api.CallerIdentity
	Approved bool
	Reason   string
}

type ApprovalRecord struct {
	Approval
	ID            string
	PreparedAt    time.Time
	DecisionSeq   int64
	AbandonedAt   time.Time
	AbandonedHead int64
}

// Outcome is deliberately not a provider response blob. Error details and
// tokens must never enter durable evidence or executor diagnostics.
type Outcome struct {
	Status                      string // succeeded, failed or unknown
	CommentID, URL, FailureCode string
}

type Intent struct {
	Call                      Call
	ApprovalID, ReservationID string
	DecisionSeq               int64
	ReservedAt                time.Time
	Outcome                   *Outcome // nil means sending may have happened; never automatically resend.
}

func textOK(s string, max int) bool {
	if s == "" || len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func digestOK(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}
func decimalID(s string) bool {
	if s == "" || len(s) > 32 || s[0] == '0' {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
func identityOK(i api.CallerIdentity) bool { return textOK(i.Issuer, 256) && textOK(i.Subject, 256) }
func (c Call) valid() bool {
	if !textOK(c.SessionUID, 256) || !textOK(c.ExecutionID, 256) || !textOK(c.CallID, 256) || !textOK(c.Key, 128) || !identityOK(c.Requester) || c.CallSeq <= 0 || c.RequestSeq <= c.CallSeq || !digestOK(c.CallHash) || !digestOK(c.OperationDigest) {
		return false
	}
	for _, b := range []byte(c.Key) {
		if b < 33 || b > 126 {
			return false
		}
	}
	return decimalID(c.AppID) && decimalID(c.InstallationID) && decimalID(c.RepositoryID)
}
func (c Call) slot() string {
	b, _ := json.Marshal([]any{c.SessionUID, c.ExecutionID, c.CallID, c.RequestSeq})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
func (a Approval) valid() bool {
	if !a.Call.valid() || !identityOK(a.Approver) || a.Approver == a.Call.Requester || len(a.Reason) > 2048 || !utf8.ValidString(a.Reason) {
		return false
	}
	for _, r := range a.Reason {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return false
		}
	}
	return true
}
func (r ApprovalRecord) valid() bool {
	if !r.Approval.valid() || !textOK(r.ID, 64) || r.PreparedAt.IsZero() || r.DecisionSeq < 0 || r.DecisionSeq != 0 && r.DecisionSeq <= r.Call.RequestSeq {
		return false
	}
	if r.AbandonedAt.IsZero() {
		return r.AbandonedHead == 0
	}
	return r.DecisionSeq == 0 && r.AbandonedHead >= r.Call.RequestSeq
}
func (o Outcome) valid() bool {
	switch o.Status {
	case "succeeded":
		return decimalID(o.CommentID) && textOK(o.URL, 2048) && o.FailureCode == ""
	case "failed":
		return o.CommentID == "" && o.URL == "" && o.FailureCode == "provider_rejected"
	case "unknown":
		return o.CommentID == "" && o.URL == "" && o.FailureCode == "response_unknown"
	}
	return false
}
func (i Intent) valid(a ApprovalRecord) bool {
	return i.Call == a.Call && i.ApprovalID == a.ID && a.Approved && a.AbandonedAt.IsZero() && a.DecisionSeq > 0 && i.DecisionSeq == a.DecisionSeq && textOK(i.ReservationID, 64) && !i.ReservedAt.IsZero() && (i.Outcome == nil || i.Outcome.valid())
}
