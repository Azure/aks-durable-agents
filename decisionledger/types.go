// Package decisionledger records non-executing, host-authorized human decisions.
// It has no production listener or execution adapter. Trusted host code owns
// subject registration and must supply a durable resource-policy guard.
package decisionledger

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/agent-primitives/sessions/api"
)

var (
	ErrInvalid         = errors.New("invalid decision request")
	ErrUnauthenticated = errors.New("human credential unavailable or expired")
	ErrDenied          = errors.New("decision access denied")
	ErrNotFound        = errors.New("decision not found")
	ErrConflict        = errors.New("decision conflict")
	ErrUnavailable     = errors.New("decision store unavailable; reconcile exact request")
)

type Kind string
type Action string

const (
	SuiteKind        Kind   = "suite_version"
	EffectKind       Kind   = "effect_approval"
	Accept           Action = "accept"
	Reject           Action = "reject"
	RequestChanges   Action = "request_changes"
	Approve          Action = "approve"
	Deny             Action = "deny"
	NonExecutingMode        = "non_executing_decision_v1"
)

// SubjectRef includes kind in its namespace; a digest never grants authority.
type SubjectRef struct {
	Workspace  string
	Kind       Kind
	ID         string
	Generation uint64
	Digest     string
}
type SuiteProposal struct {
	ProposalID, TargetID, ExpectedVersion         string
	ExpectedRevision                              uint64
	Intent, OperationKey                          string
	PredecessorDigest, SuiteDigest                string
	Member, Composition, Platform                 string
	InventoryDigest, CasesDigest, BindingDigest   string
	QualificationID, EvidenceDigest, SourceDigest string
}
type EffectApproval struct {
	SessionID, ExecutionID                            string
	RequestSequence                                   uint64
	ToolCallID, OperationID, VersionID, InputRevision string
	InputDigest, ArgumentsDigest                      string
}

// Subject is a closed union of host-retained snapshots. BindingDigest identifies
// the complete runtime/model/harness/binding tuple, not merely a model name.
type Subject struct {
	Workspace  string
	Kind       Kind
	ID         string
	Generation uint64
	Resource   string
	ExpiresAt  time.Time
	Source     string
	Suite      *SuiteProposal
	Effect     *EffectApproval
}

type DecideRequest struct {
	Workspace, Key string
	Subject        SubjectRef
	Action         Action
	Feedback       string
}

// Authorization is supplied by trusted policy, never by a decision request.
// It must match this exact person, subject and action, while policy remains held.
type Authorization struct {
	Actor               api.CallerIdentity
	Subject             SubjectRef
	Action              Action
	Role, PolicyVersion string
	GrantIDs            []string
}
type DecisionRecord struct {
	ID, StoreID, HostLineageID string
	Request                    DecideRequest
	RequestDigest              string
	Actor                      api.CallerIdentity
	Outcome                    string // recorded or refused; reject/deny are explicit human actions.
	RefusalCode                string
	Authorization              *Authorization
	CommittedAt                time.Time
	Mode                       string
}

func textOK(s string, max int) bool {
	if len(s) == 0 || len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func keyOK(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, b := range []byte(s) {
		if b < 33 || b > 126 {
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
func validAction(k Kind, a Action) bool {
	switch k {
	case SuiteKind:
		return a == Accept || a == Reject || a == RequestChanges
	case EffectKind:
		return a == Approve || a == Deny
	}
	return false
}
func (r SubjectRef) valid() bool {
	return textOK(r.Workspace, 256) && textOK(r.ID, 256) && (r.Kind == SuiteKind || r.Kind == EffectKind) && r.Generation > 0 && r.Generation <= math.MaxInt64 && digestOK(r.Digest)
}

// hashFields is a domain-separated, ordered length-prefix encoding. No maps or
// mutable evidence bytes participate; all referenced digests are validated first.
func hashFields(domain string, fields ...string) string {
	h := sha256.New()
	for _, s := range append([]string{domain}, fields...) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	return hex.EncodeToString(h.Sum(nil))
}
func number(n uint64) string { var b [8]byte; binary.BigEndian.PutUint64(b[:], n); return string(b[:]) }
func (s Subject) Reference() (SubjectRef, error) {
	bad := func() (SubjectRef, error) { return SubjectRef{}, ErrInvalid }
	if !textOK(s.Workspace, 256) || !textOK(s.ID, 256) || !textOK(s.Resource, 256) || !textOK(s.Source, 256) || s.Generation == 0 || s.Generation > math.MaxInt64 || s.ExpiresAt.IsZero() || s.ExpiresAt.Year() < 1970 || s.ExpiresAt.Year() > 9999 {
		return bad()
	}
	fields := []string{s.Workspace, string(s.Kind), s.ID, number(s.Generation), s.Resource, s.ExpiresAt.UTC().Format(time.RFC3339Nano), s.Source}
	var ids, digests []string
	switch s.Kind {
	case SuiteKind:
		if s.Suite == nil || s.Effect != nil {
			return bad()
		}
		p := s.Suite
		if p.Intent != "activate" || p.TargetID != s.Resource || p.ExpectedRevision == 0 || p.ExpectedRevision > math.MaxInt64 || !keyOK(p.OperationKey) {
			return bad()
		}
		ids = []string{p.ProposalID, p.TargetID, p.ExpectedVersion, p.Intent, p.OperationKey, p.Member, p.Composition, p.Platform, p.QualificationID}
		digests = []string{p.PredecessorDigest, p.SuiteDigest, p.InventoryDigest, p.CasesDigest, p.BindingDigest, p.EvidenceDigest, p.SourceDigest}
		fields = append(fields, number(p.ExpectedRevision))
	case EffectKind:
		if s.Effect == nil || s.Suite != nil {
			return bad()
		}
		p := s.Effect
		if p.RequestSequence == 0 || p.RequestSequence > math.MaxInt64 {
			return bad()
		}
		ids = []string{p.SessionID, p.ExecutionID, p.ToolCallID, p.OperationID, p.VersionID, p.InputRevision}
		digests = []string{p.InputDigest, p.ArgumentsDigest}
		fields = append(fields, number(p.RequestSequence))
	default:
		return bad()
	}
	for _, v := range ids {
		if !textOK(v, 256) {
			return bad()
		}
	}
	for _, v := range digests {
		if !digestOK(v) {
			return bad()
		}
	}
	fields = append(fields, ids...)
	fields = append(fields, digests...)
	return SubjectRef{s.Workspace, s.Kind, s.ID, s.Generation, hashFields("host-decision-subject-v1", fields...)}, nil
}
func (r DecideRequest) fingerprint() (string, error) {
	if !r.Subject.valid() || r.Workspace != r.Subject.Workspace || !keyOK(r.Key) || len(r.Action) == 0 || len(r.Action) > 64 || !textOK(string(r.Action), 64) || len(r.Feedback) > 2048 || !utf8.ValidString(r.Feedback) {
		return "", ErrInvalid
	}
	for _, c := range r.Feedback {
		if unicode.IsControl(c) && c != '\n' && c != '\t' {
			return "", ErrInvalid
		}
	}
	return hashFields("host-decision-request-v1", r.Workspace, r.Key, string(r.Subject.Kind), r.Subject.ID, number(r.Subject.Generation), r.Subject.Digest, string(r.Action), r.Feedback), nil
}
func (a Authorization) valid(actor api.CallerIdentity, ref SubjectRef, action Action, roles []string) bool {
	if a.Actor != actor || a.Subject != ref || a.Action != action || !textOK(a.Role, 256) || !textOK(a.PolicyVersion, 256) || len(a.GrantIDs) == 0 || len(a.GrantIDs) > 64 {
		return false
	}
	matched := false
	for _, role := range roles {
		if role == a.Role {
			matched = true
		}
	}
	if !matched {
		return false
	}
	for i, g := range a.GrantIDs {
		if !textOK(g, 256) || (i > 0 && a.GrantIDs[i-1] >= g) {
			return false
		}
	}
	return true
}
