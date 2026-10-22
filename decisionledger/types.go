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

	"github.com/Azure/aks-durable-agents/decisionrecord"
	"github.com/Azure/aks-durable-agents/entraauth"
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

type Kind = decisionrecord.Kind
type Action = decisionrecord.Action
type SubjectRef = decisionrecord.SubjectRef
type DecideRequest = decisionrecord.DecideRequest
type Authorization = decisionrecord.Authorization
type DecisionRecord = decisionrecord.DecisionRecord

const (
	SuiteKind        = decisionrecord.SuiteKind
	EffectKind       = decisionrecord.EffectKind
	Accept           = decisionrecord.Accept
	Reject           = decisionrecord.Reject
	RequestChanges   = decisionrecord.RequestChanges
	Approve          = decisionrecord.Approve
	Deny             = decisionrecord.Deny
	NonExecutingMode = decisionrecord.NonExecutingMode
)

type SuiteProposal struct {
	// ProposedBy is supplied by trusted host registration from the verified
	// proposal creator, never from the approval request or agent provenance.
	ProposedBy                                    api.CallerIdentity
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
func validReference(r SubjectRef) bool {
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
	domain := "host-decision-subject-v1"
	switch s.Kind {
	case SuiteKind:
		if s.Suite == nil || s.Effect != nil {
			return bad()
		}
		p := s.Suite
		// Reuse VerifyHuman's canonical oid form, without sub fallback. This
		// checks form only; the registering host must verify issuer trust.
		oidForm := entraauth.Config{Issuer: p.ProposedBy.Issuer, SubjectClaim: "oid"}
		if !p.ProposedBy.Valid() || !oidForm.ValidIdentity(p.ProposedBy) || p.Intent != "activate" || p.TargetID != s.Resource || p.ExpectedRevision == 0 || p.ExpectedRevision > math.MaxInt64 || !keyOK(p.OperationKey) {
			return bad()
		}
		ids = []string{p.ProposalID, p.TargetID, p.ExpectedVersion, p.Intent, p.OperationKey, p.Member, p.Composition, p.Platform, p.QualificationID}
		digests = []string{p.PredecessorDigest, p.SuiteDigest, p.InventoryDigest, p.CasesDigest, p.BindingDigest, p.EvidenceDigest, p.SourceDigest}
		fields = append(fields, number(p.ExpectedRevision), p.ProposedBy.Issuer, p.ProposedBy.Subject)
		domain = "host-decision-subject-v2"
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
	return SubjectRef{Workspace: s.Workspace, Kind: s.Kind, ID: s.ID, Generation: s.Generation, Digest: hashFields(domain, fields...)}, nil
}
func requestFingerprint(r DecideRequest) (string, error) {
	if !validReference(r.Subject) || r.Workspace != r.Subject.Workspace || !keyOK(r.Key) || len(r.Action) == 0 || len(r.Action) > 64 || !textOK(string(r.Action), 64) || len(r.Feedback) > 2048 || !utf8.ValidString(r.Feedback) {
		return "", ErrInvalid
	}
	for _, c := range r.Feedback {
		if unicode.IsControl(c) && c != '\n' && c != '\t' {
			return "", ErrInvalid
		}
	}
	return hashFields("host-decision-request-v1", r.Workspace, r.Key, string(r.Subject.Kind), r.Subject.ID, number(r.Subject.Generation), r.Subject.Digest, string(r.Action), r.Feedback), nil
}
func validAuthorization(a Authorization, actor api.CallerIdentity, ref SubjectRef, action Action, roles []string) bool {
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
