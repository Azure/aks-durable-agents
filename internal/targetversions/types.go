// Package targetversions is an unwired, trusted-input record state machine.
// Values supplied here do not establish human authority, qualification authenticity
// or physical runtime fencing. No method invokes a model, tool or runtime adapter.
package targetversions

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Azure/aks-durable-agents/internal/decisionrecord"
)

var (
	ErrConflict    = errors.New("target version conflict")
	ErrBusy        = errors.New("target version store lock contention")
	ErrOccupied    = errors.New("target has a pending version operation")
	ErrUnavailable = errors.New("target version store unavailable; reconcile exact request")
	ErrIntegrity   = errors.New("target version integrity failure; reconcile retained state")
	ErrUnsupported = errors.New("unsupported target version schema or kind")
	ErrInvalid     = errors.New("invalid target version input")
)

type ArtifactTuple struct {
	SuiteDigest, Member, Composition, Platform, InventoryDigest, CasesDigest  string
	Harness, Runtime, Model, ModelConfig, Judge, JudgeSettings, BindingDigest string
}
type Qualification struct {
	ID, StoreID, Digest, EvidenceDigest, JournalsDigest, PolicyVersion string
	Artifact                                                           ArtifactTuple
	Complete, Passed, Eligible                                         bool
}
type Candidate struct {
	Artifact      ArtifactTuple
	SourceDigest  string
	Qualification Qualification
}
type PredecessorRef struct{ Kind, ID string }

// Shared DTOs carry historical evidence, not authority. Digesting this evidence
// remains a G1 codec, never an E1 record encoder.
type Identity = decisionrecord.Identity
type SubjectRef = decisionrecord.SubjectRef
type DecideRequest = decisionrecord.DecideRequest
type DecisionAuthorization = decisionrecord.Authorization
type DecisionRecord = decisionrecord.DecisionRecord

// Current authority is a separate request-local snapshot. Credential validity is
// checked only at reservation; its expiry never reinterprets a reserved operation.
type AuthorizationSnapshot struct {
	OperationID, Phase                                 string
	Generation, OperationRevision                      uint64
	DecisionRecord                                     DecisionRecord
	DecisionDigest                                     string
	Actor                                              Identity
	Subject                                            SubjectRef
	Action, Role, TargetID, PolicyVersion, PolicyEpoch string
	GrantIDs                                           []string
	AuthorizedAt, ExpiresAt, CredentialExpiresAt       time.Time
}
type Request struct {
	TargetID, Key, Intent, SourceVersionID string
	ExpectedRevision                       uint64
	Predecessor                            PredecessorRef
	Candidate                              Candidate
	Subject                                SubjectRef
	DecisionRecord                         DecisionRecord
}
type Target struct {
	Predecessor                                PredecessorRef
	ID, Kind, StoreID, GenesisID               string
	Revision, Generation                       uint64
	ActiveVersionID, OperationID, Availability string
}
type Version struct {
	ID, TargetID, OperationID, ExecutionContextID string
	Candidate                                     Candidate
	CreatedAt                                     time.Time
}
type Step struct {
	OperationID                  string
	ExpectedRevision, Generation uint64
}
type Receipt struct {
	Kind, OperationID, TargetID, BackendLineageID, ExecutionContextID               string
	Generation                                                                      uint64
	ArtifactDigest, EvidenceDigest, FenceDigest, ContextDigest, QualificationDigest string
	Predecessor                                                                     PredecessorRef
	PredecessorEvidence, IntentID                                                   string
}
type Abandonment struct {
	IntentID, ID, Key, Reason, Fingerprint, LastPhase string
	Authority                                         AuthorizationSnapshot
	CreatedAt                                         time.Time
}
type Operation struct {
	ID, Fingerprint, Phase string
	Revision, Generation   uint64
	Request                Request
	Version                Version
	// FrozenSource is an exact retained committed version, not the failed candidate.
	FrozenSource *Version
	Reserved     *AuthorizationSnapshot
	ReservedAt   time.Time
	Receipts     []Receipt
	AbortReason  string
	Abandonment  *Abandonment
}
type AbandonRequest struct {
	Step
	Key, Reason string
	Authority   AuthorizationSnapshot
}
type Link struct{ Kind, FromID, ToID string }
type Event struct {
	BackendLineageID                          string
	Sequence                                  uint64
	TargetID, OperationID, FromPhase, ToPhase string
	At                                        time.Time
	Target                                    Target
	Operation                                 *Operation
	Links                                     []Link
	Tombstone                                 string
}

func keyOK(v string) bool {
	if len(v) == 0 || len(v) > 128 {
		return false
	}
	for _, b := range []byte(v) {
		if b < 33 || b > 126 {
			return false
		}
	}
	return true
}

// Copied decision evidence follows the producer's UTF-8 identifier domain,
// independently of this store's narrower operation-key namespace.
func evidenceText(v string, max int) bool {
	if len(v) == 0 || len(v) > max || !utf8.ValidString(v) {
		return false
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func evidenceFeedback(v string) bool {
	if len(v) > 2048 || !utf8.ValidString(v) {
		return false
	}
	for _, r := range v {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return false
		}
	}
	return true
}
func digestOK(v string) bool {
	if len(v) != 64 {
		return false
	}
	for _, b := range []byte(v) {
		if !strings.ContainsRune("0123456789abcdef", rune(b)) {
			return false
		}
	}
	return true
}
func bounded(v any) bool       { b, e := json.Marshal(v); return e == nil && len(b) <= 65536 }
func reasonOK(v string) bool   { return len(v) > 0 && len(v) <= 4096 && utf8.ValidString(v) }
func number(n uint64) string   { return strconv.FormatUint(n, 10) }
func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
func hash(domain string, fields ...string) string {
	h := sha256.New()
	for _, s := range append([]string{domain}, fields...) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	return hex.EncodeToString(h.Sum(nil))
}
func (a ArtifactTuple) fields() []string {
	return []string{a.SuiteDigest, a.Member, a.Composition, a.Platform, a.InventoryDigest, a.CasesDigest, a.Harness, a.Runtime, a.Model, a.ModelConfig, a.Judge, a.JudgeSettings, a.BindingDigest}
}
func (a ArtifactTuple) valid() bool {
	for _, v := range a.fields() {
		if !keyOK(v) {
			return false
		}
	}
	for _, v := range []string{a.SuiteDigest, a.InventoryDigest, a.CasesDigest, a.ModelConfig, a.JudgeSettings, a.BindingDigest} {
		if !digestOK(v) {
			return false
		}
	}
	return true
}
func (c Candidate) binding() string {
	return hash("g1-candidate-v1", append(c.Artifact.fields(), c.SourceDigest)...)
}
func subjectFields(s SubjectRef) []string {
	return []string{s.Workspace, string(s.Kind), s.ID, number(s.Generation), s.Digest}
}
func validSubjectRef(s SubjectRef) bool {
	return evidenceText(s.Workspace, 256) && evidenceText(s.ID, 256) && s.Kind == decisionrecord.SuiteKind && s.Generation > 0 && s.Generation <= math.MaxInt64 && digestOK(s.Digest)
}
func grantsOK(gs []string) bool {
	if len(gs) == 0 || len(gs) > 64 {
		return false
	}
	for i, g := range gs {
		if !evidenceText(g, 256) || (i > 0 && gs[i-1] >= g) {
			return false
		}
	}
	return true
}
func action(intent string) string {
	if intent == "activate" {
		return "accept"
	}
	return intent
}
func decisionFields(d DecisionRecord) []string {
	f := []string{d.ID, d.StoreID, d.HostLineageID, d.Request.Workspace, d.Request.Key}
	f = append(f, subjectFields(d.Request.Subject)...)
	f = append(f, string(d.Request.Action), d.Request.Feedback, d.RequestDigest, d.Actor.Issuer, d.Actor.Subject, d.Outcome, d.RefusalCode, stamp(d.CommittedAt), d.Mode)
	if d.Authorization == nil {
		return append(f, "none")
	}
	a := d.Authorization
	f = append(f, "authorization", a.Actor.Issuer, a.Actor.Subject)
	f = append(f, subjectFields(a.Subject)...)
	f = append(f, string(a.Action), a.Role, a.PolicyVersion, number(uint64(len(a.GrantIDs))))
	return append(f, a.GrantIDs...)
}
func copiedDecisionDigest(d DecisionRecord) string {
	return hash("g1-copied-decision-record-v1", decisionFields(d)...)
}
func validDecisionRecord(d DecisionRecord, ref SubjectRef, act string) bool {
	a := d.Authorization
	return evidenceText(d.ID, 256) && evidenceText(d.StoreID, 256) && evidenceText(d.HostLineageID, 256) && keyOK(d.Request.Key) && d.Request.Workspace == ref.Workspace && d.Request.Subject == ref && validSubjectRef(ref) && string(d.Request.Action) == act && evidenceFeedback(d.Request.Feedback) && digestOK(d.RequestDigest) && evidenceText(d.Actor.Issuer, 256) && evidenceText(d.Actor.Subject, 256) && d.Outcome == "recorded" && d.RefusalCode == "" && d.Mode == decisionrecord.NonExecutingMode && !d.CommittedAt.IsZero() && a != nil && evidenceText(a.Actor.Issuer, 256) && evidenceText(a.Actor.Subject, 256) && a.Actor == d.Actor && a.Subject == ref && string(a.Action) == act && evidenceText(a.PolicyVersion, 256) && grantsOK(a.GrantIDs) && evidenceText(a.Role, 256)
}
func (r Request) fingerprint() string {
	f := []string{r.TargetID, r.Key, r.Intent, r.SourceVersionID, number(r.ExpectedRevision), r.Predecessor.Kind, r.Predecessor.ID}
	f = append(f, r.Candidate.Artifact.fields()...)
	f = append(f, r.Candidate.SourceDigest)
	q := r.Candidate.Qualification
	f = append(f, q.ID, q.StoreID, q.Digest, q.EvidenceDigest, q.JournalsDigest, q.PolicyVersion, strconv.FormatBool(q.Complete), strconv.FormatBool(q.Passed), strconv.FormatBool(q.Eligible))
	f = append(f, q.Artifact.fields()...)
	f = append(f, subjectFields(r.Subject)...)
	return hash("g1-request-v1", append(f, decisionFields(r.DecisionRecord)...)...)
}
func (r Request) valid() bool {
	q := r.Candidate.Qualification
	return bounded(r) && keyOK(r.TargetID) && keyOK(r.Key) && r.ExpectedRevision > 0 && r.ExpectedRevision < math.MaxInt64 && keyOK(r.Predecessor.ID) && (r.Predecessor.Kind == "genesis" || r.Predecessor.Kind == "version" || r.Predecessor.Kind == "abandonment") && (r.SourceVersionID == "" || keyOK(r.SourceVersionID)) && (r.Intent == "activate" || r.Intent == "rollback" || r.Intent == "recover") && r.Candidate.Artifact.valid() && digestOK(r.Candidate.SourceDigest) && keyOK(q.ID) && keyOK(q.StoreID) && digestOK(q.Digest) && digestOK(q.EvidenceDigest) && digestOK(q.JournalsDigest) && keyOK(q.PolicyVersion) && q.Complete && q.Passed && q.Eligible && q.Artifact == r.Candidate.Artifact && validDecisionRecord(r.DecisionRecord, r.Subject, action(r.Intent))
}
func (a AuthorizationSnapshot) fields() []string {
	f := append(decisionFields(a.DecisionRecord), a.DecisionDigest, a.Actor.Issuer, a.Actor.Subject, a.OperationID, a.Phase, number(a.Generation), number(a.OperationRevision))
	f = append(f, subjectFields(a.Subject)...)
	f = append(f, a.Action, a.Role, a.TargetID, a.PolicyVersion, a.PolicyEpoch, stamp(a.AuthorizedAt), stamp(a.ExpiresAt), stamp(a.CredentialExpiresAt), number(uint64(len(a.GrantIDs))))
	return append(f, a.GrantIDs...)
}
func (a AuthorizationSnapshot) bound(o Operation) bool {
	return a.OperationID == o.ID && a.Generation == o.Generation && a.OperationRevision == o.Revision && a.Phase == o.Phase
}
func (a AuthorizationSnapshot) valid(target, act string, now time.Time) bool {
	return bounded(a) && validDecisionRecord(a.DecisionRecord, a.Subject, act) && a.DecisionDigest == copiedDecisionDigest(a.DecisionRecord) && a.Actor == a.DecisionRecord.Actor && a.Subject == a.DecisionRecord.Request.Subject && a.Action == act && evidenceText(a.Role, 256) && a.TargetID == target && evidenceText(a.PolicyVersion, 256) && keyOK(a.PolicyEpoch) && grantsOK(a.GrantIDs) && !a.AuthorizedAt.IsZero() && !a.AuthorizedAt.After(now) && a.ExpiresAt.After(now) && a.CredentialExpiresAt.After(now)
}
func same(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}
