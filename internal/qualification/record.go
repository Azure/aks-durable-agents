// Package qualification retains host-owned qualification evidence. It is not
// wired to the host and supplies neither a candidate runner nor authorization.
package qualification

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	ErrInvalid    = errors.New("qualification: invalid input")
	ErrConflict   = errors.New("qualification: conflict")
	ErrBusy       = errors.New("qualification: writer busy")
	ErrIntegrity  = errors.New("qualification: integrity failure")
	ErrIneligible = errors.New("qualification: ineligible")
)

const (
	maxRequestBytes = 512 << 10
	maxRecordBytes  = 1 << 20
	maxBlobBytes    = 256 << 10
	maxJournalSlots = 64
)

type State string

const (
	Admitted   State = "admitted"
	Running    State = "running"
	Verifying  State = "verifying"
	Passed     State = "passed"
	Failed     State = "failed"
	Refused    State = "refused"
	Incomplete State = "incomplete"
)

func terminal(s State) bool { return s == Passed || s == Failed || s == Refused || s == Incomplete }

type Subject struct{ Workspace, Target, SuiteDigest, BindingDigest, ProfileDigest, ModelDigest, JudgeDigest, PolicyDigest string }
type Member struct{ ID, Digest string }
type Assertion struct {
	ID, Kind, Value string
	MinScore        int
	JudgeModel      string
}
type Case struct {
	ID, Digest, InputDigest string
	Runs, MinPasses         int
	Assertions              []Assertion
}
type Plan struct {
	Subject                                            Subject
	Members                                            []Member
	MemberID, CompositionDigest, Platform, IndexDigest string
	Cases                                              []Case
	ExpiresAt                                          time.Time
}
type Request struct {
	Key, Requester string
	Plan           Plan
}
type BlobRef struct {
	Digest string
	Size   int64
}
type Journal struct {
	SessionID, ExecutionID, HeadHash string
	Count                            int
	Blob                             BlobRef
}
type Judgment struct {
	AssertionID string
	Calls       []Journal
}
type Observation struct {
	CaseID    string
	Run       int
	Candidate Journal
	Judges    []Judgment
}
type Record struct {
	ID, Lineage, RequestDigest, PlanDigest string
	Request                                Request
	State                                  State
	Generation                             int64
	Observations                           []Observation
	Reason                                 string
	CompletedAt                            time.Time
	Digest                                 string
}
type Verified struct {
	ID, Digest  string
	Subject     Subject
	CompletedAt time.Time
}
type lease struct {
	ID         string
	Generation int64
}

func hashBytes(b []byte) string { s := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(s[:]) }
func objectDigest(domain string, v any) string {
	b, _ := json.Marshal(v)
	return hashBytes(append([]byte(domain+"\n"), b...))
}
func seal(r *Record) { r.Digest = ""; r.Digest = objectDigest("qualification-record-v1", *r) }
func validDigest(s string) bool {
	if len(s) != 71 || !strings.HasPrefix(s, "sha256:") {
		return false
	}
	for _, c := range s[7:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func validID(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if c < 33 || c > 126 {
			return false
		}
	}
	return true
}

// Workspace follows the host evidence namespace, not the narrower key/ID domain.
func validWorkspace(s string) bool {
	if len(s) == 0 || len(s) > 256 || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func normalize(r Request) Request { r.Plan.ExpiresAt = r.Plan.ExpiresAt.Round(0).UTC(); return r }
func validateRequest(r Request) error {
	p := r.Plan
	if !validID(r.Key) || !validID(r.Requester) || !validWorkspace(p.Subject.Workspace) || !validID(p.Subject.Target) || !validID(p.MemberID) || !validID(p.Platform) || p.ExpiresAt.IsZero() {
		return ErrInvalid
	}
	for _, d := range []string{p.Subject.SuiteDigest, p.Subject.BindingDigest, p.Subject.ProfileDigest, p.Subject.ModelDigest, p.Subject.JudgeDigest, p.Subject.PolicyDigest, p.CompositionDigest, p.IndexDigest} {
		if !validDigest(d) {
			return ErrInvalid
		}
	}
	if len(p.Members) == 0 || len(p.Members) > 128 || len(p.Cases) == 0 || len(p.Cases) > 128 {
		return ErrInvalid
	}
	members := map[string]bool{}
	for _, m := range p.Members {
		if !validID(m.ID) || !validDigest(m.Digest) || members[m.ID] {
			return ErrInvalid
		}
		members[m.ID] = true
	}
	if !members[p.MemberID] {
		return ErrInvalid
	}
	cases := map[string]bool{}
	slots, rows := 0, 0
	for _, c := range p.Cases {
		if !validID(c.ID) || cases[c.ID] || !validDigest(c.Digest) || !validDigest(c.InputDigest) || c.Runs < 1 || c.Runs > 1000 || c.MinPasses < 1 || c.MinPasses > c.Runs || len(c.Assertions) == 0 || len(c.Assertions) > 1000 {
			return ErrInvalid
		}
		cases[c.ID] = true
		ids := map[string]bool{}
		judges := 0
		for _, a := range c.Assertions {
			if !validID(a.ID) || ids[a.ID] || len(a.Value) > 4096 || !utf8.ValidString(a.Value) {
				return ErrInvalid
			}
			ids[a.ID] = true
			switch a.Kind {
			case "contains", "notContains":
				if strings.TrimSpace(a.Value) == "" || a.MinScore != 0 || a.JudgeModel != "" {
					return ErrInvalid
				}
			case "regex":
				if a.Value == "" || a.MinScore != 0 || a.JudgeModel != "" {
					return ErrInvalid
				}
				if _, err := regexp.Compile(a.Value); err != nil {
					return ErrInvalid
				}
			case "toolNotCalled":
				if !validID(a.Value) || a.MinScore != 0 || a.JudgeModel != "" {
					return ErrInvalid
				}
			case "llmJudge":
				if a.Value != "" || a.MinScore < 0 || a.MinScore > 100 || !validID(a.JudgeModel) {
					return ErrInvalid
				}
				judges++
			default:
				return ErrInvalid
			}
		}
		// Counts are bounded before multiplying; no partial inventory is admitted.
		slots += c.Runs * (1 + 2*judges)
		rows += c.Runs * len(c.Assertions)
		if slots > maxJournalSlots || rows > 32000 {
			return ErrInvalid
		}
	}
	b, err := json.Marshal(r)
	if err != nil || len(b) > maxRequestBytes || len(b)+slots*2048+4096 > maxRecordBytes {
		return ErrInvalid
	}
	return nil
}
func checkRecord(r Record, lineage string) error {
	copy := r
	seal(&copy)
	if r.Lineage != lineage || !validID(r.ID) || r.Digest != copy.Digest || r.Generation < 0 || validateRequest(r.Request) != nil || r.RequestDigest != objectDigest("qualification-request-v1", r.Request) || r.PlanDigest != objectDigest("qualification-plan-v1", r.Request.Plan) {
		return ErrIntegrity
	}
	if terminal(r.State) {
		if r.CompletedAt.IsZero() {
			return ErrIntegrity
		}
	} else if r.State != Admitted && r.State != Running && r.State != Verifying {
		return ErrIntegrity
	} else if !r.CompletedAt.IsZero() {
		return ErrIntegrity
	}
	switch r.Reason {
	case "", "assertion", "interrupted", "evidence":
	default:
		return ErrIntegrity
	}
	return nil
}

// strictJSON refuses duplicate keys and unknown struct fields. Typed validation
// owns nullability: Sessions events legitimately encode absent payloads as null.
func strictJSON(data []byte, out any) error {
	if !utf8.Valid(data) {
		return ErrIntegrity
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 64 {
			return ErrIntegrity
		}
		tok, err := d.Token()
		if err != nil {
			return ErrIntegrity
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				s, ok := key.(string)
				if err != nil || !ok || seen[s] {
					return ErrIntegrity
				}
				seen[s] = true
				if err = value(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err = value(depth + 1); err != nil {
					return err
				}
			}
		default:
			return ErrIntegrity
		}
		_, err = d.Token()
		return err
	}
	if err := value(0); err != nil {
		return ErrIntegrity
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrIntegrity
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return ErrIntegrity
	}
	return nil
}
