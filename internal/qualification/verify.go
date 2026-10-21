package qualification

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/agent-primitives/sessions/api"
	"github.com/agent-primitives/sessions/eventlog"
)

func (s *Store) blob(ref BlobRef) ([]byte, error) {
	if !validDigest(ref.Digest) || ref.Size < 1 || ref.Size > maxBlobBytes || privateDir(filepath.Join(s.dir, "evidence")) != nil {
		return nil, ErrIntegrity
	}
	f, err := privateFile(filepath.Join(s.dir, "evidence", ref.Digest[7:]), false)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.Size() != ref.Size {
		return nil, ErrIntegrity
	}
	b, err := io.ReadAll(io.LimitReader(f, maxBlobBytes+1))
	if err != nil || int64(len(b)) != ref.Size || hashBytes(b) != ref.Digest {
		return nil, ErrIntegrity
	}
	return b, nil
}

// retain is only available to the future trusted runner, never a request API.
func (s *Store) retain(data []byte) (BlobRef, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ref := BlobRef{hashBytes(data), int64(len(data))}
	if s.db == nil || len(data) == 0 || len(data) > maxBlobBytes {
		return BlobRef{}, ErrInvalid
	}
	dir := filepath.Join(s.dir, "evidence")
	if privateDir(dir) != nil {
		return BlobRef{}, ErrIntegrity
	}
	path := filepath.Join(dir, ref.Digest[7:])
	if _, err := os.Lstat(path); err == nil {
		_, err = s.blob(ref)
		return ref, err
	} else if !os.IsNotExist(err) {
		return BlobRef{}, ErrIntegrity
	}
	f, err := os.CreateTemp(dir, ".pending-")
	if err != nil {
		return BlobRef{}, ErrIntegrity
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return BlobRef{}, ErrIntegrity
	}
	if os.Rename(name, path) != nil || syncDir(dir) != nil {
		return BlobRef{}, ErrIntegrity
	}
	return ref, nil
}
func (s *Store) complete(ctx context.Context, l lease, obs []Observation) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.read(ctx, l.ID)
	if err != nil {
		return Record{}, err
	}
	if r.Generation != l.Generation {
		return Record{}, ErrConflict
	}
	if terminal(r.State) {
		if objectDigest("observations-v1", r.Observations) != objectDigest("observations-v1", obs) {
			return Record{}, ErrConflict
		}
		return r, nil
	}
	if r.State != Running {
		return Record{}, ErrConflict
	}
	// Bound and detach caller-owned slices before retaining the verifying intent.
	b, err := json.Marshal(obs)
	if err != nil || len(b) > maxRecordBytes-maxRequestBytes {
		return Record{}, ErrInvalid
	}
	if err = json.Unmarshal(b, &r.Observations); err != nil {
		return Record{}, ErrInvalid
	}
	r.State = Verifying
	if err = s.transaction(ctx, func() error { return s.save(ctx, r, false) }); err != nil {
		return Record{}, err
	}
	outcome, evalErr := s.evaluate(r)
	if !time.Now().Before(r.Request.Plan.ExpiresAt) {
		evalErr = ErrIneligible
	}
	r.State = outcome
	r.Reason = ""
	if evalErr != nil {
		r.State = Incomplete
		r.Reason = "evidence"
	} else if outcome == Failed {
		r.Reason = "assertion"
	}
	r.CompletedAt = time.Now().UTC()
	seal(&r)
	if err = s.transaction(ctx, func() error { return s.save(ctx, r, false) }); err != nil {
		return Record{}, err
	}
	return r, nil
}

// VerifyForActivation verifies retained evidence against an independently
// resolved plan. It grants no permission and must be called inside the future
// activation authority's current-policy/target gate, not cached as approval.
func (s *Store) VerifyForActivation(ctx context.Context, id string, expected Plan, now time.Time) (Verified, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.read(ctx, id)
	if err != nil {
		return Verified{}, err
	}
	expected.ExpiresAt = expected.ExpiresAt.Round(0).UTC()
	if r.State != Passed || now.IsZero() || !now.Before(r.Request.Plan.ExpiresAt) || r.PlanDigest != objectDigest("qualification-plan-v1", expected) {
		return Verified{}, ErrIneligible
	}
	state, err := s.evaluate(r)
	if err != nil || state != Passed {
		return Verified{}, ErrIntegrity
	}
	return Verified{r.ID, r.Digest, r.Request.Plan.Subject, r.CompletedAt}, nil
}

type judgeInput struct {
	Version      int    `json:"version"`
	AssertionID  string `json:"assertionID"`
	OutputDigest string `json:"outputDigest"`
	Model        string `json:"model"`
}
type judgeScore struct {
	Score int    `json:"score"`
	Model string `json:"model"`
}

func closedObject(b []byte, out any, fields ...string) error {
	if strictJSON(b, out) != nil {
		return ErrIntegrity
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal(b, &raw) != nil || len(raw) != len(fields) {
		return ErrIntegrity
	}
	for _, field := range fields {
		v, ok := raw[field]
		if !ok || string(v) == "null" {
			return ErrIntegrity
		}
	}
	return nil
}
func textMessage(m *api.Message, role string) (string, error) {
	if m == nil || m.Role != role || len(m.Parts) != 1 {
		return "", ErrIntegrity
	}
	p := m.Parts[0]
	if p.Text == nil || p.File != nil || p.Data != nil || p.Reasoning != nil || p.ToolCall != nil || p.ToolResult != nil {
		return "", ErrIntegrity
	}
	return p.Text.Text, nil
}
func payloadCount(e api.Event) int {
	n := 0
	for _, ok := range []bool{e.Message != nil, e.ModelCall != nil, e.ToolCall != nil, e.Result != nil, e.Approval != nil, e.ApprovalResult != nil, e.Usage != nil, e.Lifecycle != nil, e.End != nil, e.Err != nil, e.ExecutionStart != nil, e.Parked != nil} {
		if ok {
			n++
		}
	}
	return n
}
func (s *Store) journal(j Journal, used map[string]bool, expectedModel string) (string, string, error) {
	if !validID(j.SessionID) || !validID(j.ExecutionID) || used["s:"+j.SessionID] || used["e:"+j.ExecutionID] || !validDigest("sha256:"+j.HeadHash) || j.Count < 5 || j.Count > 6 {
		return "", "", ErrIntegrity
	}
	used["s:"+j.SessionID] = true
	used["e:"+j.ExecutionID] = true
	b, err := s.blob(j.Blob)
	if err != nil {
		return "", "", err
	}
	var records []eventlog.Record
	if strictJSON(b, &records) != nil || len(records) != j.Count || records[len(records)-1].Hash != j.HeadHash || eventlog.VerifyChain("", records) != nil {
		return "", "", ErrIntegrity
	}
	input, output := "", ""
	for i, rec := range records {
		e := rec.Event
		if rec.Seq != int64(i+1) || e.ExecutionID != j.ExecutionID || e.SchemaVersion != 1 || payloadCount(e) != 1 {
			return "", "", ErrIntegrity
		}
		switch {
		case i == 0:
			x := e.ExecutionStart
			if e.Kind != api.EventExecutionStart || x == nil || x.InputCount == nil || *x.InputCount != 1 || x.ResumeFromSeq != 0 || !validID(x.Harness) || !validID(x.HarnessVersion) {
				return "", "", ErrIntegrity
			}
		case i == 1:
			if e.Kind != api.EventInput {
				return "", "", ErrIntegrity
			}
			input, err = textMessage(e.Message, "user")
		case i == 2:
			if e.Kind != api.EventModelCall || e.ModelCall == nil || !validID(e.ModelCall.ID) || !validID(e.ModelCall.Model) || expectedModel != "" && e.ModelCall.Model != expectedModel {
				return "", "", ErrIntegrity
			}
		case i == 3:
			if e.Kind != api.EventOutput {
				return "", "", ErrIntegrity
			}
			output, err = textMessage(e.Message, "assistant")
		case i == len(records)-1:
			if e.Kind != api.EventEnd || e.End == nil || e.End.State != "COMPLETED" || e.End.Error != nil {
				return "", "", ErrIntegrity
			}
		default:
			if e.Kind != api.EventUsage || e.Usage == nil || e.Usage.InputTokens < 0 || e.Usage.OutputTokens < 0 || e.Usage.ReasoningTokens < 0 {
				return "", "", ErrIntegrity
			}
		}
		if err != nil {
			return "", "", err
		}
	}
	return input, output, nil
}
func (s *Store) evaluate(r Record) (State, error) {
	// Independently bound both metadata and reads, even if retained observations
	// came from a malformed or compromised worker rather than our completion path.
	expectedSlots := 0
	for _, c := range r.Request.Plan.Cases {
		expectedSlots += c.Runs
	}
	if len(r.Observations) != expectedSlots {
		return Incomplete, ErrIntegrity
	}
	used := map[string]bool{}
	pos := 0
	failed := false
	for _, c := range r.Request.Plan.Cases {
		passes := 0
		for run := 1; run <= c.Runs; run++ {
			o := r.Observations[pos]
			pos++
			if o.CaseID != c.ID || o.Run != run {
				return Incomplete, ErrIntegrity
			}
			input, output, err := s.journal(o.Candidate, used, "")
			if err != nil || hashBytes([]byte(input)) != c.InputDigest {
				return Incomplete, ErrIntegrity
			}
			judgeCount := 0
			for _, a := range c.Assertions {
				if a.Kind == "llmJudge" {
					judgeCount++
				}
			}
			if len(o.Judges) != judgeCount {
				return Incomplete, ErrIntegrity
			}
			passed := true
			judgeIndex := 0
			for _, a := range c.Assertions {
				assertionPass := false
				switch a.Kind {
				case "contains":
					assertionPass = strings.Contains(output, a.Value)
				case "notContains":
					assertionPass = !strings.Contains(output, a.Value)
				case "regex":
					pattern, err := regexp.Compile(a.Value)
					if err != nil {
						return Incomplete, ErrIntegrity
					}
					assertionPass = pattern.MatchString(output)
				case "toolNotCalled":
					assertionPass = true // the complete journal profile excludes all tool events
				case "llmJudge":
					j := o.Judges[judgeIndex]
					judgeIndex++
					if j.AssertionID != a.ID || len(j.Calls) != 2 {
						return Incomplete, ErrIntegrity
					}
					passingScores := 0
					for _, call := range j.Calls {
						in, out, err := s.journal(call, used, a.JudgeModel)
						if err != nil {
							return Incomplete, ErrIntegrity
						}
						var binding judgeInput
						var score judgeScore
						if closedObject([]byte(in), &binding, "version", "assertionID", "outputDigest", "model") != nil || binding != (judgeInput{1, a.ID, hashBytes([]byte(output)), a.JudgeModel}) || closedObject([]byte(out), &score, "score", "model") != nil || score.Score < 0 || score.Score > 100 || score.Model != a.JudgeModel {
							return Incomplete, ErrIntegrity
						}
						if score.Score >= a.MinScore {
							passingScores++
						}
					}
					if passingScores == 1 {
						return Incomplete, ErrIntegrity
					}
					assertionPass = passingScores == 2
				default:
					return Incomplete, ErrIntegrity
				}
				passed = passed && assertionPass
			}
			if passed {
				passes++
			}
		}
		if passes < c.MinPasses {
			failed = true
		}
	}
	if failed {
		return Failed, nil
	}
	return Passed, nil
}
