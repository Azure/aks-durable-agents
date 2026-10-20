package sessionfixture

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"syscall"

	"github.com/agent-primitives/sessions/api"
	v1 "github.com/agent-primitives/sessions/api/genpb"
	"github.com/agent-primitives/sessions/client"
	"github.com/agent-primitives/sessions/wire"
	"google.golang.org/protobuf/proto"
)

type pendingTuple struct {
	ExecutionID string `json:"executionID"`
	ToolCallID  string `json:"toolCallID"`
	RequestSeq  int64  `json:"requestSeq"`
}
type loopProof struct {
	fixtureEvidence
	Session                    string        `json:"session"`
	DeniedSession              string        `json:"deniedSession,omitempty"`
	Pending                    *pendingTuple `json:"pending,omitempty"`
	HeadSeq                    int64         `json:"headSeq"`
	HeadHash                   string        `json:"headHash"`
	Published                  bool          `json:"published,omitempty"`
	DenyZeroEffects            bool          `json:"denyZeroEffects"`
	ApproveOnlyEffects         int           `json:"approveOnlyEffects"`
	ArtifactInventoryUnchanged bool          `json:"artifactInventoryUnchanged,omitempty"`
	Replay                     *replayProof  `json:"replay,omitempty"`
}
type inspection struct {
	Session  *v1.Session
	Records  []*v1.LogRecord
	HeadHash string
}

func inspectLoop(ctx context.Context, c *client.Client, uid string) (inspection, error) {
	s, err := c.GetSession(ctx, uid)
	if err != nil {
		return inspection{}, err
	}
	if s.GetLastSeq() < 0 || s.GetLastSeq() > 10000 {
		return inspection{}, errors.New("session exceeds bounded proof size")
	}
	records, err := c.Replay(ctx, uid, 1, s.GetLastSeq())
	if err != nil {
		return inspection{}, err
	}
	after, err := c.GetSession(ctx, uid)
	if err != nil {
		return inspection{}, err
	}
	if s.GetLastSeq() != after.GetLastSeq() || !proto.Equal(s.GetPendingApproval(), after.GetPendingApproval()) {
		return inspection{}, errors.New("session changed during inspection")
	}
	hash := ""
	if len(records) > 0 {
		last := records[len(records)-1]
		if last.GetSeq() != s.GetLastSeq() {
			return inspection{}, errors.New("missing journal head")
		}
		hash = last.GetContentHash()
	}
	return inspection{Session: s, Records: records, HeadHash: hash}, nil
}
func tuple(p *v1.ApprovalRef) *pendingTuple {
	if p == nil {
		return nil
	}
	return &pendingTuple{p.GetExecutionId(), p.GetToolCallId(), p.GetRequestSeq()}
}
func decideLoop(ctx context.Context, c *client.Client, uid string, p *pendingTuple, approved bool) error {
	if p == nil {
		return errors.New("undecided approval tuple required")
	}
	_, err := c.Approve(ctx, uid, api.ApprovalDecision{ExecutionID: p.ExecutionID, ToolCallID: p.ToolCallID, RequestSeq: p.RequestSeq, Approved: approved, Reason: "REFERENCE bounded fictional verification; not human authentication"})
	return err
}
func resumeLoop(ctx context.Context, c *client.Client, uid string, head int64) error {
	// Use the SDK's underlying RPC to preserve the same cursor precondition as the
	// native helper. Approve is always a distinct SDK call before this explicit Resume.
	_, err := c.Sessions().Resume(ctx, &v1.ResumeRequest{Session: uid, ExpectedLastSeq: &head})
	return err
}
func createParked(ctx context.Context, c *client.Client, variant string) (inspection, error) {
	s, err := c.CreateSession(ctx, &v1.Session{Harness: "release-notes"})
	if err != nil {
		return inspection{}, err
	}
	uid := s.GetMetadata().GetUid()
	head := s.GetLastSeq()
	if _, err = c.Exec(ctx, client.ExecOptions{Session: uid, Inputs: []string{"REFERENCE fictional proposal, variant " + variant}, ExpectedLastSeq: &head}); err != nil {
		return inspection{}, err
	}
	view, err := inspectLoop(ctx, c, uid)
	if err != nil {
		return view, err
	}
	p := tuple(view.Session.GetPendingApproval())
	if p == nil || p.ExecutionID == "" || p.ToolCallID != p.ExecutionID+"/publish_release_notes" || p.RequestSeq <= 0 {
		return view, errors.New("missing deterministic parked approval")
	}
	return view, nil
}
func requireReceipt(view inspection, p *pendingTuple, approved bool) (*api.ToolResult, error) {
	var call *api.ToolCall
	var result *api.ToolResult
	decisionSeq := int64(0)
	completed := false
	for _, record := range view.Records {
		e := wire.EventFromProto(record.GetEvent())
		if e.ExecutionID != p.ExecutionID && e.Kind != api.EventLifecycle {
			return nil, errors.New("unexpected execution in bounded fixture session")
		}
		switch e.Kind {
		case api.EventToolCall:
			if call != nil {
				return nil, errors.New("duplicate publication call")
			}
			call = e.ToolCall
		case api.EventApprovalResult:
			if e.ApprovalResult == nil || e.ApprovalResult.Approved != approved || e.ApprovalResult.RequestSeq != p.RequestSeq || e.ApprovalResult.ToolCallID != p.ToolCallID {
				return nil, errors.New("approval result mismatch")
			}
			decisionSeq = record.GetSeq()
		case api.EventToolResult:
			if result != nil {
				return nil, errors.New("duplicate result")
			}
			result = e.Result
		case api.EventEnd:
			completed = e.End != nil && e.End.State == "COMPLETED"
		}
	}
	if !completed || view.Session.GetPendingApproval() != nil || call == nil || result == nil || decisionSeq <= p.RequestSeq || result.ID != p.ToolCallID || result.ApprovalRequestSeq != p.RequestSeq || result.ApprovalDecisionSeq != decisionSeq {
		return nil, errors.New("terminal receipt/call/approval stamp invariant failed")
	}
	if approved {
		if result.IsError || result.Code != api.ToolResultCodeUnspecified || result.Output["simulated"] != true || result.Output["draft"] != call.Args["draft"] || result.Output["destination"] != "release-notes-demo" {
			return nil, errors.New("fictional publication receipt failed; reconcile durable state, do not retry with a new key")
		}
		tupleRaw, _ := json.Marshal([]string{view.Session.GetMetadata().GetUid(), call.IdempotencyKey})
		if result.Output["artifact"] != digestBytes(tupleRaw)+".json" {
			return nil, errors.New("artifact identity mismatch")
		}
	} else if !result.IsError || result.Code != api.ToolResultCodeApprovalDenied {
		return nil, errors.New("denial did not yield native APPROVAL_DENIED receipt")
	}
	return result, nil
}
func verifyUnchangedReplay(effects, afterReplay fixtureEvidence, completed, afterView inspection, replay replayProof) error {
	if replay.SessionUID != completed.Session.GetMetadata().GetUid() || replay.HeadSeq != completed.Session.GetLastSeq() || replay.HeadHash != completed.HeadHash {
		return errors.New("strict replay proof does not bind the exact RPC head")
	}
	if !reflect.DeepEqual(effects, afterReplay) || completed.Session.GetLastSeq() != afterView.Session.GetLastSeq() || completed.HeadHash != afterView.HeadHash {
		return errors.New("strict replay changed inventory/counter/journal head")
	}
	return nil
}

func verifyLoop(ctx context.Context, phase, data, server, uid string) (loopProof, error) {
	proof := loopProof{}
	if err := existingPrivateDirectory(data); err != nil {
		return proof, err
	}
	if _, err := instructionBytes(filepath.Join(data, "instructions.txt")); err != nil {
		return proof, err
	}
	c, err := client.Dial(server)
	if err != nil {
		return proof, err
	}
	defer c.Close()
	snapshotPath := filepath.Join(data, "park-proof.json")
	switch phase {
	case "park":
		if uid != "" {
			return proof, errors.New("park cannot select an existing session")
		}
		if _, err = os.Lstat(snapshotPath); !errors.Is(err, os.ErrNotExist) {
			return proof, errors.New("park proof already exists or cannot be inspected")
		}
		initial, err := readEvidence(data)
		if err != nil {
			return proof, err
		}
		if initial.FakeModelCalls != 0 || initial.PublicationCount != 0 || initial.ReceiptCount != 0 {
			return proof, errors.New("park requires a fresh fictional fixture inventory; refusing implicit retry")
		}
		denied, err := createParked(ctx, c, "A")
		if err != nil {
			return proof, err
		}
		deniedUID := denied.Session.GetMetadata().GetUid()
		pending := tuple(denied.Session.GetPendingApproval())
		if err = decideLoop(ctx, c, deniedUID, pending, false); err != nil {
			return proof, err
		}
		decided, err := inspectLoop(ctx, c, deniedUID)
		if err != nil {
			return proof, err
		}
		beforeResume, err := readEvidence(data)
		if err != nil {
			return proof, err
		}
		if beforeResume.FakeModelCalls != 1 || beforeResume.PublicationCount != 0 || beforeResume.ReceiptCount != 0 {
			return proof, errors.New("denial Approve performed effects")
		}
		if err = resumeLoop(ctx, c, deniedUID, decided.Session.GetLastSeq()); err != nil {
			return proof, err
		}
		done, err := inspectLoop(ctx, c, deniedUID)
		if err != nil {
			return proof, err
		}
		if _, err = requireReceipt(done, pending, false); err != nil {
			return proof, err
		}
		afterDeny, err := readEvidence(data)
		if err != nil {
			return proof, err
		}
		if !reflect.DeepEqual(beforeResume, afterDeny) {
			return proof, errors.New("denied explicit Resume changed effects or provider counter")
		}
		candidate, err := createParked(ctx, c, "B")
		if err != nil {
			return proof, err
		}
		final, err := readEvidence(data)
		if err != nil {
			return proof, err
		}
		if final.FakeModelCalls != 2 || final.PublicationCount != 0 || final.ReceiptCount != 0 {
			return proof, errors.New("undecided candidate performed effects")
		}
		proof = loopProof{fixtureEvidence: final, Session: candidate.Session.GetMetadata().GetUid(), DeniedSession: deniedUID, Pending: tuple(candidate.Session.GetPendingApproval()), HeadSeq: candidate.Session.GetLastSeq(), HeadHash: candidate.HeadHash, DenyZeroEffects: true}
		raw, err := json.Marshal(proof)
		if err != nil {
			return proof, err
		}
		if err = freezeFile(snapshotPath, append(raw, '\n')); err != nil {
			return proof, err
		}
		return proof, nil
	case "complete":
		f, err := os.OpenFile(snapshotPath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return proof, err
		}
		raw, err := io.ReadAll(io.LimitReader(f, 65537))
		f.Close()
		if err != nil {
			return proof, err
		}
		if len(raw) > 65536 {
			return proof, errors.New("park proof too large")
		}
		var parked loopProof
		if err = strictJSON(raw, []string{"session", "deniedSession", "pending", "headSeq", "headHash", "fakeModelCalls", "artifacts", "publicationCount", "receiptCount", "denyZeroEffects", "approveOnlyEffects"}, &parked); err != nil {
			return proof, err
		}
		if uid == "" || uid != parked.Session || !parked.DenyZeroEffects || parked.Pending == nil {
			return proof, errors.New("exact parked session UID and snapshot are required")
		}
		view, err := inspectLoop(ctx, c, uid)
		if err != nil {
			return proof, err
		}
		before, err := readEvidence(data)
		if err != nil {
			return proof, err
		}
		if !reflect.DeepEqual(before, parked.fixtureEvidence) || view.Session.GetLastSeq() != parked.HeadSeq || view.HeadHash != parked.HeadHash || !reflect.DeepEqual(tuple(view.Session.GetPendingApproval()), parked.Pending) {
			return proof, errors.New("restart changed parked tuple/head/counter/effect inventory")
		}
		if err = decideLoop(ctx, c, uid, parked.Pending, true); err != nil {
			return proof, err
		}
		approved, err := inspectLoop(ctx, c, uid)
		if err != nil {
			return proof, err
		}
		approveOnly, err := readEvidence(data)
		if err != nil {
			return proof, err
		}
		if !reflect.DeepEqual(before, approveOnly) {
			return proof, errors.New("approve alone performed publication or provider effect")
		}
		for _, record := range approved.Records {
			e := wire.EventFromProto(record.GetEvent())
			if e.Kind == api.EventToolResult || e.Kind == api.EventEnd {
				return proof, errors.New("approve alone executed the pending call")
			}
		}
		if err = resumeLoop(ctx, c, uid, approved.Session.GetLastSeq()); err != nil {
			return proof, err
		}
		completed, err := inspectLoop(ctx, c, uid)
		if err != nil {
			return proof, err
		}
		receipt, err := requireReceipt(completed, parked.Pending, true)
		if err != nil {
			return proof, err
		}
		effects, err := readEvidence(data)
		if err != nil {
			return proof, err
		}
		if effects.FakeModelCalls != 2 || effects.PublicationCount != 1 || effects.ReceiptCount != 1 || len(effects.Artifacts) != 1 || effects.Artifacts[0].Name != receipt.Output["artifact"] {
			return proof, errors.New("explicit Resume did not yield exactly one matching durable publication and receipt")
		}
		replay, err := verifyJournal(ctx, filepath.Join(data, "journal.db"), filepath.Join(data, "instructions.txt"), uid)
		if err != nil {
			return proof, err
		}
		afterReplay, err := readEvidence(data)
		if err != nil {
			return proof, err
		}
		afterView, err := inspectLoop(ctx, c, uid)
		if err != nil {
			return proof, err
		}
		if err = verifyUnchangedReplay(effects, afterReplay, completed, afterView, replay); err != nil {
			return proof, err
		}
		proof = loopProof{fixtureEvidence: effects, Session: uid, DeniedSession: parked.DeniedSession, HeadSeq: completed.Session.GetLastSeq(), HeadHash: completed.HeadHash, Published: true, DenyZeroEffects: true, ApproveOnlyEffects: 0, ArtifactInventoryUnchanged: true, Replay: &replay}
		return proof, nil
	default:
		return proof, errors.New("phase must be park or complete")
	}
}
