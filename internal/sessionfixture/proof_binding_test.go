package sessionfixture

import (
	"strings"
	"testing"

	v1 "github.com/agent-primitives/sessions/api/genpb"
)

func TestReplayProofBindsTheExactRPCHead(t *testing.T) {
	view := inspection{Session: &v1.Session{Metadata: &v1.ResourceMetadata{Uid: "session-1"}, LastSeq: 12}, HeadHash: "head-12"}
	evidence := fixtureEvidence{FakeModelCalls: 2, Artifacts: []artifactDigest{}}
	matching := replayProof{SessionUID: "session-1", HeadSeq: 12, HeadHash: "head-12"}
	if err := verifyUnchangedReplay(evidence, evidence, view, view, matching); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		proof replayProof
	}{
		{"stale sequence", replayProof{SessionUID: "session-1", HeadSeq: 11, HeadHash: "head-12"}},
		{"different hash", replayProof{SessionUID: "session-1", HeadSeq: 12, HeadHash: "other-head"}},
		{"different session", replayProof{SessionUID: "session-2", HeadSeq: 12, HeadHash: "head-12"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyUnchangedReplay(evidence, evidence, view, view, tc.proof)
			if err == nil || !strings.Contains(err.Error(), "RPC head") {
				t.Fatalf("unbound proof accepted: %v", err)
			}
		})
	}
}
