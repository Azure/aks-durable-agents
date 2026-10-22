// Package decisionrecord defines the shared, non-executing decision evidence
// exchanged by the host ledger and version history. Constructing these values
// authenticates nobody and grants no authority. Verification, policy, subject
// binding, persistence and execution remain with their owning packages.
package decisionrecord

import (
	"github.com/agent-primitives/sessions/api"
	"time"
)

type Identity = api.CallerIdentity
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

// SubjectRef is an opaque retained-subject identity, never an authorization.
type SubjectRef struct {
	Workspace  string
	Kind       Kind
	ID         string
	Generation uint64
	Digest     string
}
type DecideRequest struct {
	Workspace, Key string
	Subject        SubjectRef
	Action         Action
	Feedback       string
}

// Authorization is historical evidence supplied by verified host policy. A
// consumer must separately check current policy, not infer power from Role.
type Authorization struct {
	Actor               Identity
	Subject             SubjectRef
	Action              Action
	Role, PolicyVersion string
	GrantIDs            []string
}
type DecisionRecord struct {
	ID, StoreID, HostLineageID string
	Request                    DecideRequest
	RequestDigest              string
	Actor                      Identity
	Outcome                    string // recorded or refused; reject/deny remain explicit human actions.
	RefusalCode                string
	Authorization              *Authorization
	CommittedAt                time.Time
	Mode                       string
}
