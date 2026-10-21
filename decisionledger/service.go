package decisionledger

import (
	"context"
	"errors"
	"sync"

	"github.com/Azure/aks-durable-agents/entraauth"
)

// HumanVerifier must verify this request's delegated token itself. A browser's
// provenance, a role label or an execution-service identity is not a human.
type HumanVerifier interface {
	VerifyHuman(context.Context) (entraauth.VerifiedHuman, error)
}

// DecisionPolicy is a trusted host adapter. WithDecision holds current resource
// policy/revocation serialization across one synchronous commit callback and
// returns its error. ErrDenied is an authorization refusal; other errors mean
// unavailable policy, not a durable rejection. There is no default policy.
type DecisionPolicy interface {
	AuthorizeRead(context.Context, entraauth.VerifiedHuman, Subject) error
	WithDecision(context.Context, entraauth.VerifiedHuman, Subject, Action, func(Authorization) error) error
}
type Service struct {
	store    *Store
	verifier HumanVerifier
	policy   DecisionPolicy
}

func NewService(store *Store, verifier HumanVerifier, policy DecisionPolicy) (*Service, error) {
	if store == nil || verifier == nil || policy == nil {
		return nil, ErrInvalid
	}
	return &Service{store, verifier, policy}, nil
}
func (s *Service) human(ctx context.Context) (entraauth.VerifiedHuman, error) {
	if err := ctx.Err(); err != nil {
		return entraauth.VerifiedHuman{}, err
	}
	h, err := s.verifier.VerifyHuman(ctx)
	if err != nil || !h.Caller.Identity.Valid() || !s.store.now().Before(h.Caller.ValidUntil) || len(h.Roles) == 0 {
		return entraauth.VerifiedHuman{}, ErrUnauthenticated
	}
	for _, role := range h.Roles {
		if !textOK(role, 256) {
			return entraauth.VerifiedHuman{}, ErrUnauthenticated
		}
	}
	return h, nil
}
func (s *Service) visible(ctx context.Context, h entraauth.VerifiedHuman, subject Subject) error {
	if err := s.policy.AuthorizeRead(ctx, h, subject); err != nil {
		if errors.Is(err, ErrDenied) {
			return ErrDenied
		}
		return ErrUnavailable
	}
	if !s.store.now().Before(h.Caller.ValidUntil) {
		return ErrUnauthenticated
	}
	return ctx.Err()
}

// Get reads only the freshly verified person's request-key namespace. History
// reads for another human or a workload need a separately authorized API.
func (s *Service) Get(ctx context.Context, workspace, key string) (DecisionRecord, error) {
	h, err := s.human(ctx)
	if err != nil {
		return DecisionRecord{}, err
	}
	if !textOK(workspace, 256) || !keyOK(key) {
		return DecisionRecord{}, ErrInvalid
	}
	out, err := s.store.lookup(ctx, h.Caller.Identity, workspace, key)
	if err != nil {
		return DecisionRecord{}, err
	}
	subject, _, err := s.store.subject(ctx, out.Request.Subject)
	if err != nil {
		return DecisionRecord{}, err
	}
	if err = s.visible(ctx, h, subject); err != nil {
		return DecisionRecord{}, err
	}
	return out, nil
}

// Decide persists only a decision. No session approval, Resume, target activation
// or tool/model capability is reachable from this service.
func (s *Service) Decide(ctx context.Context, r DecideRequest) (DecisionRecord, error) {
	h, err := s.human(ctx)
	if err != nil {
		return DecisionRecord{}, err
	}
	hash, err := r.fingerprint()
	if err != nil {
		return DecisionRecord{}, err
	}
	subject, _, err := s.store.subject(ctx, r.Subject)
	if err != nil {
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrConflict) {
			return DecisionRecord{}, ErrDenied
		}
		return DecisionRecord{}, err
	}
	if err = s.visible(ctx, h, subject); err != nil {
		return DecisionRecord{}, err
	}
	prior, err := s.store.lookup(ctx, h.Caller.Identity, r.Workspace, r.Key)
	if err == nil {
		if prior.RequestDigest != hash {
			return DecisionRecord{}, ErrConflict
		}
		return prior, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return DecisionRecord{}, err
	}
	// A misbehaving adapter cannot invoke a saved callback after the guard returns
	// or suppress its commit error. Policy adapters are trusted host code, not RPC
	// inputs; durable policy/dispatch serialization is still D2's responsibility.
	var mu sync.Mutex
	active := true
	calls := 0
	var commitErr error
	policyErr := s.policy.WithDecision(ctx, h, subject, r.Action, func(a Authorization) error {
		mu.Lock()
		defer mu.Unlock()
		if !active || calls != 0 {
			commitErr = ErrUnavailable
			return commitErr
		}
		calls++
		if !a.valid(h.Caller.Identity, r.Subject, r.Action, h.Roles) {
			commitErr = ErrDenied
			return commitErr
		}
		_, commitErr = s.store.commit(ctx, h.Caller.Identity, h.Caller.ValidUntil, r, &a, "")
		return commitErr
	})
	mu.Lock()
	active = false
	n, writeErr := calls, commitErr
	mu.Unlock()
	if writeErr != nil {
		return DecisionRecord{}, writeErr
	}
	if n == 0 && errors.Is(policyErr, ErrDenied) {
		if _, err = s.store.commit(ctx, h.Caller.Identity, h.Caller.ValidUntil, r, nil, "policy_denied"); err != nil {
			return DecisionRecord{}, err
		}
	} else if policyErr != nil || n != 1 {
		return DecisionRecord{}, ErrUnavailable
	}
	// Read the durable result and recheck current visibility; lost replies/errors
	// here remain uncertain, and a fresh explicit Get can recover the same record.
	out, err := s.Get(ctx, r.Workspace, r.Key)
	if err != nil {
		return DecisionRecord{}, ErrUnavailable
	}
	return out, nil
}
