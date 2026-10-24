package agentpackage

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
)

var (
	ErrUnavailable = errors.New("package unavailable")
	ErrIntegrity   = errors.New("package integrity failed")
	ErrUnsupported = errors.New("unsupported package")
)

// Error exposes only safe local diagnostics. StatusCode is the last observed
// response (zero if none); Rule is a local check, never a peer-supplied message.
// Unavailable is not an instruction to retry: e.g. 401/403 need credentials fixed.
type Error struct {
	Kind       error
	Role       string
	StatusCode int
	Rule       string
	cause      error // only a context sentinel, never an ORAS, URL or Suite error
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s: %s (%s; HTTP %d)", e.Role, e.Kind, e.Rule, e.StatusCode)
}
func (e *Error) Unwrap() []error {
	if e.cause == nil {
		return []error{e.Kind}
	}
	return []error{e.Kind, e.cause}
}
func fault(kind error, role, rule string) error { return &Error{Kind: kind, Role: role, Rule: rule} }
func cancellation(ctx context.Context, role string) error {
	return &Error{Kind: ErrUnavailable, Role: role, Rule: "context", cause: ctx.Err()}
}

type readKey struct{}
type readState struct {
	role   string
	status int
}

// Record response metadata before ORAS validates headers: some ORAS header
// integrity errors have no typed cause. Never classify by its URL/error text.
type statusTransport struct{ http.RoundTripper }

func (t statusTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.RoundTripper.RoundTrip(req)
	if s, ok := req.Context().Value(readKey{}).(*readState); ok && resp != nil {
		s.status = resp.StatusCode
	}
	return resp, err
}
func (s *readState) failure(ctx context.Context, kind error, rule string, err error) error {
	var network net.Error
	cause := ctx.Err()
	if cause == nil {
		for _, sentinel := range []error{context.Canceled, context.DeadlineExceeded} {
			if errors.Is(err, sentinel) {
				cause = sentinel
				break
			}
		}
	}
	if cause != nil {
		return &Error{Kind: ErrUnavailable, Role: s.role, StatusCode: s.status, Rule: "context", cause: cause}
	}
	var local *Error
	if errors.As(err, &local) {
		return &Error{Kind: local.Kind, Role: s.role, StatusCode: s.status, Rule: local.Rule, cause: local.cause}
	}
	if errors.As(err, &network) {
		kind = ErrUnavailable
	}
	if kind == nil {
		kind = ErrUnavailable
		if s.status == http.StatusOK && !errors.As(err, &network) {
			kind = ErrIntegrity
		}
	}
	return &Error{Kind: kind, Role: s.role, StatusCode: s.status, Rule: rule}
}
