package host

import (
	"context"
	"errors"
	"log/slog"
	"regexp"
	"sync"
	"time"

	"github.com/agent-primitives/sessions/authn"
)

const (
	// authLogInterval bounds failure logging to one line per reason per interval.
	authLogInterval = time.Minute
	// keyExpiryWarning is a quarter of the verifier's 24h key-snapshot lifetime.
	keyExpiryWarning = 6 * time.Hour
)

// Fixed diagnostic codes are short lowercase words. Anything else is logged
// as "unclassified" so a verifier change cannot put error text in logs.
var debugReasonCode = regexp.MustCompile(`^[a-z_]{1,32}$`)

func debugReason(err error) string {
	var d interface{ DebugReason() string }
	if errors.As(err, &d) {
		if reason := d.DebugReason(); debugReasonCode.MatchString(reason) {
			return reason
		}
	}
	return "unclassified"
}

// loggingVerifier makes rejected callers observable. The sessions interceptors
// return a generic UNAUTHENTICATED and never log, so without this a bad token
// and an Entra outage look the same. Only the fixed DebugReason code and a
// suppressed count are logged, never the error text, token or claims.
type loggingVerifier struct {
	verifier authn.CallerVerifier
	logger   *slog.Logger
	now      func() time.Time
	mu       sync.Mutex
	reasons  map[string]*reasonLog
}

type reasonLog struct {
	next       time.Time
	suppressed int
}

func newLoggingVerifier(v authn.CallerVerifier, logger *slog.Logger, now func() time.Time) *loggingVerifier {
	return &loggingVerifier{verifier: v, logger: logger, now: now, reasons: map[string]*reasonLog{}}
}

// Verify returns the wrapped result unchanged.
func (l *loggingVerifier) Verify(ctx context.Context) (authn.VerifiedCaller, error) {
	caller, err := l.verifier.Verify(ctx)
	if err != nil {
		l.failed(debugReason(err))
	}
	return caller, err
}

func (l *loggingVerifier) failed(reason string)         { l.logFailure(reason, false) }
func (l *loggingVerifier) approvalFailed(reason string) { l.logFailure(reason, true) }

func (l *loggingVerifier) logFailure(reason string, approval bool) {
	message, contextMessage, key := "caller authentication failed", "caller context ended during authentication", reason
	if approval {
		message, contextMessage, key = "approval verification failed", "caller context ended during approval verification", "approval:"+reason
	}
	now := l.now()
	l.mu.Lock()
	r := l.reasons[key]
	if r == nil {
		r = &reasonLog{}
		l.reasons[key] = r
	}
	if now.Before(r.next) {
		r.suppressed++
		l.mu.Unlock()
		return
	}
	suppressed := r.suppressed
	r.next, r.suppressed = now.Add(authLogInterval), 0
	l.mu.Unlock()
	if reason == "canceled" || reason == "deadline" {
		// The caller's own RPC context ended (disconnect or client deadline),
		// for example while waiting on an unknown-key refresh. Not a credential
		// or Entra failure, so keep it out of the warnings.
		l.logger.Debug(contextMessage, "reason", reason, "suppressed", suppressed)
		return
	}
	l.logger.Warn(message, "reason", reason, "suppressed", suppressed)
}

// refreshErrorLogger reports failed background Entra key refreshes. Refreshes
// run at most hourly plus one unknown-key attempt per five minutes, so this
// needs no rate limit. A failed refresh never extends the snapshot, so the
// warning escalates as the snapshot nears and passes expiry.
func refreshErrorLogger(logger *slog.Logger, now func() time.Time) func(string, time.Time) {
	return func(reason string, keysExpire time.Time) {
		if !debugReasonCode.MatchString(reason) {
			reason = "unclassified"
		}
		left := keysExpire.Sub(now()).Truncate(time.Second)
		switch {
		case left <= 0:
			logger.Error("Entra signing keys expired; all authentication fails until a key refresh succeeds", "reason", reason)
		case left <= keyExpiryWarning:
			logger.Warn("Entra signing-key refresh failed; key snapshot nears expiry", "reason", reason, "keys_expire_in", left)
		default:
			logger.Warn("Entra signing-key refresh failed", "reason", reason, "keys_expire_in", left)
		}
	}
}
