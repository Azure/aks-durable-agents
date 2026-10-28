package githubtools

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
	"unicode/utf8"

	"github.com/agent-primitives/sessions/api"
)

const readRecordLimit = 8 << 20

// ReadCall is ordinary TOOL_CALL evidence, without invented approval sequences.
type ReadCall struct {
	SessionUID, ExecutionID, CallID, Key string
	CallSeq                              int64
	CallHash                             string
	Requester                            api.CallerIdentity
	AppID, InstallationID, RepositoryID  string
	IssueNumber                          int64
}
type ReadOutcome struct {
	Issue       Issue
	FailureCode string
}
type ReadRecord struct {
	Call                  ReadCall
	StartedAt, FinishedAt time.Time
	Outcome               *ReadOutcome
}

func (c ReadCall) valid() bool {
	if !textOK(c.SessionUID, 256) || !textOK(c.ExecutionID, 256) || !textOK(c.CallID, 256) || !textOK(c.Key, 128) || c.CallSeq <= 0 || !digestOK(c.CallHash) || !identityOK(c.Requester) || !decimalID(c.AppID) || !decimalID(c.InstallationID) || !decimalID(c.RepositoryID) || c.IssueNumber <= 0 || c.IssueNumber > 1<<53-1 {
		return false
	}
	for _, b := range []byte(c.Key) {
		if b < 33 || b > 126 {
			return false
		}
	}
	return true
}
func (c ReadCall) slot() string {
	raw, _ := json.Marshal([]any{c.SessionUID, c.ExecutionID, c.CallID, c.CallSeq})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func (o ReadOutcome) valid(c ReadCall) bool {
	if o.FailureCode != "" {
		return o.Issue == (Issue{}) && (o.FailureCode == "read_unavailable" || o.FailureCode == "access_unavailable")
	}
	return o.Issue.Number == c.IssueNumber && o.Issue.Title != "" && len(o.Issue.Title) <= githubBodyLimit && utf8.ValidString(o.Issue.Title) && len(o.Issue.Body) <= githubBodyLimit && utf8.ValidString(o.Issue.Body) && textOK(o.Issue.URL, 2048)
}
func (r ReadRecord) valid() bool {
	return r.Call.valid() && !r.StartedAt.IsZero() && ((r.Outcome == nil && r.FinishedAt.IsZero()) || (r.Outcome != nil && !r.FinishedAt.IsZero() && r.Outcome.valid(r.Call))) && len(encode(r)) <= readRecordLimit
}
func decodeRead(raw string, r *ReadRecord) error { return decodeBound(raw, r, readRecordLimit) }

func noReadKey(ctx context.Context, c *sql.Conn, uid, key string) error {
	var n int
	if c.QueryRowContext(ctx, "SELECT count(*) FROM reads WHERE session_uid=? AND request_key=?", uid, key).Scan(&n) != nil {
		return ErrUnavailable
	}
	if n != 0 {
		return ErrConflict
	}
	return nil
}
func readCached(ctx context.Context, c *sql.Conn, call ReadCall) (ReadRecord, error) {
	var r ReadRecord
	var raw string
	err := c.QueryRowContext(ctx, "SELECT record FROM reads WHERE slot=? OR (session_uid=? AND request_key=?)", call.slot(), call.SessionUID, call.Key).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrNotFound
	}
	if err != nil || decodeRead(raw, &r) != nil || !r.valid() {
		return r, ErrUnavailable
	}
	if r.Call != call {
		return r, ErrConflict
	}
	return r, nil
}

// PrepareRead audits admission before GET. Pending reads may be repeated because
// GET has no external side effect, unlike a pending comment intent.
func (s *Store) PrepareRead(ctx context.Context, call ReadCall) (record ReadRecord, err error) {
	if !call.valid() {
		return record, ErrInvalid
	}
	err = s.transaction(ctx, func(c *sql.Conn) error {
		var n int
		if c.QueryRowContext(ctx, "SELECT count(*) FROM approvals WHERE session_uid=? AND request_key=?", call.SessionUID, call.Key).Scan(&n) != nil {
			return ErrUnavailable
		}
		if n != 0 {
			return ErrConflict
		}
		old, err := readCached(ctx, c, call)
		if err == nil {
			record = old
			return nil
		}
		if !errors.Is(err, ErrNotFound) {
			return err
		}
		record = ReadRecord{Call: call, StartedAt: s.now().UTC()}
		if !record.valid() {
			return ErrUnavailable
		}
		if _, err = c.ExecContext(ctx, "INSERT INTO reads VALUES(?,?,?,?)", call.slot(), call.SessionUID, call.Key, encode(record)); err != nil {
			return ErrUnavailable
		}
		return nil
	})
	return
}
func (s *Store) Read(ctx context.Context, call ReadCall) (record ReadRecord, err error) {
	if !call.valid() {
		return record, ErrInvalid
	}
	err = s.transaction(ctx, func(c *sql.Conn) error { record, err = readCached(ctx, c, call); return err })
	return
}

// SaveRead returns the first durable outcome. Concurrent safe GETs may complete
// differently, but cannot overwrite that first result or return a newer one.
func (s *Store) SaveRead(ctx context.Context, call ReadCall, outcome ReadOutcome) (record ReadRecord, err error) {
	if !call.valid() || !outcome.valid(call) {
		return record, ErrInvalid
	}
	err = s.transaction(ctx, func(c *sql.Conn) error {
		var err error
		record, err = readCached(ctx, c, call)
		if err != nil {
			return err
		}
		if record.Outcome != nil {
			return nil
		}
		record.Outcome = &outcome
		record.FinishedAt = s.now().UTC()
		if !record.valid() {
			return ErrUnavailable
		}
		if _, err = c.ExecContext(ctx, "UPDATE reads SET record=? WHERE slot=?", encode(record), call.slot()); err != nil {
			return ErrUnavailable
		}
		return nil
	})
	return
}
func (s *Store) verifyReads() error {
	rows, err := s.db.Query("SELECT slot,session_uid,request_key,record FROM reads")
	if err != nil {
		return ErrUnavailable
	}
	defer rows.Close()
	for rows.Next() {
		var slot, uid, key, raw string
		var r ReadRecord
		if rows.Scan(&slot, &uid, &key, &raw) != nil || decodeRead(raw, &r) != nil || !r.valid() || slot != r.Call.slot() || uid != r.Call.SessionUID || key != r.Call.Key {
			return ErrUnavailable
		}
	}
	if rows.Err() != nil {
		return ErrUnavailable
	}
	rows.Close()
	var n int
	if s.db.QueryRow("SELECT count(*) FROM reads r JOIN approvals a ON r.session_uid=a.session_uid AND r.request_key=a.request_key").Scan(&n) != nil || n != 0 {
		return ErrUnavailable
	}
	return nil
}
