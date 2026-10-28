package githubtools

import (
	"context"
	"database/sql"
	"errors"

	"github.com/agent-primitives/sessions/api"
)

func activeApproval(ctx context.Context, c *sql.Conn, call Call) (ApprovalRecord, error) {
	var r ApprovalRecord
	var raw string
	err := c.QueryRowContext(ctx, "SELECT record FROM approvals WHERE slot=? AND state='active'", call.slot()).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrNotFound
	}
	if err != nil || decode(raw, &r) != nil || !r.valid() {
		return r, ErrUnavailable
	}
	if r.Call != call {
		return r, ErrConflict
	}
	return r, nil
}
func readIntent(ctx context.Context, c *sql.Conn, call Call) (Intent, error) {
	var i Intent
	var raw string
	err := c.QueryRowContext(ctx, "SELECT record FROM intents WHERE slot=? OR (session_uid=? AND request_key=?)", call.slot(), call.SessionUID, call.Key).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return i, ErrNotFound
	}
	if err != nil || decode(raw, &i) != nil {
		return i, ErrUnavailable
	}
	if i.Call != call {
		return i, ErrConflict
	}
	return i, nil
}

// PrepareApproval retains verified attribution before the native Approve RPC.
// This pending record alone never authorizes release. Call evidence remains
// immutable even if a pending attempt is later explicitly abandoned.
func (s *Store) PrepareApproval(ctx context.Context, a Approval) error {
	if !a.valid() {
		return ErrInvalid
	}
	return s.transaction(ctx, func(c *sql.Conn) error {
		rows, err := c.QueryContext(ctx, "SELECT record FROM approvals WHERE slot=? OR (session_uid=? AND request_key=?)", a.Call.slot(), a.Call.SessionUID, a.Call.Key)
		if err != nil {
			return ErrUnavailable
		}
		active := false
		for rows.Next() {
			var raw string
			var old ApprovalRecord
			if rows.Scan(&raw) != nil || decode(raw, &old) != nil || !old.valid() {
				rows.Close()
				return ErrUnavailable
			}
			if old.Call != a.Call {
				rows.Close()
				return ErrConflict
			}
			if old.AbandonedAt.IsZero() {
				if old.Approval != a {
					rows.Close()
					return ErrConflict
				}
				active = true
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return ErrUnavailable
		}
		if active {
			return nil
		}
		r := ApprovalRecord{Approval: a, ID: randomID(), PreparedAt: s.now().UTC()}
		if !r.valid() {
			return ErrUnavailable
		}
		_, err = c.ExecContext(ctx, "INSERT INTO approvals VALUES(?,?,?,?,?,?)", r.ID, a.Call.slot(), a.Call.SessionUID, a.Call.Key, "active", encode(r))
		if err != nil {
			return ErrUnavailable
		}
		return nil
	})
}

// CommitApproval links the exact native decision found by the host. The host
// must validate its journal evidence; this API cannot turn attribution into a
// native approval. It also permits recovery of a matched pending/native cut.
func (s *Store) CommitApproval(ctx context.Context, call Call, approver api.CallerIdentity, decisionSeq int64) error {
	if !call.valid() || !identityOK(approver) || decisionSeq <= call.RequestSeq {
		return ErrInvalid
	}
	return s.transaction(ctx, func(c *sql.Conn) error {
		r, err := activeApproval(ctx, c, call)
		if err != nil {
			return err
		}
		if r.Approver != approver || r.DecisionSeq != 0 && r.DecisionSeq != decisionSeq {
			return ErrConflict
		}
		r.DecisionSeq = decisionSeq
		_, err = c.ExecContext(ctx, "UPDATE approvals SET record=? WHERE id=?", encode(r), r.ID)
		if err != nil {
			return ErrUnavailable
		}
		return nil
	})
}

// AbandonApproval is only for a trusted host that has proved there is no native
// decision, under the SAME host gate as this transition. Timeout is not proof.
// Retaining history allows a replacement approver without transferring identity.
func (s *Store) AbandonApproval(ctx context.Context, call Call, approver api.CallerIdentity, observedHead int64) error {
	if !call.valid() || !identityOK(approver) || observedHead < call.RequestSeq {
		return ErrInvalid
	}
	return s.transaction(ctx, func(c *sql.Conn) error {
		r, err := activeApproval(ctx, c, call)
		if err != nil {
			return err
		}
		if r.Approver != approver || r.DecisionSeq != 0 {
			return ErrConflict
		}
		r.AbandonedAt = s.now().UTC()
		r.AbandonedHead = observedHead
		if !r.valid() {
			return ErrUnavailable
		}
		_, err = c.ExecContext(ctx, "UPDATE approvals SET state='abandoned',record=? WHERE id=?", encode(r), r.ID)
		if err != nil {
			return ErrUnavailable
		}
		return nil
	})
}
func (s *Store) Approval(ctx context.Context, call Call) (ApprovalRecord, error) {
	var r ApprovalRecord
	if !call.valid() {
		return r, ErrInvalid
	}
	err := s.transaction(ctx, func(c *sql.Conn) error { var err error; r, err = activeApproval(ctx, c, call); return err })
	return r, err
}

// Reserve atomically retains release evidence and intent before any POST. Only
// created=true permits this invocation to send. A duplicate unknown intent never
// creates another owner, even across a process restart or under a new key.
func (s *Store) Reserve(ctx context.Context, call Call, decisionSeq int64) (intent Intent, created bool, err error) {
	if !call.valid() || decisionSeq <= call.RequestSeq {
		return intent, false, ErrInvalid
	}
	err = s.transaction(ctx, func(c *sql.Conn) error {
		old, err := readIntent(ctx, c, call)
		if err == nil {
			if old.DecisionSeq != decisionSeq {
				return ErrConflict
			}
			intent = old
			if intentState(old) == "unknown" {
				return ErrUnknownOutcome
			}
			return nil
		}
		if !errors.Is(err, ErrNotFound) {
			return err
		}
		r, err := activeApproval(ctx, c, call)
		if err != nil {
			return err
		}
		if !r.Approved || r.DecisionSeq != decisionSeq {
			return ErrConflict
		}
		var held int
		if c.QueryRowContext(ctx, "SELECT count(*) FROM intents WHERE state='unknown' AND (session_uid=? OR operation_digest=?)", call.SessionUID, call.OperationDigest).Scan(&held) != nil {
			return ErrUnavailable
		}
		if held > 0 {
			return ErrUnknownOutcome
		}
		intent = Intent{Call: call, ApprovalID: r.ID, ReservationID: randomID(), DecisionSeq: decisionSeq, ReservedAt: s.now().UTC()}
		if !intent.valid(r) {
			return ErrUnavailable
		}
		_, err = c.ExecContext(ctx, "INSERT INTO intents VALUES(?,?,?,?,?,?,?)", call.slot(), r.ID, call.SessionUID, call.Key, call.OperationDigest, "unknown", encode(intent))
		if err != nil {
			return ErrUnavailable
		}
		created = true
		return nil
	})
	// A failed/uncertain COMMIT cannot authorize a POST; read back the same call.
	if err != nil {
		created = false
	}
	return
}

func (s *Store) Intent(ctx context.Context, call Call) (Intent, error) {
	var i Intent
	if !call.valid() {
		return i, ErrInvalid
	}
	err := s.transaction(ctx, func(c *sql.Conn) error { var err error; i, err = readIntent(ctx, c, call); return err })
	return i, err
}

// Finish durably saves a bounded outcome before the executor returns. A failed
// write leaves the original reservation unknown. Terminal results are immutable;
// an unknown result is not an invitation to reconcile or repost automatically.
func (s *Store) Finish(ctx context.Context, call Call, reservationID string, outcome Outcome) error {
	if !call.valid() || !textOK(reservationID, 64) || !outcome.valid() {
		return ErrInvalid
	}
	return s.transaction(ctx, func(c *sql.Conn) error {
		i, err := readIntent(ctx, c, call)
		if err != nil {
			return err
		}
		if i.ReservationID != reservationID {
			return ErrConflict
		}
		if i.Outcome != nil {
			if *i.Outcome != outcome {
				return ErrConflict
			}
			return nil
		}
		i.Outcome = &outcome
		_, err = c.ExecContext(ctx, "UPDATE intents SET state=?,record=? WHERE slot=?", intentState(i), encode(i), call.slot())
		if err != nil {
			return ErrUnavailable
		}
		return nil
	})
}
