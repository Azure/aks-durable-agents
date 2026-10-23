package squadproof

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"unicode/utf8"
)

func (l *Ledger) Operation(ctx context.Context, id string) (Operation, error) {
	return readOperation(ctx, l.db, id)
}

func (l *Ledger) Admit(ctx context.Context, op Operation) (Operation, error) {
	var got Operation
	err := l.transaction(ctx, func(c *sql.Conn) error { var err error; got, err = admit(ctx, c, op); return err })
	return got, err
}
func admit(ctx context.Context, c *sql.Conn, op Operation) (Operation, error) {
	// Leave room for the fixed result-key prefix within an input's identity bound.
	if !identity(op.ID) || len(op.ID) > 128 || !identity(op.Team) || !digest(op.PackageDigest) || op.Epoch <= 0 || op.SessionUID != "" {
		return Operation{}, ErrInvalid
	}
	var err error
	op.Payload, op.PayloadHash, err = canonical(op.Payload)
	if err != nil {
		return Operation{}, err
	}
	if (op.Kind != "lead" || op.ParentID != "" || op.Member != "lead") && (op.Kind != "dispatch" || !identity(op.ParentID) || op.Member != "member") {
		return Operation{}, ErrInvalid
	}
	prior, err := readOperation(ctx, c, op.ID)
	if err == nil {
		if prior.Kind != op.Kind || prior.ParentID != op.ParentID || prior.Team != op.Team || prior.PackageDigest != op.PackageDigest || prior.Member != op.Member || prior.Epoch != op.Epoch || prior.PayloadHash != op.PayloadHash {
			return Operation{}, ErrConflict
		}
		return prior, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return Operation{}, err
	}
	if op.Kind == "dispatch" {
		parent, err := readOperation(ctx, c, op.ParentID)
		if err != nil {
			return Operation{}, err
		}
		if parent.Kind != "lead" || parent.Team != op.Team || parent.PackageDigest != op.PackageDigest {
			return Operation{}, ErrInvalid
		}
		if parent.Epoch != op.Epoch || parent.State == "uncertain" {
			return Operation{}, ErrHeld
		}
		var outstanding int
		if err = c.QueryRowContext(ctx, `SELECT count(*) FROM operations WHERE parent=? AND state<>'terminal'`, op.ParentID).Scan(&outstanding); err != nil {
			return Operation{}, err
		}
		if outstanding != 0 {
			return Operation{}, ErrHeld
		}
	}
	op.State, op.Evidence, op.Reason, op.InputHeadSeq = "admitted", Evidence{}, "", 0
	raw, err := json.Marshal(op)
	if err != nil {
		return Operation{}, err
	}
	if _, err = c.ExecContext(ctx, `INSERT INTO operations(id,parent,state,record) VALUES(?,?,?,?)`, op.ID, op.ParentID, op.State, raw); err != nil {
		return Operation{}, err
	}
	return op, event(ctx, c, "admitted", op.ID)
}

func (l *Ledger) BindSession(ctx context.Context, id, uid string) error {
	if !identity(uid) {
		return ErrInvalid
	}
	return l.transaction(ctx, func(c *sql.Conn) error {
		op, err := readOperation(ctx, c, id)
		if err != nil {
			return err
		}
		if op.State == "uncertain" {
			return ErrHeld
		}
		if op.SessionUID != "" {
			if op.SessionUID == uid {
				return nil
			}
			return ErrConflict
		}
		var count int
		if err = c.QueryRowContext(ctx, `SELECT count(*) FROM operations WHERE session_uid=?`, uid).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			return ErrConflict
		}
		op.SessionUID, op.State = uid, "mapped"
		if err = saveOperation(ctx, c, op); err != nil {
			return err
		}
		return event(ctx, c, "session-bound", id)
	})
}

// Observe records verified journal evidence without clearing uncertain outcomes.
// A new execution identity can only replace the previous one via ConfirmInput.
func (l *Ledger) Observe(ctx context.Context, id string, e Evidence) error {
	return l.transaction(ctx, func(c *sql.Conn) error {
		op, err := readOperation(ctx, c, id)
		if err != nil {
			return err
		}
		if op.State == "uncertain" {
			return ErrHeld
		}
		if op.Evidence.ExecutionID == "" {
			return ErrHeld
		}
		if !e.valid() || op.SessionUID == "" {
			return ErrInvalid
		}
		for _, seq := range []int64{e.RequestSeq, e.DecisionSeq, e.ReceiptSeq, e.EndSeq} {
			if seq != 0 && seq <= op.InputHeadSeq {
				return ErrConflict
			}
		}
		old := op.Evidence
		if reflect.DeepEqual(old, e) {
			return nil
		}
		if e.HeadSeq <= old.HeadSeq || (old.ExecutionID != "" && e.ExecutionID != old.ExecutionID) || e.RequestSeq < old.RequestSeq {
			return ErrConflict
		}
		if old.EndSeq > 0 && (e.EndSeq != old.EndSeq || e.EndHash != old.EndHash) {
			return ErrConflict
		}
		if e.RequestSeq == old.RequestSeq && ((old.DecisionSeq > 0 && old.DecisionSeq != e.DecisionSeq) || (old.ReceiptSeq > 0 && old.ReceiptSeq != e.ReceiptSeq)) {
			return ErrConflict
		}
		var pending int
		if err = c.QueryRowContext(ctx, `SELECT count(*) FROM inputs WHERE target=? AND state='delivering'`, id).Scan(&pending); err != nil {
			return err
		}
		if pending != 0 {
			return ErrHeld
		}
		op.Evidence, op.State = e, "running"
		if e.EndSeq > 0 {
			op.State = "terminal"
		} else if e.RequestSeq > 0 && e.ReceiptSeq == 0 {
			op.State = "awaiting-approval"
			if e.DecisionSeq > 0 {
				op.State = "continuation-pending"
			}
		}
		if err = saveOperation(ctx, c, op); err != nil {
			return err
		}
		return event(ctx, c, "observed", id)
	})
}
func (l *Ledger) MarkUncertain(ctx context.Context, id, reason string) error {
	if !identity(reason) {
		return ErrInvalid
	}
	return l.transaction(ctx, func(c *sql.Conn) error {
		op, err := readOperation(ctx, c, id)
		if err != nil {
			return err
		}
		if op.State == "terminal" {
			return ErrConflict
		}
		if op.State == "uncertain" {
			if op.Reason == reason {
				return nil
			}
			return ErrConflict
		}
		op.State, op.Reason = "uncertain", reason
		if err = saveOperation(ctx, c, op); err != nil {
			return err
		}
		return event(ctx, c, "uncertain", id)
	})
}

// AdvanceEpoch changes an idle owner only; active work cannot be orphaned by
// retirement. This is single-writer proof setup, not an in-flight execution lease.
func (l *Ledger) AdvanceEpoch(ctx context.Context, id string, old, next int64) error {
	if next <= 0 || next != old+1 {
		return ErrInvalid
	}
	return l.transaction(ctx, func(c *sql.Conn) error {
		op, err := readOperation(ctx, c, id)
		if err != nil {
			return err
		}
		if op.Kind != "lead" {
			return ErrInvalid
		}
		if op.State == "uncertain" {
			return ErrHeld
		}
		if op.Epoch != old {
			return ErrConflict
		}
		if op.State != "mapped" && op.State != "terminal" {
			return ErrHeld
		}
		var outstanding int
		if err = c.QueryRowContext(ctx, `SELECT count(*) FROM operations WHERE parent=? AND state<>'terminal'`, id).Scan(&outstanding); err != nil {
			return err
		}
		if outstanding != 0 {
			return ErrHeld
		}
		op.Epoch = next
		if err = saveOperation(ctx, c, op); err != nil {
			return err
		}
		return event(ctx, c, "epoch-advanced", id)
	})
}

// SeedContext is immutable host fixture setup. It never accepts model writes.
func (l *Ledger) SeedContext(ctx context.Context, id, key, value string) error {
	if !identity(key) || len(value) > 16<<10 || !utf8.ValidString(value) {
		return ErrInvalid
	}
	return l.transaction(ctx, func(c *sql.Conn) error {
		op, err := readOperation(ctx, c, id)
		if err != nil {
			return err
		}
		if op.Kind != "lead" {
			return ErrInvalid
		}
		if op.State == "uncertain" {
			return ErrHeld
		}
		var prior string
		err = c.QueryRowContext(ctx, `SELECT value FROM context WHERE root=? AND key=?`, id, key).Scan(&prior)
		if err == nil {
			if prior == value {
				return nil
			}
			return ErrConflict
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if _, err = c.ExecContext(ctx, `INSERT INTO context VALUES(?,?,?)`, id, key, value); err != nil {
			return err
		}
		return event(ctx, c, "context-seeded", id)
	})
}
