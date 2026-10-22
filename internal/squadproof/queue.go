package squadproof

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
)

// Enqueue accepts host-originated user/tick/task input. Member results must use
// EnqueueResult so a payload cannot invent terminal evidence or its own result key.
func (l *Ledger) Enqueue(ctx context.Context, in Input) (Input, error) {
	if in.Source != "" || in.TerminalHash != "" || (in.Kind != "user" && in.Kind != "tick" && in.Kind != "task") {
		return Input{}, ErrInvalid
	}
	var got Input
	err := l.transaction(ctx, func(c *sql.Conn) error { var err error; got, err = enqueue(ctx, c, in); return err })
	return got, err
}
func enqueue(ctx context.Context, c *sql.Conn, in Input) (Input, error) {
	if !identity(in.ID) {
		return Input{}, ErrInvalid
	}
	target, err := readOperation(ctx, c, in.Target)
	if err != nil {
		return Input{}, err
	}
	if target.State == "uncertain" {
		return Input{}, ErrHeld
	}
	if (target.Kind == "dispatch") != (in.Kind == "task") {
		return Input{}, ErrInvalid
	}
	in.Payload, in.PayloadHash, err = canonical(in.Payload)
	if err != nil {
		return Input{}, err
	}
	var raw []byte
	err = c.QueryRowContext(ctx, `SELECT record FROM inputs WHERE id=?`, in.ID).Scan(&raw)
	if err == nil {
		var old Input
		if json.Unmarshal(raw, &old) != nil {
			return Input{}, ErrForeign
		}
		if old.Target != in.Target || old.Kind != in.Kind || old.Source != in.Source || old.TerminalHash != in.TerminalHash || old.PayloadHash != in.PayloadHash {
			return Input{}, ErrConflict
		}
		return old, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Input{}, err
	}
	in.Ordinal, in.ExecutionID, in.State, in.Epoch, in.HeadSeq = 0, "", "queued", 0, 0
	if target.Evidence.RequestSeq > 0 && target.Evidence.ReceiptSeq == 0 {
		in.State = "queued-behind-approval"
	}
	raw, err = json.Marshal(in)
	if err != nil {
		return Input{}, err
	}
	result, err := c.ExecContext(ctx, `INSERT INTO inputs(id,target,state,record) VALUES(?,?,?,?)`, in.ID, in.Target, in.State, raw)
	if err != nil {
		return Input{}, err
	}
	in.Ordinal, err = result.LastInsertId()
	if err != nil {
		return Input{}, err
	}
	if err = saveInput(ctx, c, in); err != nil {
		return Input{}, err
	}
	return in, event(ctx, c, "input-queued", in.Target)
}
func saveInput(ctx context.Context, c *sql.Conn, in Input) error {
	raw, err := json.Marshal(in)
	if err != nil {
		return err
	}
	_, err = c.ExecContext(ctx, `UPDATE inputs SET state=?,execution_id=NULLIF(?,''),record=? WHERE id=?`, in.State, in.ExecutionID, raw, in.ID)
	return err
}
func (l *Ledger) EnqueueResult(ctx context.Context, child string, payload []byte) (Input, error) {
	var in Input
	err := l.transaction(ctx, func(c *sql.Conn) error {
		op, err := readOperation(ctx, c, child)
		if err != nil {
			return err
		}
		if op.Kind != "dispatch" || op.State != "terminal" || op.Evidence.EndSeq == 0 {
			return ErrHeld
		}
		in, err = enqueue(ctx, c, Input{ID: "result-" + child, Target: op.ParentID, Kind: "result", Source: child, TerminalHash: op.Evidence.EndHash, Payload: payload})
		return err
	})
	return in, err
}
func (l *Ledger) Inputs(ctx context.Context, target string) ([]Input, error) {
	rows, err := l.db.QueryContext(ctx, `SELECT record FROM inputs WHERE target=? ORDER BY ordinal`, target)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Input
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		var in Input
		if json.Unmarshal(raw, &in) != nil {
			return nil, ErrForeign
		}
		out = append(out, in)
	}
	return out, rows.Err()
}

// NextInput reserves one input before an RPC, never blindly redelivers it. A lost
// outcome must be held/marked uncertain; ConfirmInput requires an acknowledged ID.
func (l *Ledger) NextInput(ctx context.Context, target string, epoch, expectedHead int64) (Input, error) {
	var in Input
	err := l.transaction(ctx, func(c *sql.Conn) error {
		op, err := readOperation(ctx, c, target)
		if err != nil {
			return err
		}
		root := op
		if op.ParentID != "" {
			root, err = readOperation(ctx, c, op.ParentID)
			if err != nil {
				return err
			}
		}
		if op.State == "uncertain" || root.State == "uncertain" || op.Epoch != epoch || root.Epoch != epoch || op.SessionUID == "" {
			return ErrHeld
		}
		if op.Evidence.HeadSeq != expectedHead {
			return ErrConflict
		}
		if op.State != "mapped" && op.State != "terminal" {
			return ErrHeld
		}
		if op.Evidence.ExecutionID != "" && (op.Evidence.EndSeq == 0 || (op.Evidence.RequestSeq > 0 && op.Evidence.ReceiptSeq == 0)) {
			return ErrHeld
		}
		if op.Kind == "dispatch" && op.State == "terminal" {
			return ErrHeld
		}
		var raw []byte
		err = c.QueryRowContext(ctx, `SELECT record FROM inputs WHERE target=? AND state IN ('queued','queued-behind-approval') ORDER BY ordinal LIMIT 1`, target).Scan(&raw)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if json.Unmarshal(raw, &in) != nil {
			return ErrForeign
		}
		in.State, in.Epoch, in.HeadSeq = "delivering", epoch, expectedHead
		if err = saveInput(ctx, c, in); err != nil {
			return err
		}
		op.State = "running"
		op.Evidence = Evidence{HeadSeq: op.Evidence.HeadSeq, HeadHash: op.Evidence.HeadHash}
		if err = saveOperation(ctx, c, op); err != nil {
			return err
		}
		return event(ctx, c, "input-reserved", target)
	})
	if err != nil {
		return Input{}, err
	}
	return in, nil
}
func (l *Ledger) ConfirmInput(ctx context.Context, id, executionID string) error {
	if !identity(executionID) {
		return ErrInvalid
	}
	return l.transaction(ctx, func(c *sql.Conn) error {
		var raw []byte
		if err := c.QueryRowContext(ctx, `SELECT record FROM inputs WHERE id=?`, id).Scan(&raw); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		var in Input
		if json.Unmarshal(raw, &in) != nil {
			return ErrForeign
		}
		op, err := readOperation(ctx, c, in.Target)
		if err != nil {
			return err
		}
		root := op
		if op.ParentID != "" {
			root, err = readOperation(ctx, c, op.ParentID)
			if err != nil {
				return err
			}
		}
		if op.State == "uncertain" || root.State == "uncertain" || in.Epoch != op.Epoch || in.Epoch != root.Epoch {
			return ErrHeld
		}
		if in.State == "delivered" {
			if in.ExecutionID == executionID {
				return nil
			}
			return ErrConflict
		}
		if in.State != "delivering" || op.State != "running" {
			return ErrConflict
		}
		var reused int
		if err = c.QueryRowContext(ctx, `SELECT count(*) FROM inputs WHERE target=? AND execution_id=?`, in.Target, executionID).Scan(&reused); err != nil {
			return err
		}
		if reused != 0 {
			return ErrConflict
		}
		in.State, in.ExecutionID = "delivered", executionID
		if err = saveInput(ctx, c, in); err != nil {
			return err
		}
		op.Evidence.ExecutionID, op.InputHeadSeq = executionID, in.HeadSeq
		if err = saveOperation(ctx, c, op); err != nil {
			return err
		}
		return event(ctx, c, "input-confirmed", op.ID)
	})
}
