//go:build squadproof

package squadproof

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/agent-primitives/sessions/api"
)

func (l *Ledger) Operations(ctx context.Context) ([]Operation, error) {
	rows, err := l.db.QueryContext(ctx, `SELECT record FROM operations ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Operation
	for rows.Next() {
		var raw []byte
		var op Operation
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		if json.Unmarshal(raw, &op) != nil {
			return nil, ErrForeign
		}
		out = append(out, op)
	}
	return out, rows.Err()
}

func (l *Ledger) beginAllocation(ctx context.Context, id string) error {
	return l.transaction(ctx, func(c *sql.Conn) error {
		op, err := readOperation(ctx, c, id)
		if err != nil {
			return err
		}
		if op.State != "admitted" || op.SessionUID != "" {
			return ErrHeld
		}
		op.State = "allocating"
		if err = saveOperation(ctx, c, op); err != nil {
			return err
		}
		raw, err := json.Marshal(map[string]string{"operation": id})
		if err != nil {
			return err
		}
		return event(ctx, c, "broker.create", string(raw))
	})
}

type brokerAction struct {
	Op        string
	Decision  api.ApprovalDecision
	Seq, Head int64
	Phase     string
}

func (a brokerAction) key() string {
	return fmt.Sprintf("%s\x00%s\x00%d\x00%s", a.Op, a.Decision.ExecutionID, a.Decision.RequestSeq, a.Decision.ToolCallID)
}

type brokerReader interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func brokerActions(ctx context.Context, q brokerReader) ([]brokerAction, error) {
	rows, err := q.QueryContext(ctx, `SELECT operation FROM events WHERE kind='broker.action' ORDER BY ordinal`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []brokerAction
	positions := map[string]int{}
	for rows.Next() {
		var raw []byte
		var a brokerAction
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		if json.Unmarshal(raw, &a) != nil {
			return nil, ErrForeign
		}
		if i, ok := positions[a.key()]; ok {
			out[i] = a
		} else {
			positions[a.key()] = len(out)
			out = append(out, a)
		}
	}
	return out, rows.Err()
}
func (l *Ledger) saveAction(ctx context.Context, a brokerAction) error {
	return l.transaction(ctx, func(c *sql.Conn) error {
		actions, err := brokerActions(ctx, c)
		if err != nil {
			return err
		}
		for _, old := range actions {
			if old.key() == a.key() {
				if old.Decision != a.Decision || old.Seq != 0 && old.Seq != a.Seq {
					return ErrConflict
				}
				if old == a {
					return nil
				}
				if old.Phase == "done" || old.Phase == "held" {
					return ErrHeld
				}
			}
		}
		raw, err := json.Marshal(a)
		if err != nil {
			return err
		}
		return event(ctx, c, "broker.action", string(raw))
	})
}
