//go:build squadproof

package squadproof

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"time"
)

const cutExit = 86

func cutMode(ctx context.Context, q queryer, point string) (string, error) {
	var raw string
	err := q.QueryRowContext(ctx, `SELECT operation FROM events WHERE kind=? ORDER BY ordinal DESC LIMIT 1`, "fault.arm."+point).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	var value struct {
		Mode string `json:"mode"`
	}
	if json.Unmarshal([]byte(raw), &value) != nil || value.Mode != "crash" && value.Mode != "pause" {
		return "", ErrForeign
	}
	return value.Mode, nil
}
func (l *Ledger) ArmCut(ctx context.Context, point, mode string) error {
	if !identity(point) || mode != "crash" && mode != "pause" {
		return ErrInvalid
	}
	return l.transaction(ctx, func(c *sql.Conn) error {
		old, err := cutMode(ctx, c, point)
		if err != nil {
			return err
		}
		if old != "" {
			if old == mode {
				return nil
			}
			return ErrConflict
		}
		raw, _ := json.Marshal(map[string]string{"mode": mode})
		return event(ctx, c, "fault.arm."+point, string(raw))
	})
}
func (l *Ledger) ReleaseCut(ctx context.Context, point string) error {
	if !identity(point) {
		return ErrInvalid
	}
	return l.transaction(ctx, func(c *sql.Conn) error {
		var n int
		if err := c.QueryRowContext(ctx, `SELECT count(*) FROM events WHERE kind='fault.release' AND operation=?`, point).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return nil
		}
		return event(ctx, c, "fault.release", point)
	})
}

// hit is proof instrumentation, never a domain effect. Reached state commits
// before a real process exit; a retained case cannot re-arm the same cut.
func (l *Ledger) hit(ctx context.Context, point string) error {
	var mode string
	trigger := false
	err := l.transaction(ctx, func(c *sql.Conn) error {
		var err error
		mode, err = cutMode(ctx, c, point)
		if err != nil || mode == "" {
			return err
		}
		var n int
		if err = c.QueryRowContext(ctx, `SELECT count(*) FROM events WHERE kind='fault.hit' AND operation=?`, point).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return nil
		}
		trigger = true
		return event(ctx, c, "fault.hit", point)
	})
	if err != nil || !trigger {
		return err
	}
	if mode == "crash" {
		os.Exit(cutExit)
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var n int
		if err = l.db.QueryRowContext(ctx, `SELECT count(*) FROM events WHERE kind='fault.release' AND operation=?`, point).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
