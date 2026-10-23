package squadproof

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/agent-primitives/sessions/api"
	"github.com/agent-primitives/sessions/controller"
)

// Executor is only a simulated local executor. Sessions must enforce approval
// before calling it; it cannot authenticate an approver or validate a journal.
type Executor struct{ Ledger *Ledger }

func arguments(raw []byte, dst any, fields string) error {
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil {
		return ErrInvalid
	}
	for key := range object {
		if !slices.Contains(strings.Fields(fields), key) {
			return ErrInvalid
		}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(dst) != nil {
		return ErrInvalid
	}
	return nil
}
func (e *Executor) Execute(ctx context.Context, scope controller.ToolCallContext, call api.ToolCall) (api.ToolResult, error) {
	if !identity(scope.SessionUID) || !identity(call.ID) || !identity(call.IdempotencyKey) {
		return api.ToolResult{}, ErrInvalid
	}
	mediation := api.MediationControllerMediated
	if call.Tool == "publish" || call.Tool == "checkpoint" {
		mediation = api.MediationRequiresApproval
	}
	if call.Mediation != mediation {
		return api.ToolResult{}, ErrInvalid
	}
	raw, err := json.Marshal(call.Args)
	if err != nil {
		return api.ToolResult{}, ErrInvalid
	}
	raw, _, err = canonical(raw)
	if err != nil {
		return api.ToolResult{}, err
	}
	var input struct {
		Epoch int64 `json:"epoch"`
	}
	if json.Unmarshal(raw, &input) != nil || input.Epoch <= 0 {
		return api.ToolResult{}, ErrInvalid
	}
	fingerprintBytes, err := json.Marshal(struct {
		Tool      string
		Mediation api.Mediation
		Args      json.RawMessage
	}{call.Tool, call.Mediation, raw})
	if err != nil {
		return api.ToolResult{}, err
	}
	hash := sha256.Sum256(fingerprintBytes)
	fingerprint := hex.EncodeToString(hash[:])
	var result api.ToolResult
	err = e.Ledger.transaction(ctx, func(c *sql.Conn) error {
		var id string
		err := c.QueryRowContext(ctx, `SELECT id FROM operations WHERE session_uid=?`, scope.SessionUID).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		op, err := readOperation(ctx, c, id)
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
		if op.State == "uncertain" || root.State == "uncertain" || op.Epoch != input.Epoch || root.Epoch != input.Epoch {
			return ErrHeld
		}
		if op.Team != root.Team || op.PackageDigest != root.PackageDigest {
			return ErrInvalid
		}
		var prior string
		var cached []byte
		err = c.QueryRowContext(ctx, `SELECT fingerprint,result FROM tool_results WHERE uid=? AND key=?`, scope.SessionUID, call.IdempotencyKey).Scan(&prior, &cached)
		if err == nil {
			if prior != fingerprint {
				return ErrConflict
			}
			if json.Unmarshal(cached, &result) != nil {
				return ErrForeign
			}
			result.ID = call.ID
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		result = api.ToolResult{ID: call.ID}
		switch call.Tool {
		case "dispatch_member":
			var args struct {
				Epoch  int64  `json:"epoch"`
				Member string `json:"member"`
				Task   string `json:"task"`
			}
			if arguments(raw, &args, "epoch member task") != nil || op.Kind != "lead" || args.Member != "member" || args.Task == "" || len(args.Task) > 4096 || !utf8.ValidString(args.Task) {
				return ErrInvalid
			}
			tuple, _ := json.Marshal([]string{scope.SessionUID, call.IdempotencyKey})
			childHash := sha256.Sum256(tuple)
			payload, _ := json.Marshal(map[string]string{"task": args.Task})
			child, err := admit(ctx, c, Operation{ID: "dispatch-" + hex.EncodeToString(childHash[:]), Kind: "dispatch", ParentID: root.ID, Team: root.Team, PackageDigest: root.PackageDigest, Member: "member", Epoch: root.Epoch, Payload: payload})
			if err != nil {
				return err
			}
			result.Output = map[string]any{"handle": child.ID}
		case "publish", "checkpoint":
			var args struct {
				Epoch int64  `json:"epoch"`
				Text  string `json:"text,omitempty"`
			}
			fields := "epoch"
			if call.Tool == "publish" {
				fields += " text"
			}
			if arguments(raw, &args, fields) != nil {
				return ErrInvalid
			}
			if call.Tool == "publish" {
				if op.Kind != "dispatch" || args.Text == "" || len(args.Text) > 4096 || !utf8.ValidString(args.Text) {
					return ErrInvalid
				}
				if _, err = c.ExecContext(ctx, `INSERT INTO effects VALUES(?,?,?)`, scope.SessionUID, call.IdempotencyKey, raw); err != nil {
					return err
				}
				result.Output = map[string]any{"simulated": true, "text": args.Text}
			} else {
				if op.Kind != "lead" || args.Text != "" {
					return ErrInvalid
				}
				result.Output = map[string]any{"checkpoint": true}
			}
		case "read_context":
			var args struct {
				Epoch int64  `json:"epoch"`
				Team  string `json:"team"`
				Key   string `json:"key"`
			}
			if arguments(raw, &args, "epoch team key") != nil || args.Team != root.Team || !identity(args.Key) {
				return ErrInvalid
			}
			var value string
			if err = c.QueryRowContext(ctx, `SELECT value FROM context WHERE root=? AND key=?`, root.ID, args.Key).Scan(&value); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return ErrNotFound
				}
				return err
			}
			result.Output = map[string]any{"text": value}
		default:
			return ErrInvalid
		}
		stored, err := json.Marshal(result)
		if err != nil {
			return err
		}
		if _, err = c.ExecContext(ctx, `INSERT INTO tool_results VALUES(?,?,?,?)`, scope.SessionUID, call.IdempotencyKey, fingerprint, stored); err != nil {
			return err
		}
		return event(ctx, c, "tool-committed", op.ID)
	})
	if err != nil {
		return api.ToolResult{}, err
	}
	return result, nil
}
