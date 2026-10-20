package sessionfixture

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/gowebpki/jcs"
)

type realAttempt struct {
	AttemptID       int     `json:"attemptId"`
	Time            string  `json:"time"`
	FinishedAt      *string `json:"finishedAt"`
	Outcome         string  `json:"outcome"`
	InputTokens     *int64  `json:"inputTokens"`
	OutputTokens    *int64  `json:"outputTokens"`
	ReasoningTokens *int64  `json:"reasoningTokens"`
}
type ledgerRow struct {
	ID              int     `json:"id"`
	RequestHash     string  `json:"request_hash"`
	StartedAt       string  `json:"started_at"`
	FinishedAt      *string `json:"finished_at"`
	Outcome         string  `json:"outcome"`
	InputTokens     *int64  `json:"input_tokens"`
	OutputTokens    *int64  `json:"output_tokens"`
	ReasoningTokens *int64  `json:"reasoning_tokens"`
}

// Read the host-owned schema without creating, migrating, repairing, or updating
// it. A single read transaction binds the budget and all attempts to one snapshot.
// The digest is SHA-256(JCS({budget: snapshot TEXT, attempts: full ordered rows})).
// Keeping snapshot as a string also binds its exact policy serialization.
func readRealLedger(path string) ([]realAttempt, string, error) {
	if err := existingPrivateDirectory(filepath.Dir(path)); err != nil {
		return nil, "", err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, "", err
	}
	info, err := f.Stat()
	f.Close()
	if err != nil {
		return nil, "", err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !ok || int(st.Uid) != os.Getuid() || info.Size() > 8<<20 {
		return nil, "", errors.New("bounded owned regular mode 0600 real ledger required")
	}
	db, err := readOnlyDB(path)
	if err != nil {
		return nil, "", err
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback()
	var budget string
	var n int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM model_budget`).Scan(&n); err != nil {
		return nil, "", err
	}
	if n != 1 {
		return nil, "", errors.New("real ledger requires one budget snapshot")
	}
	if err = tx.QueryRowContext(ctx, `SELECT snapshot FROM model_budget WHERE id=1`).Scan(&budget); err != nil {
		return nil, "", err
	}
	if len(budget) == 0 || len(budget) > 65536 || !json.Valid([]byte(budget)) {
		return nil, "", errors.New("invalid bounded budget snapshot")
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,request_hash,started_at,finished_at,outcome,input_tokens,output_tokens,reasoning_tokens FROM model_attempts ORDER BY id LIMIT 3`)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	attempts := []realAttempt{}
	fullRows := []ledgerRow{}
	for rows.Next() {
		var r ledgerRow
		if err = rows.Scan(&r.ID, &r.RequestHash, &r.StartedAt, &r.FinishedAt, &r.Outcome, &r.InputTokens, &r.OutputTokens, &r.ReasoningTokens); err != nil {
			return nil, "", err
		}
		if len(fullRows) >= 2 || r.ID != len(fullRows)+1 || !lowerHexDigest(r.RequestHash) {
			return nil, "", errors.New("invalid real ledger attempt identity or max-two bound")
		}
		if _, err = time.Parse(time.RFC3339Nano, r.StartedAt); err != nil {
			return nil, "", errors.New("invalid real ledger start time")
		}
		if r.FinishedAt != nil {
			if _, err = time.Parse(time.RFC3339Nano, *r.FinishedAt); err != nil {
				return nil, "", errors.New("invalid real ledger finish time")
			}
		}
		switch r.Outcome {
		case "reserved", "dispatching", "succeeded", "failed", "unknown":
		default:
			return nil, "", errors.New("invalid real ledger outcome")
		}
		for _, tokens := range []*int64{r.InputTokens, r.OutputTokens, r.ReasoningTokens} {
			if tokens != nil && (*tokens < 0 || *tokens > 1<<31) {
				return nil, "", errors.New("invalid real ledger token usage")
			}
		}
		if r.Outcome == "succeeded" && (r.FinishedAt == nil || r.InputTokens == nil || r.OutputTokens == nil || *r.InputTokens > 8192 || *r.OutputTokens > 4096 || (r.ReasoningTokens != nil && *r.ReasoningTokens > *r.OutputTokens)) {
			return nil, "", errors.New("successful real ledger attempt lacks bounded complete usage")
		}
		fullRows = append(fullRows, r)
		attempts = append(attempts, realAttempt{r.ID, r.StartedAt, r.FinishedAt, r.Outcome, r.InputTokens, r.OutputTokens, r.ReasoningTokens})
	}
	if err = rows.Err(); err != nil {
		return nil, "", err
	}
	raw, err := json.Marshal(struct {
		Budget   string      `json:"budget"`
		Attempts []ledgerRow `json:"attempts"`
	}{budget, fullRows})
	if err != nil {
		return nil, "", err
	}
	canonical, err := jcs.Transform(raw)
	if err != nil {
		return nil, "", err
	}
	return attempts, digestBytes(canonical), nil
}
func lowerHexDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func encodeEvidence(out io.Writer, ev fixtureEvidence, scenario string) error {
	if scenario != "v2" {
		return json.NewEncoder(out).Encode(ev)
	}
	return json.NewEncoder(out).Encode(struct {
		FakeModelCalls   int              `json:"fakeModelCalls"`
		RealModelCalls   *int             `json:"realModelCalls"`
		RealLedgerDigest string           `json:"realLedgerDigest"`
		RealAttempts     []realAttempt    `json:"realAttempts"`
		Artifacts        []artifactDigest `json:"artifacts"`
		PublicationCount int              `json:"publicationCount"`
		ReceiptCount     int              `json:"receiptCount"`
	}{ev.FakeModelCalls, ev.RealModelCalls, ev.RealLedgerDigest, ev.RealAttempts, ev.Artifacts, ev.PublicationCount, ev.ReceiptCount})
}
