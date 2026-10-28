package modeltransport

import (
	"context"
	"database/sql"
	"slices"
	"strings"
)

const budgetSchema = `CREATE TABLE model_budget(id INTEGER PRIMARY KEY CHECK(id=1),snapshot TEXT NOT NULL)`
const plannedAttemptsSchema = `CREATE TABLE model_attempts(id INTEGER PRIMARY KEY,call_slot TEXT NOT NULL UNIQUE,request_hash TEXT NOT NULL,started_at TEXT NOT NULL,finished_at TEXT,outcome TEXT NOT NULL,input_tokens INTEGER,output_tokens INTEGER,reasoning_tokens INTEGER)`

func validCallSlots(slots []string) bool {
	// This profile changes identity only, not the existing three-attempt budget.
	if len(slots) != 3 {
		return false
	}
	seen := make(map[string]bool, len(slots))
	for _, slot := range slots {
		if len(slot) == 0 || len(slot) > 128 || seen[slot] {
			return false
		}
		for _, c := range slot {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("_-.:/", c)) {
				return false
			}
		}
		seen[slot] = true
	}
	return true
}

func (p *Policy) acceptsCallSlot(slot string) bool {
	if p.config.Version == 3 {
		return slices.Contains(p.config.PlannedCallSlots, slot)
	}
	return slot == ""
}

// A v3 ledger is a distinct format. Never adopt a similar table that lost its
// uniqueness constraint or gained an effectful trigger. Legacy tables are unchanged.
func validatePlannedLedger(conn *sql.Conn, slots []string) error {
	ctx := context.Background()
	rows, err := conn.QueryContext(ctx, "SELECT type,name,sql FROM sqlite_schema ORDER BY name")
	if err != nil {
		return ledgerError()
	}
	expected := map[string]string{"model_budget": budgetSchema, "model_attempts": plannedAttemptsSchema}
	indexSeen := false
	for rows.Next() {
		var kind, name string
		var stmt sql.NullString
		if err = rows.Scan(&kind, &name, &stmt); err != nil {
			rows.Close()
			return ledgerError()
		}
		if kind == "index" && name == "sqlite_autoindex_model_attempts_1" && !stmt.Valid {
			if indexSeen {
				rows.Close()
				return ledgerError()
			}
			indexSeen = true
			continue
		}
		want, ok := expected[name]
		if !ok || kind != "table" || !stmt.Valid || stmt.String != want {
			rows.Close()
			return ledgerError()
		}
		delete(expected, name)
	}
	err = rows.Err()
	rows.Close()
	if err != nil || len(expected) != 0 || !indexSeen {
		return ledgerError()
	}
	rows, err = conn.QueryContext(ctx, "SELECT call_slot,request_hash,typeof(call_slot),typeof(request_hash) FROM model_attempts")
	if err != nil {
		return ledgerError()
	}
	defer rows.Close()
	for rows.Next() {
		var slot, hash, slotType, hashType string
		// Scanning BLOBs into strings erases SQLite's distinct uniqueness domain.
		if err = rows.Scan(&slot, &hash, &slotType, &hashType); err != nil || slotType != "text" || hashType != "text" || !slices.Contains(slots, slot) || len(hash) != 64 {
			return ledgerError()
		}
		for _, c := range hash {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return ledgerError()
			}
		}
	}
	if rows.Err() != nil {
		return ledgerError()
	}
	return nil
}
