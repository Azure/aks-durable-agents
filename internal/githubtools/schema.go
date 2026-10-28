package githubtools

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
)

var schemaV2 = []struct{ name, sql string }{
	{"metadata", `CREATE TABLE metadata(id INTEGER PRIMARY KEY CHECK(id=1),schema_version INTEGER NOT NULL,store_id TEXT NOT NULL,lineage TEXT NOT NULL,binding TEXT NOT NULL)`},
	{"approvals", `CREATE TABLE approvals(id TEXT PRIMARY KEY,slot TEXT NOT NULL,session_uid TEXT NOT NULL,request_key TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('active','abandoned')),record TEXT NOT NULL)`},
	{"approval_history_slot", `CREATE INDEX approval_history_slot ON approvals(slot)`},
	{"approval_history_key", `CREATE INDEX approval_history_key ON approvals(session_uid,request_key)`},
	{"one_active_slot", `CREATE UNIQUE INDEX one_active_slot ON approvals(slot) WHERE state='active'`},
	{"one_active_key", `CREATE UNIQUE INDEX one_active_key ON approvals(session_uid,request_key) WHERE state='active'`},
	{"intents", `CREATE TABLE intents(slot TEXT PRIMARY KEY,approval_id TEXT NOT NULL UNIQUE,session_uid TEXT NOT NULL,request_key TEXT NOT NULL,operation_digest TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('unknown','succeeded','failed')),record TEXT NOT NULL,UNIQUE(session_uid,request_key),FOREIGN KEY(approval_id) REFERENCES approvals(id))`},
	{"one_unknown_session", `CREATE UNIQUE INDEX one_unknown_session ON intents(session_uid) WHERE state='unknown'`},
	{"one_unknown_operation", `CREATE UNIQUE INDEX one_unknown_operation ON intents(operation_digest) WHERE state='unknown'`},
	{"reads", `CREATE TABLE reads(slot TEXT PRIMARY KEY,session_uid TEXT NOT NULL,request_key TEXT NOT NULL,record TEXT NOT NULL,UNIQUE(session_uid,request_key))`},
}

func createSchema(ctx context.Context, c *sql.Conn) error {
	if _, err := c.ExecContext(ctx, "PRAGMA user_version=2"); err != nil {
		return ErrUnavailable
	}
	for _, o := range schemaV2 {
		if _, err := c.ExecContext(ctx, o.sql); err != nil {
			return ErrUnavailable
		}
	}
	return nil
}
func encode(v any) string            { b, _ := json.Marshal(v); return string(b) }
func decode(raw string, v any) error { return decodeBound(raw, v, 65536) }
func decodeBound(raw string, v any, limit int) error {
	if len(raw) > limit {
		return ErrUnavailable
	}
	d := json.NewDecoder(bytes.NewBufferString(raw))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF || encode(v) != raw {
		return ErrUnavailable
	}
	return nil
}
func intentState(i Intent) string {
	if i.Outcome == nil {
		return "unknown"
	}
	return i.Outcome.Status
}

func (s *Store) verify() error {
	var version, userVersion int
	var id, lineage, binding, integrity string
	if s.db.QueryRow("PRAGMA user_version").Scan(&userVersion) != nil || userVersion != 2 || s.db.QueryRow("SELECT schema_version,store_id,lineage,binding FROM metadata WHERE id=1").Scan(&version, &id, &lineage, &binding) != nil || version != 2 || id != s.id || lineage != s.lineage || binding != s.binding || s.db.QueryRow("PRAGMA integrity_check").Scan(&integrity) != nil || integrity != "ok" {
		return ErrUnavailable
	}
	expected := make(map[string]string, len(schemaV2))
	for _, o := range schemaV2 {
		expected[o.name] = o.sql
	}
	rows, err := s.db.Query("SELECT name,sql FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*'")
	if err != nil {
		return ErrUnavailable
	}
	for rows.Next() {
		var name, definition string
		if rows.Scan(&name, &definition) != nil || expected[name] != definition {
			rows.Close()
			return ErrUnavailable
		}
		delete(expected, name)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return ErrUnavailable
	}
	rows.Close()
	if len(expected) != 0 {
		return ErrUnavailable
	}
	approvals := make(map[string]ApprovalRecord)
	calls := make(map[string]Call)
	rows, err = s.db.Query("SELECT id,slot,session_uid,request_key,state,record FROM approvals")
	if err != nil {
		return ErrUnavailable
	}
	for rows.Next() {
		var id, slot, uid, key, state, raw string
		var r ApprovalRecord
		if rows.Scan(&id, &slot, &uid, &key, &state, &raw) != nil || decode(raw, &r) != nil || !r.valid() || r.ID != id || r.Call.slot() != slot || r.Call.SessionUID != uid || r.Call.Key != key || (state == "abandoned") != (!r.AbandonedAt.IsZero()) {
			rows.Close()
			return ErrUnavailable
		}
		if old, ok := calls[slot]; ok && old != r.Call {
			rows.Close()
			return ErrUnavailable
		}
		calls[slot] = r.Call
		approvals[id] = r
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return ErrUnavailable
	}
	rows.Close()
	rows, err = s.db.Query("SELECT slot,approval_id,session_uid,request_key,operation_digest,state,record FROM intents")
	if err != nil {
		return ErrUnavailable
	}
	defer rows.Close()
	for rows.Next() {
		var slot, id, uid, key, operation, state, raw string
		var i Intent
		if rows.Scan(&slot, &id, &uid, &key, &operation, &state, &raw) != nil || decode(raw, &i) != nil || !i.valid(approvals[id]) || i.ApprovalID != id || i.Call.slot() != slot || i.Call.SessionUID != uid || i.Call.Key != key || i.Call.OperationDigest != operation || intentState(i) != state {
			return ErrUnavailable
		}
	}
	if rows.Err() != nil {
		return ErrUnavailable
	}
	rows.Close()
	return s.verifyReads()
}
