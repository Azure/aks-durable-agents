package decisionledger

import (
	"context"
	"database/sql"
)

// Schema 2 requires immutable proposer identity on suite snapshots. Schema 1
// cannot be adopted or backfilled with the approver as the proposal creator.
// Keep creation and reopen checks on the same DDL; unknown layouts are refused,
// never repaired or implicitly adopted as a compatible store.
var schemaV2 = []struct{ name, sql string }{
	{"metadata", `CREATE TABLE metadata(id INTEGER PRIMARY KEY CHECK(id=1),schema_version INTEGER NOT NULL,store_id TEXT NOT NULL,lineage TEXT NOT NULL)`},
	{"subjects", `CREATE TABLE subjects(workspace TEXT NOT NULL,kind TEXT NOT NULL,subject_id TEXT NOT NULL,generation INTEGER NOT NULL,digest TEXT NOT NULL,snapshot TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('open','decided','superseded')),PRIMARY KEY(workspace,kind,subject_id,generation))`},
	{"one_open", `CREATE UNIQUE INDEX one_open ON subjects(workspace,kind,subject_id) WHERE state='open'`},
	{"requests", `CREATE TABLE requests(workspace TEXT NOT NULL,issuer TEXT NOT NULL,oid TEXT NOT NULL,request_key TEXT NOT NULL,kind TEXT NOT NULL,subject_id TEXT NOT NULL,generation INTEGER NOT NULL,record_id TEXT NOT NULL UNIQUE,outcome TEXT NOT NULL CHECK(outcome IN ('recorded','refused')),record TEXT NOT NULL,PRIMARY KEY(workspace,issuer,oid,request_key),FOREIGN KEY(workspace,kind,subject_id,generation) REFERENCES subjects(workspace,kind,subject_id,generation))`},
	{"one_decision", `CREATE UNIQUE INDEX one_decision ON requests(workspace,kind,subject_id,generation) WHERE outcome='recorded'`},
}

func createSchema(ctx context.Context, c *sql.Conn) error {
	if _, err := c.ExecContext(ctx, "PRAGMA user_version=2"); err != nil {
		return ErrUnavailable
	}
	for _, object := range schemaV2 {
		if _, err := c.ExecContext(ctx, object.sql); err != nil {
			return ErrUnavailable
		}
	}
	return nil
}
func (s *Store) verifySchema() error {
	expected := make(map[string]string, len(schemaV2))
	for _, object := range schemaV2 {
		expected[object.name] = object.sql
	}
	rows, err := s.db.Query("SELECT name,sql FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*'")
	if err != nil {
		return ErrUnavailable
	}
	defer rows.Close()
	for rows.Next() {
		var name, definition string
		if rows.Scan(&name, &definition) != nil || expected[name] != definition {
			return ErrUnavailable
		}
		delete(expected, name)
	}
	if rows.Err() != nil || len(expected) != 0 {
		return ErrUnavailable
	}
	return nil
}
