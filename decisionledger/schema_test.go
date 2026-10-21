package decisionledger

import (
	"database/sql"
	"errors"
	"testing"
)

// Same version markers do not authorize a different table/index contract.
func TestSchemaDefinitionsRequired(t *testing.T) {
	for name, statement := range map[string]string{
		"decision index":            "DROP INDEX one_decision",
		"open index":                "DROP INDEX one_open",
		"unknown column":            "ALTER TABLE subjects ADD COLUMN unknown_future_field TEXT",
		"missing constraints":       "DROP TABLE requests; CREATE TABLE requests(workspace TEXT,issuer TEXT,oid TEXT,request_key TEXT,kind TEXT,subject_id TEXT,generation INTEGER,record_id TEXT,outcome TEXT,record TEXT)",
		"extra view":                "CREATE VIEW external_view AS SELECT workspace FROM subjects",
		"internal prefix lookalike": "CREATE TABLE sqliteX_external(id INTEGER)",
	} {
		t.Run(name, func(t *testing.T) {
			store := newTestStore(t)
			path, id := store.path, store.ID()
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = db.Exec(statement); err != nil {
				db.Close()
				t.Fatal(err)
			}
			if err = db.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := Open(path, id, "host-lineage")
			if reopened != nil {
				reopened.Close()
			}
			if !errors.Is(err, ErrUnavailable) {
				t.Fatalf("same-version structural drift accepted: %v", err)
			}
		})
	}
}
