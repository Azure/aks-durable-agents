package targetversions

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// These fixtures are unmodified outputs of the real decisionledger.Service,
// not receipts invented by the consumer. The producer pin is in testdata.
// This tests the copied evidence domain, not retained-subject authentication.
func TestDecisionLedgerRecordConformance(t *testing.T) {
	paths, err := filepath.Glob("testdata/decision-ledger/*.json")
	if err != nil || len(paths) != 6 {
		t.Fatalf("producer fixtures: %v (%d)", err, len(paths))
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var record DecisionRecord
			decoder := json.NewDecoder(bytes.NewReader(raw))
			decoder.DisallowUnknownFields()
			if err = decoder.Decode(&record); err != nil {
				t.Fatal(err)
			}
			original := clone(record)
			s, _ := newStore(t)
			committed(t, s, begin(t, s, request(register(t, s, "agent"), "bootstrap")))
			r := activeRequest(t, s, "agent", record.Request.Key)
			r.Subject = record.Request.Subject
			r.DecisionRecord = record
			operation, err := s.Begin(ctx, r)
			if err != nil {
				t.Fatal("real producer record rejected", err)
			}
			operation = prepared(t, s, operation)
			operation = reserved(t, s, operation)
			operation = retired(t, s, operation)
			operation, err = s.Commit(ctx, step(operation), receipt(s, operation, "commit"))
			if err != nil {
				t.Fatal(err)
			}
			if !same(operation.Request.DecisionRecord, original) || !same(operation.Reserved.DecisionRecord, original) {
				t.Fatal("historical decision evidence rewritten")
			}
		})
	}
}
