package targetversions

import (
	"errors"
	"testing"
)

// Non-STRICT SQLite accepts these values without a physical/FK error. They are
// retained-state mismatches, not operational failures to retry on this handle.
func TestStoredIntegerTypesAreIntegrityFailures(t *testing.T) {
	for _, tc := range []struct {
		name, statement string
		value           any
	}{
		{"event-negative", "UPDATE events SET sequence=?", int64(-1)},
		{"event-text", "UPDATE events SET sequence=?", "x"},
		{"event-real", "UPDATE events SET sequence=?", 1.5},
		{"schema-text", "UPDATE metadata SET schema_version=?", "x"},
		{"schema-real", "UPDATE metadata SET schema_version=?", 1.5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, path := newStore(t)
			register(t, s, "agent")
			if _, err := s.db.Exec(tc.statement, tc.value); err != nil {
				t.Fatal(err)
			}
			if err := s.basicVerify(ctx, s.db); err != nil {
				t.Fatal("fixture must retain physical integrity", err)
			}
			if err := s.Verify(ctx); !errors.Is(err, ErrIntegrity) {
				t.Errorf("invalid stored integer: %v", err)
			}
			if !s.bad.Load() {
				t.Error("detected integer mismatch did not latch")
			}
			if _, err := s.RegisterTarget(ctx, "must-not-exist"); !errors.Is(err, ErrIntegrity) {
				t.Errorf("writer escaped mismatch latch: %v", err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := Open(path, s.ID)
			if reopened != nil {
				reopened.Close()
			}
			if !errors.Is(err, ErrIntegrity) {
				t.Errorf("invalid stored integer Open: %v", err)
			}
		})
	}
}
