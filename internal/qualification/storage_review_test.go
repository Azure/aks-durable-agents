package qualification

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestOpenRefusesRetainedWALSidecars(t *testing.T) {
	for _, name := range []string{"records.db-wal", "records.db-shm"} {
		for _, data := range []string{"", "retained recovery bytes"} {
			t.Run(name+"/"+data, func(t *testing.T) {
				s, dir := testStore(t)
				lineage := s.Lineage()
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
				before := recoverySnapshot(t, dir)
				opened, err := Open(dir, lineage)
				if opened != nil {
					opened.Close()
				}
				if !errors.Is(err, ErrIntegrity) {
					t.Errorf("retained sidecar accepted: %v", err)
				}
				if !reflect.DeepEqual(before, recoverySnapshot(t, dir)) {
					t.Fatal("refusal changed recovery set")
				}
			})
		}
	}
}
