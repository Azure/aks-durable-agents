package qualification

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestNullProjectionAfterOpenIsIntegrity(t *testing.T) {
	for _, column := range []string{"workspace", "id"} {
		t.Run(column, func(t *testing.T) {
			s, _ := testStore(t)
			r := admit(t, s)
			if _, err := s.db.Exec("ALTER TABLE records RENAME TO original; CREATE TABLE records(id,workspace,target,request_key,body); INSERT INTO records SELECT * FROM original; UPDATE records SET " + column + "=NULL"); err != nil {
				t.Fatal(err)
			}
			var err error
			if column == "workspace" {
				_, err = s.Read(context.Background(), r.ID)
			} else {
				_, err = s.Admit(context.Background(), r.Request)
			}
			if !errors.Is(err, ErrIntegrity) || errors.Is(err, ErrUnavailable) {
				t.Fatalf("NULL projection misclassified: %v", err)
			}
		})
	}
}

func TestOpenRefusesMalformedMetadata(t *testing.T) {
	for _, statement := range []string{"DELETE FROM metadata", "UPDATE metadata SET version='foreign'"} {
		t.Run(statement, func(t *testing.T) {
			s, dir := testStore(t)
			lineage := s.Lineage()
			if _, err := s.db.Exec(statement); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			before := recoverySnapshot(t, dir)
			opened, err := Open(dir, lineage)
			if opened != nil {
				opened.Close()
			}
			if !errors.Is(err, ErrIntegrity) || errors.Is(err, ErrUnavailable) {
				t.Fatalf("malformed metadata misclassified: %v", err)
			}
			if !reflect.DeepEqual(before, recoverySnapshot(t, dir)) {
				t.Fatal("refusal modified metadata/recovery set")
			}
		})
	}
}

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
