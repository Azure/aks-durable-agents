package democli

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func completedDemo(t *testing.T) *demo {
	t.Helper()
	d := newDemo(t)
	d.mustRPC("park")
	d.mustRPC("approve")
	d.mustRPC("continue")
	d.stopWriters()
	return d
}

func TestSealPreservesLogicalStateAndRemovesSidecars(t *testing.T) {
	d := completedDemo(t)
	before := d.evidence()
	completed, err := readState(d.data, "completed.json")
	if err != nil {
		t.Fatal(err)
	}
	got := mustCLI(t, "seal", "--data", d.data)
	if got["sealed"] != true || got["session"] != completed.Session {
		t.Fatalf("seal output: %v", got)
	}
	if !reflect.DeepEqual(before, d.evidence()) {
		t.Fatal("sealing changed model or effect inventories")
	}
	sealed, err := readState(d.data, "sealed.json")
	if err != nil || !reflect.DeepEqual(sealed, completed) {
		t.Fatalf("sealed head differs: %+v %v", sealed, err)
	}
	if n, err := meter(d.data); err != nil || n != 1 {
		t.Fatalf("HTTP inventory changed: %d %v", n, err)
	}
	for _, name := range []string{"journal.db", "publications.db"} {
		for _, suffix := range []string{"-wal", "-shm"} {
			if _, err := os.Lstat(filepath.Join(d.data, name+suffix)); !os.IsNotExist(err) {
				t.Fatalf("sidecar remains: %s%s (%v)", name, suffix, err)
			}
		}
	}
	if _, err := cli(t, "seal", "--data", d.data); err == nil {
		t.Fatal("second seal was accepted")
	}
	if proof := mustCLI(t, "verify", "--data", d.data); proof["completed"] != true {
		t.Fatalf("first replay failed: %v", proof)
	}
}

func TestSealRefusesMissingDatabaseWithoutCreatingIt(t *testing.T) {
	d := completedDemo(t)
	missing := filepath.Join(d.data, "publications.db")
	if err := os.Remove(missing); err != nil {
		t.Fatal(err)
	}
	if _, err := cli(t, "seal", "--data", d.data); err == nil || !strings.Contains(err.Error(), "no such file") {
		t.Fatalf("missing-store refusal: %v", err)
	}
	if _, err := os.Lstat(missing); !os.IsNotExist(err) {
		t.Fatalf("missing DB was created: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(d.data, "sealed.json")); !os.IsNotExist(err) {
		t.Fatal("refused seal wrote a success marker")
	}
}

func TestSealRefusesBusyStoreWithoutWaitingOrRetrying(t *testing.T) {
	d := completedDemo(t)
	db, err := sql.Open("sqlite", "file:"+filepath.Join(d.data, "journal.db")+"?mode=rw")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	conn, err := db.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(t.Context(), "BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	defer conn.ExecContext(context.Background(), "ROLLBACK")
	start := time.Now()
	_, err = cli(t, "seal", "--data", d.data)
	if err == nil || (!strings.Contains(err.Error(), "locked") && !strings.Contains(err.Error(), "busy")) {
		t.Fatalf("busy store was not refused: %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("busy seal waited instead of failing immediately")
	}
	if _, err := os.Lstat(filepath.Join(d.data, "sealed.json")); !os.IsNotExist(err) {
		t.Fatal("busy seal wrote a success marker")
	}
}

func TestCheckpointRefusesNonDeleteResult(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	conn, err := db.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// A real in-memory database reports "memory", without an SQL error.
	if err := checkpointDelete(t.Context(), conn); err == nil || !strings.Contains(err.Error(), "delete") {
		t.Fatalf("non-delete result was accepted: %v", err)
	}
}

func TestSealRefusesChangedCompletedHead(t *testing.T) {
	d := completedDemo(t)
	d.rewrite("completed.json", func(v map[string]any) { v["headHash"] = strings.Repeat("0", 64) })
	if _, err := cli(t, "seal", "--data", d.data); err == nil {
		t.Fatal("seal accepted a different logical head")
	}
	if _, err := os.Lstat(filepath.Join(d.data, "sealed.json")); !os.IsNotExist(err) {
		t.Fatal("head mismatch wrote a success marker")
	}
}
