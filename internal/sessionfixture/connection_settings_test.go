package sessionfixture

import "testing"

func TestExecutorSettingsSurviveConnectionReplacement(t *testing.T) {
	ex, err := newExecutor(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer ex.close()
	// Force the initialized connection out of the pool. Every query below must
	// receive these settings on a newly opened connection, not just the first one.
	ex.db.SetMaxIdleConns(0)
	for _, tc := range []struct {
		name string
		want int
	}{{"foreign_keys", 1}, {"busy_timeout", 5000}, {"synchronous", 2}} {
		var got int
		if err := ex.db.QueryRow("PRAGMA " + tc.name).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Errorf("reopened connection %s=%d, want %d", tc.name, got, tc.want)
		}
	}
}
