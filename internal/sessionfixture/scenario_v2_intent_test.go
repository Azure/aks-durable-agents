package sessionfixture

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Break caught: lost-Create reconciliation guesses an ambiguous UID or mutates the journal.
func TestResolveIntentReadOnlyUniqueMatch(t *testing.T) {
	const intent = "release-123e4567-e89b-42d3-a456-426614174000"
	for _, count := range []int{0, 1, 2} {
		t.Run(string(rune('0'+count)), func(t *testing.T) {
			path := filepath.Join(privateTempDir(t), "journal.db")
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = db.Exec(`CREATE TABLE sessions(session TEXT PRIMARY KEY,name TEXT)`); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < count; i++ {
				if _, err = db.Exec(`INSERT INTO sessions VALUES(?,?)`, string(rune('a'+i)), intent); err != nil {
					t.Fatal(err)
				}
			}
			if _, err = db.Exec(`INSERT INTO sessions VALUES('other','release-unrelated')`); err != nil {
				t.Fatal(err)
			}
			db.Close()
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			err = runCLI(t.Context(), []string{"resolve-intent", "--scenario", "v2", "--journal", path, "--intent", intent}, &out, &out)
			if count == 1 {
				if err != nil {
					t.Fatal(err)
				}
				var got map[string]string
				if err = json.Unmarshal(out.Bytes(), &got); err != nil {
					t.Fatal(err)
				}
				if len(got) != 2 || got["session_uid"] != "a" || got["intent"] != intent {
					t.Fatalf("%v", got)
				}
			} else if err == nil || !strings.Contains(err.Error(), map[int]string{0: "unresolved", 2: "ambiguous"}[count]) {
				t.Fatalf("count=%d err=%v", count, err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("resolution mutated journal")
			}
		})
	}
}
func TestResolveIntentRejectsMissingJournal(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "journal.db")
	if err := runCLI(t.Context(), []string{"resolve-intent", "--scenario", "v2", "--journal", path, "--intent", "release-123e4567-e89b-42d3-a456-426614174000"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("missing journal accepted")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("resolution created journal")
	}
}
