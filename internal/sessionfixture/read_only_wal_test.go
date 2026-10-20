package sessionfixture

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// The error chain remains inspectable; only CANTOPEN receives conditional WAL
// guidance, not every SQLite failure and not errors that merely mention WAL.
func TestReadOnlyReplayErrorClassification(t *testing.T) {
	for _, query := range []string{"SELECT 1", "SELECT * FROM missing_table"} {
		dsn := filepath.Join(privateTempDir(t), "missing.db")
		if query == "SELECT 1" {
			dsn = "file:" + dsn + "?mode=ro"
		}
		db, err := sql.Open("sqlite", dsn)
		if err != nil {
			t.Fatal(err)
		}
		_, cause := db.Exec(query)
		db.Close()
		if cause == nil {
			t.Fatal("expected a real SQLite error")
		}
		got := explainReadOnlyReplayError(cause)
		var sqliteErr *sqlite.Error
		if !errors.As(got, &sqliteErr) || !errors.Is(got, cause) {
			t.Fatalf("SQLite cause lost: %v", got)
		}
		if sqliteErr.Code()&0xff == sqlite3.SQLITE_CANTOPEN {
			for _, want := range []string{"read-only", "WAL", "sidecar", "scratch"} {
				if !strings.Contains(got.Error(), want) {
					t.Errorf("missing %q guidance: %v", want, got)
				}
			}
		} else if got != cause {
			t.Fatalf("unrelated SQLite failure changed: %v", got)
		}
	}
	for _, cause := range []error{nil, errors.New("WAL access denied")} {
		if got := explainReadOnlyReplayError(cause); got != cause {
			t.Fatalf("non-SQLite error changed: %v", got)
		}
	}
}

// Run explicitly with FIXTURE_DOCKER_IMAGE=<pinned fixture> to exercise the real
// CLI on a genuinely read-only mount (chmod is not equivalent and fails as root).
func TestReadOnlyWALReplayDocker(t *testing.T) {
	image := os.Getenv("FIXTURE_DOCKER_IMAGE")
	if image == "" {
		t.Skip("set FIXTURE_DOCKER_IMAGE to run the read-only Docker regression")
	}
	if !strings.HasPrefix(image, "ghcr.io/azure/aks-durable-agents/session-fixture@sha256:") {
		t.Fatal("immutable public fixture runtime image required")
	}
	data := privateTempDir(t)
	if err := initData(data, "/run/reference/publish.sock"); err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(data, "journal.db")
	db, err := sql.Open("sqlite", journal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("PRAGMA journal_mode=WAL; CREATE TABLE sessions(session TEXT)"); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil { // stopped store: WAL header, absent sidecars
		t.Fatal(err)
	}
	before, err := journalBytes(journal)
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(privateTempDir(t), "session-fixture")
	build := exec.CommandContext(t.Context(), "go", "build", "-o", binary, "./cmd/session-fixture")
	build.Dir = "../.."
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build current fixture: %s: %v", out, err)
	}
	cmd := exec.CommandContext(t.Context(), "docker", "run", "--rm", "--network=none", "--read-only", "--user", strconv.Itoa(os.Getuid())+":"+strconv.Itoa(os.Getgid()),
		"--mount", "type=bind,src="+data+",dst=/data,readonly", "--mount", "type=bind,src="+binary+",dst=/fixture,readonly", "--entrypoint", "/fixture", image,
		"verify-replay", "--journal", "/data/journal.db", "--instructions", "/data/instructions.txt", "--session", "s")
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	var exit *exec.ExitError
	if err = cmd.Run(); !errors.As(err, &exit) || exit.ExitCode() != 1 {
		t.Fatalf("expected CLI refusal: %s %s %v", out.Bytes(), stderr.Bytes(), err)
	}
	var proof replayProof
	if err = json.Unmarshal(out.Bytes(), &proof); err != nil || proof.Completed || proof.ProviderCalls != 0 || proof.ExecutorCalls != 0 {
		t.Fatalf("failure proof: %s: %v", out.Bytes(), err)
	}
	if !strings.Contains(proof.Error, "sidecar") || !strings.Contains(proof.Error, "(14)") || !strings.Contains(stderr.String(), proof.Error) {
		t.Fatalf("CLI/JSON lost actionable SQLite error: %s %s", out.Bytes(), stderr.Bytes())
	}
	after, err := journalBytes(journal)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("failed inspection changed journal/WAL: %v", err)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, err = os.Lstat(journal + suffix); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed inspection created a sidecar: %v", err)
		}
	}
}
