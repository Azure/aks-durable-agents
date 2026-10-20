package sessionfixture

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"

	"github.com/agent-primitives/sessions/api"
	"github.com/agent-primitives/sessions/controller"
	_ "modernc.org/sqlite"
)

const maxDraftBytes = 32768

type executor struct {
	dir         string
	scenario    string
	db          *sql.DB
	afterCommit func() error
}
type publicationRow struct {
	Name string
	Raw  json.RawMessage
}

func privateParent(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return errors.New("absolute private directory required")
	}
	// Resolve the nearest existing ancestor before creating anything. Checking
	// only afterward could leave directories outside the allowlist via a symlink.
	ancestor := path
	for {
		_, err := os.Lstat(ancestor)
		if errors.Is(err, os.ErrNotExist) {
			ancestor = filepath.Dir(ancestor)
			continue
		}
		if err != nil {
			return err
		}
		real, err := filepath.EvalSymlinks(ancestor)
		if err != nil {
			return err
		}
		if real != ancestor {
			return errors.New("private directory ancestor must not contain symlinks")
		}
		break
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if real != path || !info.IsDir() || info.Mode().Perm() != 0700 || !ok || int(st.Uid) != os.Getuid() {
		return errors.New("directory must be owned, nonsymlink and mode 0700")
	}
	return nil
}
func privateFile(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("absolute private file required")
	}
	if err := privateParent(filepath.Dir(path)); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !ok || int(st.Uid) != os.Getuid() {
		return errors.New("file must be owned, regular and mode 0600")
	}
	return nil
}
func newExecutor(dir string) (*executor, error) {
	return openExecutor(filepath.Join(dir, "publications.db"))
}
func openExecutor(path string) (*executor, error) { return openExecutorScenario(path, "v1") }
func openExecutorScenario(path, scenario string) (*executor, error) {
	if err := validScenario(scenario); err != nil {
		return nil, err
	}
	if scenario == "v2" {
		if err := checkScenario(filepath.Dir(path), scenario); err != nil {
			return nil, err
		}
	} else if _, err := os.Lstat(filepath.Join(filepath.Dir(path), "scenario.json")); !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("v1 executor cannot consume marked scenario data")
	}
	if err := privateFile(path); err != nil {
		return nil, err
	}
	// Connection-local PRAGMAs must also apply if database/sql replaces a connection.
	pragmas := url.Values{"_pragma": {"busy_timeout(5000)", "synchronous(FULL)", "foreign_keys(1)", "journal_mode(WAL)"}}
	u := url.URL{Scheme: "file", Path: path, RawQuery: pragmas.Encode()}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	fail := func(err error) (*executor, error) { db.Close(); return nil, err }
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS publications (session_uid TEXT NOT NULL, key TEXT NOT NULL, artifact TEXT NOT NULL UNIQUE, body BLOB NOT NULL, PRIMARY KEY(session_uid,key))`,
		`CREATE TABLE IF NOT EXISTS receipts (session_uid TEXT NOT NULL, key TEXT NOT NULL, fingerprint TEXT NOT NULL, output BLOB NOT NULL, PRIMARY KEY(session_uid,key), FOREIGN KEY(session_uid,key) REFERENCES publications(session_uid,key))`,
	} {
		if _, err = db.Exec(q); err != nil {
			return fail(err)
		}
	}
	return &executor{dir: filepath.Dir(path), scenario: scenario, db: db}, nil
}
func (e *executor) close() error { return e.db.Close() }
func toolScope(uid string) controller.ToolCallContext {
	return controller.ToolCallContext{SessionUID: uid}
}
func identity(s string, max int) bool {
	return s != "" && len(s) <= max && utf8.ValidString(s) && strings.TrimSpace(s) == s && strings.IndexFunc(s, unicode.IsControl) < 0
}
func validateTool(scope controller.ToolCallContext, c api.ToolCall) error {
	if !identity(scope.SessionUID, 256) || !identity(c.ID, 256) || !identity(c.IdempotencyKey, 512) || c.Mediation != api.MediationRequiresApproval {
		return errors.New("invalid tool identity or mediation")
	}
	draft, ok := c.Args["draft"].(string)
	if c.Tool != "publish_release_notes" || len(c.Args) != 2 || c.Args["destination"] != "release-notes-demo" || !ok || (draft != draftA && draft != draftB) {
		return errors.New("only frozen fictional drafts and fixed release-notes-demo destination are allowed")
	}
	return nil
}
func (e *executor) execute(ctx context.Context, scope controller.ToolCallContext, c api.ToolCall) (api.ToolResult, error) {
	if err := validateToolScenario(scope, c, e.scenario); err != nil {
		return api.ToolResult{}, err
	}
	// The fingerprint intentionally excludes correlation ID: a redrive returns the
	// original result under the current call ID while preserving tuple identity.
	raw, err := json.Marshal(struct {
		Tool string         `json:"tool"`
		Args map[string]any `json:"args"`
	}{c.Tool, c.Args})
	if err != nil {
		return api.ToolResult{}, err
	}
	hash := sha256.Sum256(raw)
	fingerprint := hex.EncodeToString(hash[:])
	conn, err := e.db.Conn(ctx)
	if err != nil {
		return api.ToolResult{}, err
	}
	defer conn.Close()
	if _, err = conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return api.ToolResult{}, err
	}
	defer conn.ExecContext(context.Background(), "ROLLBACK")
	var prior string
	var output []byte
	err = conn.QueryRowContext(ctx, "SELECT fingerprint,output FROM receipts WHERE session_uid=? AND key=?", scope.SessionUID, c.IdempotencyKey).Scan(&prior, &output)
	if err == nil {
		if prior != fingerprint {
			return api.ToolResult{}, errors.New("idempotency content conflict")
		}
		var out map[string]any
		if err = json.Unmarshal(output, &out); err != nil {
			return api.ToolResult{}, err
		}
		if _, err = conn.ExecContext(ctx, "COMMIT"); err != nil {
			return api.ToolResult{}, err
		}
		return api.ToolResult{ID: c.ID, Output: out}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return api.ToolResult{}, err
	}
	tuple, _ := json.Marshal([]string{scope.SessionUID, c.IdempotencyKey})
	id := sha256.Sum256(tuple)
	artifact := fmt.Sprintf("%x.json", id)
	out := map[string]any{"simulated": true, "artifact": artifact, "draft": c.Args["draft"], "destination": "release-notes-demo"}
	output, err = json.Marshal(out)
	if err != nil {
		return api.ToolResult{}, err
	}
	body, err := json.Marshal(struct {
		SessionUID string         `json:"session_uid"`
		Key        string         `json:"key"`
		Output     map[string]any `json:"output"`
	}{scope.SessionUID, c.IdempotencyKey, out})
	if err != nil {
		return api.ToolResult{}, err
	}
	if _, err = conn.ExecContext(ctx, "INSERT INTO publications(session_uid,key,artifact,body) VALUES(?,?,?,?)", scope.SessionUID, c.IdempotencyKey, artifact, body); err != nil {
		return api.ToolResult{}, err
	}
	if _, err = conn.ExecContext(ctx, "INSERT INTO receipts(session_uid,key,fingerprint,output) VALUES(?,?,?,?)", scope.SessionUID, c.IdempotencyKey, fingerprint, output); err != nil {
		return api.ToolResult{}, err
	}
	if _, err = conn.ExecContext(ctx, "COMMIT"); err != nil {
		return api.ToolResult{}, err
	}
	if e.afterCommit != nil {
		if err = e.afterCommit(); err != nil {
			return api.ToolResult{}, err
		}
	}
	return api.ToolResult{ID: c.ID, Output: out}, nil
}
func (e *executor) counts() (p, r int, err error) {
	err = e.db.QueryRow("SELECT (SELECT COUNT(*) FROM publications),(SELECT COUNT(*) FROM receipts)").Scan(&p, &r)
	return
}
func (e *executor) inventory() ([]publicationRow, error) {
	rows, err := e.db.Query("SELECT artifact,body FROM publications ORDER BY artifact")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []publicationRow{}
	for rows.Next() {
		var r publicationRow
		if err = rows.Scan(&r.Name, &r.Raw); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
