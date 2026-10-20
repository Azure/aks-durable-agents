// Package democli is the SDK scenario client for the local kind demo. Every
// command prints exactly one JSON object; the runner owns human prompting and
// never retries a state-changing command. Nothing here approves or resumes
// implicitly, and no credential or non-loopback server is accepted.
package democli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/agent-primitives/sessions/api"
	v1 "github.com/agent-primitives/sessions/api/genpb"
	"github.com/agent-primitives/sessions/client"
	"github.com/agent-primitives/sessions/wire"
)

const (
	defaultServer = "http://127.0.0.1:8080"
	fixtureBinary = "/session-fixture"
	tool          = "publish_release_notes"
	destination   = "release-notes-demo"
	input         = "Write a fictional release-notes proposal for the Northwind Lantern v2.4 offline demo."
	maxFile       = 64 << 10
	maxMeterLines = 1000
	maxRecords    = 10000
)

// fixtureFunc runs one published /session-fixture command and returns stdout.
// Production always execs the fixed binary; tests adapt the same RunCLI.
type fixtureFunc func(ctx context.Context, args ...string) ([]byte, error)

// Run executes one command, writing a single JSON object to out on success.
func Run(ctx context.Context, args []string, out io.Writer) error {
	return run(ctx, args, out, execFixture)
}

type pending struct {
	ExecutionID string `json:"executionID"`
	ToolCallID  string `json:"toolCallID"`
	RequestSeq  int64  `json:"requestSeq"`
}

// state is the immutable park.json / approved.json / completed.json shape.
type state struct {
	Session     string  `json:"session"`
	Pending     pending `json:"pending"`
	HeadSeq     int64   `json:"headSeq"`
	HeadHash    string  `json:"headHash"`
	Draft       string  `json:"draft"`
	ApprovalSeq int64   `json:"approvalSeq,omitempty"`
	Artifact    string  `json:"artifact,omitempty"`
}

func run(ctx context.Context, args []string, out io.Writer, fixture fixtureFunc) error {
	const commands = "commands: prepare, park, check-parked, approve, continue, seal, verify, counter"
	if len(args) == 0 {
		return errors.New(commands)
	}
	name := args[0]
	rpc := name == "park" || name == "check-parked" || name == "approve" || name == "continue"
	if !rpc && name != "prepare" && name != "verify" && name != "counter" && name != "seal" {
		return errors.New("unknown command " + strconv.Quote(name) + "; " + commands)
	}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	data := fs.String("data", "", "absolute private data directory")
	server := fs.String("server", defaultServer, "loopback Sessions server")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	explicitServer := false
	fs.Visit(func(f *flag.Flag) { explicitServer = explicitServer || f.Name == "server" })
	if explicitServer && !rpc {
		return errors.New("--server is only valid for park, check-parked, approve and continue")
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	var result any
	var err error
	switch name {
	case "prepare":
		result, err = prepare(ctx, *data, fixture)
	case "counter":
		result, err = counter(*data)
	case "seal":
		result, err = seal(ctx, *data, fixture)
	case "verify":
		result, err = verify(ctx, *data, fixture)
	default:
		result, err = rpcCommand(ctx, name, *data, *server)
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(result)
}

func rpcCommand(ctx context.Context, name, data, server string) (any, error) {
	if err := ownedPrivateDir(data); err != nil {
		return nil, err
	}
	target := strings.TrimPrefix(server, "http://")
	host, port, err := net.SplitHostPort(target)
	number, _ := strconv.Atoi(port)
	if ip := net.ParseIP(host); err != nil || ip == nil || !ip.IsLoopback() || number < 1 || number > 65535 {
		return nil, errors.New("only a literal loopback http://HOST:PORT Sessions server is allowed")
	}
	c, err := client.Dial(target)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	switch name {
	case "park":
		return park(ctx, c, data)
	case "check-parked":
		return checkParked(ctx, c, data)
	case "approve":
		return approve(ctx, c, data)
	}
	return cont(ctx, c, data)
}

// ---- private files --------------------------------------------------------

func ownedPrivateDir(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("--data must be an absolute clean path")
	}
	if real, err := filepath.EvalSymlinks(path); err != nil || real != path {
		return errors.New("--data must be an existing path without symlinks")
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || !info.IsDir() || info.Mode().Perm() != 0700 || int(st.Uid) != os.Getuid() {
		return errors.New("--data must be an owned mode 0700 directory")
	}
	return nil
}

// readOwned reads a bounded regular mode-0600 file owned by this user without
// following symlinks. A missing file is reported as os.ErrNotExist.
func readOwned(path string, limit int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || int(st.Uid) != os.Getuid() || info.Size() > limit {
		return nil, fmt.Errorf("%s must be a bounded owned regular mode 0600 file", filepath.Base(path))
	}
	return io.ReadAll(io.LimitReader(f, limit))
}

func strictDecode(raw []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}

var hexHash = regexp.MustCompile(`^[0-9a-f]{64}$`)

func readState(data, name string) (state, error) {
	var st state
	raw, err := readOwned(filepath.Join(data, name), maxFile)
	if err != nil {
		return st, fmt.Errorf("%s: %w", name, err)
	}
	if err = strictDecode(raw, &st); err != nil {
		return st, fmt.Errorf("%s: %w", name, err)
	}
	p := st.Pending
	if st.Session == "" || p.ExecutionID == "" || p.ToolCallID == "" || p.RequestSeq <= 0 || st.HeadSeq <= 0 || !hexHash.MatchString(st.HeadHash) || st.Draft == "" {
		return st, errors.New(name + " is incomplete")
	}
	return st, nil
}

// writeState creates a new immutable snapshot; an existing file is never replaced.
func writeState(data, name string, st state) error {
	raw, err := json.Marshal(st)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(data, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(append(raw, '\n'))
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	dir, err := os.Open(data)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func absent(data, name string) error {
	if _, err := os.Lstat(filepath.Join(data, name)); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%s already exists or cannot be inspected; refusing implicit retry", name)
	}
	return nil
}

// ---- fixture commands -----------------------------------------------------

type capped struct {
	buf bytes.Buffer
	max int
}

func (c *capped) Write(p []byte) (int, error) {
	if c.buf.Len()+len(p) > c.max {
		return 0, errors.New("fixture output exceeds bound")
	}
	return c.buf.Write(p)
}

func execFixture(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, fixtureBinary, args...)
	cmd.Env = []string{}
	stdout, stderr := &capped{max: 1 << 20}, &capped{max: 4 << 10}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Run(); err != nil {
		return stdout.buf.Bytes(), fmt.Errorf("%s %s: %w: %s", fixtureBinary, args[0], err, strings.TrimSpace(stderr.buf.String()))
	}
	return stdout.buf.Bytes(), nil
}

func fixtureJSON(ctx context.Context, fixture fixtureFunc, dst any, args ...string) error {
	raw, err := fixture(ctx, args...)
	if err != nil {
		return err
	}
	if err = strictDecode(raw, dst); err != nil {
		return fmt.Errorf("fixture %s output: %w", args[0], err)
	}
	return nil
}

func prepare(ctx context.Context, data string, fixture fixtureFunc) (any, error) {
	if err := ownedPrivateDir(data); err != nil {
		return nil, err
	}
	if entries, err := os.ReadDir(data); err != nil || len(entries) != 0 {
		return nil, errors.New("prepare requires a fresh empty directory; no reuse or reset")
	}
	var initialized struct {
		Initialized bool   `json:"initialized"`
		Data        string `json:"data"`
		UID         int    `json:"uid"`
		GID         int    `json:"gid"`
		Mode        string `json:"mode"`
	}
	// The fixed runtime path: application pods mount this subtree at /data.
	if err := fixtureJSON(ctx, fixture, &initialized, "init", "--scenario", "v2", "--data", data, "--socket", "/data/publish.sock"); err != nil || !initialized.Initialized {
		return nil, fmt.Errorf("fixture init failed: %v", err)
	}
	for _, name := range []string{"tmp-daemon", "tmp-fixture-harness", "tmp-executor", "tmp-fake"} {
		path := filepath.Join(data, name)
		// Chmod explicitly: the mode passed to Mkdir is masked by the umask.
		if err := os.Mkdir(path, 0700); err != nil {
			return nil, err
		}
		if err := os.Chmod(path, 0700); err != nil {
			return nil, err
		}
	}
	return map[string]bool{"prepared": true}, nil
}

// counter reads the fake host's durable HTTP-attempt meter. Absence means no
// attempt has happened yet; any rejected, malformed or truncated record is not
// proof of a clean run.
func counter(data string) (any, error) {
	n, err := meter(data)
	if err != nil {
		return nil, err
	}
	return map[string]int{"modelHTTPCalls": n}, nil
}

func meter(data string) (int, error) {
	if err := ownedPrivateDir(data); err != nil {
		return 0, err
	}
	raw, err := readOwned(filepath.Join(data, "demo-model-calls.jsonl"), 1<<20)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if len(raw) == 0 {
		return 0, nil
	}
	if raw[len(raw)-1] != '\n' {
		return 0, errors.New("truncated model HTTP meter")
	}
	lines := bytes.Split(raw[:len(raw)-1], []byte{'\n'})
	if len(lines) > maxMeterLines {
		return 0, errors.New("model HTTP meter exceeds bound")
	}
	for _, line := range lines {
		var rec struct {
			Accepted *bool `json:"accepted"`
		}
		if err = strictDecode(line, &rec); err != nil || rec.Accepted == nil || !*rec.Accepted {
			return 0, errors.New("model HTTP meter has a malformed or non-accepted attempt")
		}
	}
	return len(lines), nil
}

// ---- Sessions commands ----------------------------------------------------

type view struct {
	session *v1.Session
	events  []api.Event
	seqs    []int64
	hash    string
}

func tupleOf(s *v1.Session) (pending, bool) {
	p := s.GetPendingApproval()
	if p == nil {
		return pending{}, false
	}
	return pending{p.GetExecutionId(), p.GetToolCallId(), p.GetRequestSeq()}, true
}

// inspect reads the session and complete journal, requiring an unchanged head
// and pending approval across the read.
func inspect(ctx context.Context, c *client.Client, uid string) (view, error) {
	s, err := c.GetSession(ctx, uid)
	if err != nil {
		return view{}, err
	}
	if s.GetMetadata().GetUid() != uid || s.GetLastSeq() < 1 || s.GetLastSeq() > maxRecords {
		return view{}, errors.New("session identity or journal bound mismatch")
	}
	records, err := c.Replay(ctx, uid, 1, s.GetLastSeq())
	if err != nil {
		return view{}, err
	}
	after, err := c.GetSession(ctx, uid)
	if err != nil {
		return view{}, err
	}
	p1, ok1 := tupleOf(s)
	p2, ok2 := tupleOf(after)
	if after.GetLastSeq() != s.GetLastSeq() || ok1 != ok2 || p1 != p2 {
		return view{}, errors.New("session changed during inspection")
	}
	if len(records) == 0 || records[len(records)-1].GetSeq() != s.GetLastSeq() {
		return view{}, errors.New("missing journal head")
	}
	v := view{session: s, hash: records[len(records)-1].GetContentHash()}
	for _, r := range records {
		v.events = append(v.events, wire.EventFromProto(r.GetEvent()))
		v.seqs = append(v.seqs, r.GetSeq())
	}
	return v, nil
}

func (v view) draft(p pending) (string, error) {
	draft := ""
	for _, e := range v.events {
		if e.Kind == api.EventToolCall {
			args, ok := e.ToolCall.Args["draft"].(string)
			if draft != "" || !ok || args == "" || e.ToolCall.ID != p.ToolCallID || e.ToolCall.Tool != tool || e.ToolCall.Args["destination"] != destination || len(e.ToolCall.Args) != 2 {
				return "", errors.New("journal lacks exactly one matching publication call")
			}
			draft = args
		}
	}
	if draft == "" {
		return "", errors.New("journal lacks the publication call")
	}
	return draft, nil
}

// sameParked requires the exact UID/head/hash/pending tuple and draft.
func sameParked(v view, st state) error {
	p, ok := tupleOf(v.session)
	draft, err := v.draft(st.Pending)
	if err != nil {
		return err
	}
	if v.session.GetMetadata().GetUid() != st.Session || v.session.GetLastSeq() != st.HeadSeq || v.hash != st.HeadHash || !ok || p != st.Pending || draft != st.Draft {
		return errors.New("session is not in the exact parked state (UID/head/hash/pending/draft changed)")
	}
	return nil
}

func park(ctx context.Context, c *client.Client, data string) (any, error) {
	if err := absent(data, "park.json"); err != nil {
		return nil, err
	}
	// A lost snapshot or earlier attempt must not silently create a second session.
	if existing, err := c.ListSessions(ctx, ""); err != nil || len(existing) != 0 {
		return nil, fmt.Errorf("park requires a fresh host with no sessions (existing %d, err %v); refusing implicit retry", len(existing), err)
	}
	created, err := c.CreateSession(ctx, &v1.Session{Harness: "release-notes"})
	if err != nil {
		return nil, err
	}
	uid, head := created.GetMetadata().GetUid(), created.GetLastSeq()
	if _, err = c.Exec(ctx, client.ExecOptions{Session: uid, Inputs: []string{input}, ExpectedLastSeq: &head}); err != nil {
		return nil, fmt.Errorf("session %s: exec: %w", uid, err)
	}
	v, err := inspect(ctx, c, uid)
	if err != nil {
		return nil, fmt.Errorf("session %s: %w", uid, err)
	}
	p, ok := tupleOf(v.session)
	if !ok || p.ExecutionID == "" || p.ToolCallID != p.ExecutionID+"/"+tool || p.RequestSeq <= 0 {
		return nil, fmt.Errorf("session %s: missing deterministic parked approval", uid)
	}
	draft, err := v.draft(p)
	if err != nil {
		return nil, fmt.Errorf("session %s: %w", uid, err)
	}
	st := state{Session: uid, Pending: p, HeadSeq: v.session.GetLastSeq(), HeadHash: v.hash, Draft: draft}
	if err = writeState(data, "park.json", st); err != nil {
		return nil, fmt.Errorf("session %s: snapshot: %w", uid, err)
	}
	return st, nil
}

func checkParked(ctx context.Context, c *client.Client, data string) (any, error) {
	st, err := readState(data, "park.json")
	if err != nil {
		return nil, err
	}
	v, err := inspect(ctx, c, st.Session)
	if err != nil {
		return nil, err
	}
	if err = sameParked(v, st); err != nil {
		return nil, err
	}
	return map[string]any{"session": st.Session, "parked": true}, nil
}

// approvalSeq validates the committed decision and that nothing has executed.
func approvalSeq(v view, st state) (int64, error) {
	seq := int64(0)
	for i, e := range v.events {
		switch e.Kind {
		case api.EventApprovalResult:
			r := e.ApprovalResult
			if seq != 0 || r == nil || !r.Approved || r.RequestSeq != st.Pending.RequestSeq || r.ToolCallID != st.Pending.ToolCallID || v.seqs[i] <= st.Pending.RequestSeq {
				return 0, errors.New("journal lacks exactly one matching approval")
			}
			seq = v.seqs[i]
		case api.EventToolResult, api.EventEnd:
			return 0, errors.New("tool result or end recorded before explicit continue")
		}
	}
	if seq == 0 || seq != v.session.GetLastSeq() {
		return 0, errors.New("approval decision is not the journal head")
	}
	return seq, nil
}

func approve(ctx context.Context, c *client.Client, data string) (any, error) {
	st, err := readState(data, "park.json")
	if err != nil {
		return nil, err
	}
	if err = absent(data, "approved.json"); err != nil {
		return nil, err
	}
	v, err := inspect(ctx, c, st.Session)
	if err != nil {
		return nil, err
	}
	if err = sameParked(v, st); err != nil {
		return nil, err
	}
	p := st.Pending
	// One Approve and no Resume; a lost response is surfaced, never retried.
	if _, err = c.Approve(ctx, st.Session, api.ApprovalDecision{ExecutionID: p.ExecutionID, ToolCallID: p.ToolCallID, RequestSeq: p.RequestSeq, Approved: true, Reason: "local demo approval from an explicit prompt; identity not exercised"}); err != nil {
		return nil, fmt.Errorf("approve outcome unknown; inspect durable state, do not retry blindly: %w", err)
	}
	after, err := inspect(ctx, c, st.Session)
	if err != nil {
		return nil, err
	}
	seq, err := approvalSeq(after, st)
	if err != nil {
		return nil, err
	}
	st.HeadSeq, st.HeadHash, st.ApprovalSeq = after.session.GetLastSeq(), after.hash, seq
	if err = writeState(data, "approved.json", st); err != nil {
		return nil, err
	}
	return map[string]any{"session": st.Session, "approved": true}, nil
}

// receipt validates the one effect and returns its artifact name.
func receipt(v view, st state) (string, error) {
	var call *api.ToolCall
	var result *api.ToolResult
	ended := 0
	for _, e := range v.events {
		switch e.Kind {
		case api.EventToolCall:
			if call != nil {
				return "", errors.New("duplicate publication call")
			}
			call = e.ToolCall
		case api.EventToolResult:
			if result != nil {
				return "", errors.New("duplicate publication result")
			}
			result = e.Result
		case api.EventEnd:
			if e.End == nil || e.End.State != "COMPLETED" {
				return "", errors.New("execution did not complete")
			}
			ended++
		}
	}
	if ended != 1 || call == nil || result == nil || v.session.GetPendingApproval() != nil || call.ID != st.Pending.ToolCallID || call.Args["draft"] != st.Draft {
		return "", errors.New("completed call/result/end invariant failed")
	}
	if result.ID != st.Pending.ToolCallID || result.ApprovalRequestSeq != st.Pending.RequestSeq || result.ApprovalDecisionSeq != st.ApprovalSeq || result.IsError || result.Code != api.ToolResultCodeUnspecified {
		return "", errors.New("receipt is not bound to the approval request and decision")
	}
	identity, _ := json.Marshal([]string{st.Session, call.IdempotencyKey})
	artifact, _ := result.Output["artifact"].(string)
	if result.Output["simulated"] != true || result.Output["draft"] != st.Draft || result.Output["destination"] != destination || artifact != digest(identity)+".json" {
		return "", errors.New("simulated publication receipt mismatch")
	}
	return artifact, nil
}

func cont(ctx context.Context, c *client.Client, data string) (any, error) {
	st, err := readState(data, "approved.json")
	if err != nil {
		return nil, err
	}
	if st.ApprovalSeq <= st.Pending.RequestSeq {
		return nil, errors.New("approved.json lacks the approval decision")
	}
	if err = absent(data, "completed.json"); err != nil {
		return nil, err
	}
	v, err := inspect(ctx, c, st.Session)
	if err != nil {
		return nil, err
	}
	if seq, aerr := approvalSeq(v, st); aerr != nil || seq != st.ApprovalSeq || v.session.GetLastSeq() != st.HeadSeq || v.hash != st.HeadHash {
		return nil, fmt.Errorf("session is not at the exact approved head (%v)", aerr)
	}
	head := st.HeadSeq
	if _, err = c.Sessions().Resume(ctx, &v1.ResumeRequest{Session: st.Session, ExpectedLastSeq: &head}); err != nil {
		return nil, fmt.Errorf("continue outcome unknown; inspect durable state, do not retry blindly: %w", err)
	}
	done, err := inspect(ctx, c, st.Session)
	if err != nil {
		return nil, err
	}
	artifact, err := receipt(done, st)
	if err != nil {
		return nil, err
	}
	st.HeadSeq, st.HeadHash, st.Artifact = done.session.GetLastSeq(), done.hash, artifact
	if err = writeState(data, "completed.json", st); err != nil {
		return nil, err
	}
	return map[string]any{"session": st.Session, "completed": true, "artifact": artifact}, nil
}

// ---- offline verification -------------------------------------------------

type artifactDigest struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
}
type attempt struct {
	AttemptID       int     `json:"attemptId"`
	Time            string  `json:"time"`
	FinishedAt      *string `json:"finishedAt"`
	Outcome         string  `json:"outcome"`
	InputTokens     *int64  `json:"inputTokens"`
	OutputTokens    *int64  `json:"outputTokens"`
	ReasoningTokens *int64  `json:"reasoningTokens"`
}

// evidence mirrors `session-fixture evidence --scenario v2` exactly.
type evidence struct {
	FakeModelCalls   int              `json:"fakeModelCalls"`
	RealModelCalls   *int             `json:"realModelCalls"`
	RealLedgerDigest string           `json:"realLedgerDigest"`
	RealAttempts     []attempt        `json:"realAttempts"`
	Artifacts        []artifactDigest `json:"artifacts"`
	PublicationCount int              `json:"publicationCount"`
	ReceiptCount     int              `json:"receiptCount"`
}

// replay mirrors `session-fixture verify-replay` exactly.
type replay struct {
	SessionUID           string   `json:"session_uid"`
	HeadSeq              int64    `json:"head_seq"`
	HeadHash             string   `json:"head_hash"`
	CheckpointSeq        int64    `json:"checkpoint_seq"`
	ExpectedExecutionIDs []string `json:"expected_execution_ids"`
	CoveredExecutionIDs  []string `json:"covered_execution_ids"`
	ProviderCalls        int      `json:"provider_calls"`
	ExecutorCalls        int      `json:"executor_calls"`
	Completed            bool     `json:"completed"`
	Error                string   `json:"error"`
}

func verify(ctx context.Context, data string, fixture fixtureFunc) (any, error) {
	st, err := readState(data, "completed.json")
	if err != nil {
		return nil, err
	}
	if st.Artifact == "" || st.ApprovalSeq <= st.Pending.RequestSeq {
		return nil, errors.New("completed.json is incomplete")
	}
	sealed, err := readState(data, "sealed.json")
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(st, sealed) {
		return nil, errors.New("completed state differs from the final sealed snapshot")
	}
	httpBefore, err := meter(data)
	if err != nil {
		return nil, err
	}
	var before, after evidence
	if err = fixtureJSON(ctx, fixture, &before, "evidence", "--scenario", "v2", "--data", data); err != nil {
		return nil, err
	}
	var proof replay
	if err = fixtureJSON(ctx, fixture, &proof, "verify-replay", "--scenario", "v2", "--journal", filepath.Join(data, "journal.db"), "--instructions", filepath.Join(data, "instructions.txt"), "--session", st.Session); err != nil {
		return nil, err
	}
	if err = fixtureJSON(ctx, fixture, &after, "evidence", "--scenario", "v2", "--data", data); err != nil {
		return nil, err
	}
	httpAfter, err := meter(data)
	if err != nil {
		return nil, err
	}
	if proof.Error != "" || !proof.Completed || proof.SessionUID != st.Session || proof.HeadSeq != st.HeadSeq || proof.HeadHash != st.HeadHash ||
		proof.ProviderCalls != 0 || proof.ExecutorCalls != 0 || len(proof.ExpectedExecutionIDs) == 0 ||
		!slices.Equal(proof.ExpectedExecutionIDs, proof.CoveredExecutionIDs) || !slices.Contains(proof.CoveredExecutionIDs, st.Pending.ExecutionID) {
		return nil, errors.New("strict replay did not cover the completed session head with zero provider/executor calls")
	}
	if !reflect.DeepEqual(before, after) || httpBefore != httpAfter {
		return nil, errors.New("verification changed an evidence or model HTTP inventory")
	}
	if after.RealModelCalls == nil || *after.RealModelCalls != 1 || len(after.RealAttempts) != 1 || after.RealAttempts[0].Outcome != "succeeded" || after.FakeModelCalls != 0 ||
		after.PublicationCount != 1 || after.ReceiptCount != 1 || len(after.Artifacts) != 1 || after.Artifacts[0].Name != st.Artifact || httpAfter != 1 {
		return nil, errors.New("evidence does not show one model attempt, one publication and receipt, and one HTTP attempt")
	}
	return map[string]any{"session": st.Session, "completed": true, "provider_calls": 0, "executor_calls": 0, "publicationCount": 1, "receiptCount": 1, "artifacts": 1,
		"realModelCalls": 1, "fakeModelCalls": 0, "modelHTTPCalls": 1, "headSeq": st.HeadSeq, "headHash": st.HeadHash, "artifact": st.Artifact}, nil
}

func digest(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
