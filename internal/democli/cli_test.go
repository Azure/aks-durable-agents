package democli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/aks-durable-agents/internal/host"
	fixture "github.com/Azure/aks-durable-agents/internal/sessionfixture"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/agent-primitives/sessions/authn"
	"github.com/agent-primitives/sessions/client"
)

// Tests run the real published-fixture roles (harness, executor, evidence,
// verify-replay) and the real host/SDK assembly in-process. Only the fake model
// HTTP endpoint is local; it stands in for the demo host's durable HTTP meter.

func privateDir(t *testing.T) string {
	t.Helper()
	// Short path: the executor uses a Unix socket. Chmod explicitly; the process
	// umask is not a safe source of 0700 (CI commonly uses 022).
	dir, err := os.MkdirTemp("", "dc-")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// fixtureAdapter calls the actual fixture CLI in-process, never canned JSON.
func fixtureAdapter(ctx context.Context, args ...string) ([]byte, error) {
	var out, errOut bytes.Buffer
	err := fixture.RunCLI(ctx, args, &out, &errOut)
	if err != nil {
		return out.Bytes(), fmt.Errorf("%w: %s", err, errOut.String())
	}
	return out.Bytes(), nil
}

func cli(t *testing.T, args ...string) (map[string]any, error) {
	t.Helper()
	var out bytes.Buffer
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	err := run(ctx, args, &out, fixtureAdapter)
	if err != nil {
		if out.Len() != 0 {
			t.Fatalf("failed command wrote stdout: %q", out.String())
		}
		return nil, err
	}
	var v map[string]any
	if json.Unmarshal(out.Bytes(), &v) != nil || bytes.Count(out.Bytes(), []byte("\n")) != 1 {
		t.Fatalf("stdout must be exactly one JSON object line: %q", out.String())
	}
	return v, nil
}

func mustCLI(t *testing.T, args ...string) map[string]any {
	t.Helper()
	v, err := cli(t, args...)
	if err != nil {
		t.Fatalf("%v: %v", args, err)
	}
	return v
}

func TestVerifyPropagatesFirstFixtureRefusal(t *testing.T) {
	d := completedDemo(t)
	mustCLI(t, "seal", "--data", d.data)
	refusal := errors.New("fixture refused replay")
	firstReplay := true
	fixtureFailure := func(ctx context.Context, args ...string) ([]byte, error) {
		if args[0] == "verify-replay" && firstReplay {
			firstReplay = false
			return nil, refusal
		}
		return fixtureAdapter(ctx, args...)
	}
	var output bytes.Buffer
	err := run(t.Context(), []string{"verify", "--data", d.data}, &output, fixtureFailure)
	if !errors.Is(err, refusal) || output.Len() != 0 {
		t.Fatalf("first fixture failure was suppressed: %v; output %s", err, &output)
	}
}

func TestPrepareFreshEmptyOwnedDirectoryOnly(t *testing.T) {
	data := privateDir(t)
	got := mustCLI(t, "prepare", "--data", data)
	if !reflect.DeepEqual(got, map[string]any{"prepared": true}) {
		t.Fatalf("stdout %v", got)
	}
	for _, name := range []string{"scenario.json", "instructions.txt", "tools.json"} {
		if info, err := os.Stat(filepath.Join(data, name)); err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("%s: %v %v", name, info, err)
		}
	}
	for _, name := range []string{"tmp-daemon", "tmp-fixture-harness", "tmp-executor", "tmp-fake"} {
		if info, err := os.Stat(filepath.Join(data, name)); err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
			t.Fatalf("%s: %v %v", name, info, err)
		}
	}
	tools, _ := os.ReadFile(filepath.Join(data, "tools.json"))
	if !strings.Contains(string(tools), `"/data/publish.sock"`) {
		t.Fatalf("runtime socket path not recorded: %s", tools)
	}
	if _, err := cli(t, "prepare", "--data", data); err == nil {
		t.Fatal("prepare reused a nonempty directory")
	}
	loose := privateDir(t)
	if err := os.Chmod(loose, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := cli(t, "prepare", "--data", loose); err == nil {
		t.Fatal("prepare accepted mode 0755")
	}
	if entries, _ := os.ReadDir(loose); len(entries) != 0 {
		t.Fatal("refused prepare mutated directory")
	}
	if _, err := cli(t, "prepare", "--data", "relative"); err == nil {
		t.Fatal("prepare accepted relative path")
	}
}

func TestCounterBoundedOwnedMeter(t *testing.T) {
	data := privateDir(t)
	if got := mustCLI(t, "counter", "--data", data); !reflect.DeepEqual(got, map[string]any{"modelHTTPCalls": float64(0)}) {
		t.Fatalf("missing meter: %v", got)
	}
	meter := filepath.Join(data, "demo-model-calls.jsonl")
	write := func(content string, mode os.FileMode) {
		t.Helper()
		os.Remove(meter)
		if err := os.WriteFile(meter, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(meter, mode); err != nil {
			t.Fatal(err)
		}
	}
	write("{\"accepted\":true}\n{\"accepted\":true}\n", 0600)
	if got := mustCLI(t, "counter", "--data", data); got["modelHTTPCalls"] != float64(2) {
		t.Fatalf("count: %v", got)
	}
	for name, content := range map[string]string{
		"rejected attempt": "{\"accepted\":false}\n", "truncated": "{\"accepted\":true}", "extra fields": "{\"accepted\":true,\"prompt\":\"x\"}\n",
		"missing field": "{}\n", "not json": "x\n", "too many": strings.Repeat("{\"accepted\":true}\n", 1001),
	} {
		write(content, 0600)
		if _, err := cli(t, "counter", "--data", data); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	write("{\"accepted\":true}\n", 0644)
	if _, err := cli(t, "counter", "--data", data); err == nil {
		t.Fatal("mode 0644 meter accepted")
	}
	os.Remove(meter)
	if err := os.Symlink("/etc/hostname", meter); err != nil {
		t.Fatal(err)
	}
	if _, err := cli(t, "counter", "--data", data); err == nil {
		t.Fatal("symlink meter accepted")
	}
}

func TestInvalidInvocationsAreRefusedWithoutOutput(t *testing.T) {
	data := privateDir(t)
	for _, args := range [][]string{
		nil, {"bogus"}, {"park"}, {"park", "--data", data, "extra"}, {"park", "--data", data, "--token", "x"},
		{"park", "--data", data, "--server", "http://example.com:8080"}, {"park", "--data", data, "--server", "10.0.0.1:8080"},
		{"park", "--data", data, "--server", "https://127.0.0.1:8080"}, {"park", "--data", data, "--server", "http://localhost:8080"},
		{"check-parked", "--data", "relative"}, {"approve", "--data", data, "--yes"}, {"counter", "--data", data, "--server", "127.0.0.1:1"},
	} {
		if _, err := cli(t, args...); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}

type staticCredential struct{}

func (staticCredential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "test-model-token", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

type firstLine struct {
	once sync.Once
	ch   chan string
	mu   sync.Mutex
	buf  bytes.Buffer
}

func (w *firstLine) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf.Write(p)
	if i := bytes.IndexByte(w.buf.Bytes(), '\n'); i >= 0 {
		w.once.Do(func() { w.ch <- string(w.buf.Bytes()[:i]) })
	}
	return len(p), nil
}

// startRole runs one actual fixture role until the returned stop is called.
func startRole(t *testing.T, args ...string) (string, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	w := &firstLine{ch: make(chan string, 1)}
	done := make(chan error, 1)
	go func() { done <- fixture.RunCLI(ctx, args, w, io.Discard) }()
	var line string
	select {
	case line = <-w.ch:
	case err := <-done:
		cancel()
		t.Fatalf("fixture %v exited: %v", args, err)
	case <-time.After(20 * time.Second):
		cancel()
		t.Fatalf("fixture %v did not start", args)
	}
	var once sync.Once
	stop := func() { once.Do(func() { cancel(); <-done }) }
	t.Cleanup(stop)
	return line, stop
}

type demo struct {
	t                                  *testing.T
	data, server                       string
	harness                            string
	stopExecutor, stopHarness, stopOne func()
	cfg                                host.Config
	posts                              int
	mu                                 sync.Mutex
}

const testDraft = "Northwind Lantern v2.4 — 18 October 2026\n\nThis fictional release introduces faster search and CSV export. This is an offline demo only; rollout pending approval. Review these release notes before the local publication simulation."

func newDemo(t *testing.T) *demo {
	t.Helper()
	d := &demo{t: t, data: privateDir(t)}
	if _, err := fixtureAdapter(t.Context(), "init", "--scenario", "v2", "--data", d.data, "--socket", filepath.Join(d.data, "publish.sock")); err != nil {
		t.Fatal(err)
	}
	_, d.stopExecutor = startRole(t, "executor", "--scenario", "v2", "--socket", filepath.Join(d.data, "publish.sock"), "--database", filepath.Join(d.data, "publications.db"))
	line, stop := startRole(t, "harness", "--scenario", "v2", "--addr", "127.0.0.1:0", "--instructions", filepath.Join(d.data, "instructions.txt"), "--node-name", "offline-node", "--pod-uid", "offline-fixture")
	d.stopHarness = stop
	var addr struct{ Addr string }
	if json.Unmarshal([]byte(line), &addr) != nil {
		t.Fatal(line)
	}
	d.harness = addr.Addr
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		d.posts++
		d.mu.Unlock()
		f, err := os.OpenFile(filepath.Join(d.data, "demo-model-calls.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			t.Error(err)
			return
		}
		f.WriteString("{\"accepted\":true}\n")
		f.Sync()
		f.Close()
		w.Header().Set("Content-Type", "text/event-stream")
		delta, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"delta": map[string]any{"content": testDraft}}}})
		fmt.Fprintf(w, "data: %s\n\ndata: {\"choices\":[],\"usage\":{\"prompt_tokens\":250,\"completion_tokens\":84,\"total_tokens\":334,\"completion_tokens_details\":{\"reasoning_tokens\":12}}}\n\ndata: [DONE]\n\n", delta)
	}))
	t.Cleanup(provider.Close)
	budget, _ := json.Marshal(map[string]any{"version": 1, "runID": "offline-test", "ledgerPath": filepath.Join(d.data, "real-attempts.db"), "deployment": "test-deployment", "pricing": map[string]any{"inputMicroUSDPerMillionTokens": 100000, "outputMicroUSDPerMillionTokens": 500000, "extraMicroUSDPerCall": 0, "source": "https://example.test/dated-test-rates", "asOf": "2026-09-22"}})
	policyPath := filepath.Join(d.data, "model-policy.json")
	if err := os.WriteFile(policyPath, budget, 0600); err != nil {
		t.Fatal(err)
	}
	d.cfg = host.Config{Addr: "127.0.0.1:0", HealthAddr: "127.0.0.1:0", Journal: filepath.Join(d.data, "journal.db"), Mode: authn.Off,
		Harnesses: map[string]string{"release-notes": d.harness}, ToolExecutors: filepath.Join(d.data, "tools.json"),
		ModelEndpoint: provider.URL + "/openai/v1/", Deployment: "test-deployment", ModelScope: "https://ai.azure.com/.default",
		ModelTransport: provider.Client().Transport.(*http.Transport), ModelCredential: staticCredential{}, ModelPolicy: policyPath,
		PeerNodeFile: filepath.Join(d.data, "fixture-node.json"), NodeName: "offline-node"}
	// Both real entrypoints set umask 0077. This in-process test must not
	// mutate a process-global umask; precreate only its own fresh journal with
	// the same private mode before SQLite initializes its schema.
	journal, err := os.OpenFile(d.cfg.Journal, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	d.startHost()
	return d
}

type logSink struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logSink) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}
func (l *logSink) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.buf.String() }

var sessionsAddr = regexp.MustCompile(`sessions=(127\.0\.0\.1:\d+)`)

// startHost starts a replacement host process-equivalent over the same durable data.
func (d *demo) startHost() {
	d.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	logs := &logSink{}
	done := make(chan error, 1)
	go func() { done <- host.Run(ctx, d.cfg, slog.New(slog.NewTextHandler(logs, nil))) }()
	deadline := time.Now().Add(20 * time.Second)
	for d.server = ""; d.server == ""; time.Sleep(10 * time.Millisecond) {
		if m := sessionsAddr.FindStringSubmatch(logs.String()); m != nil {
			d.server = "http://" + m[1]
		}
		select {
		case err := <-done:
			cancel()
			d.t.Fatalf("host exited: %v\n%s", err, logs.String())
		default:
		}
		if time.Now().After(deadline) {
			cancel()
			d.t.Fatalf("host did not listen: %s", logs.String())
		}
	}
	var once sync.Once
	d.stopOne = func() { once.Do(func() { cancel(); <-done }) }
	d.t.Cleanup(d.stopOne)
}

func (d *demo) rpc(command string) (map[string]any, error) {
	return cli(d.t, command, "--data", d.data, "--server", d.server)
}
func (d *demo) mustRPC(command string) map[string]any {
	d.t.Helper()
	v, err := d.rpc(command)
	if err != nil {
		d.t.Fatalf("%s: %v", command, err)
	}
	return v
}
func (d *demo) head(uid string) int64 {
	d.t.Helper()
	c, err := client.Dial(strings.TrimPrefix(d.server, "http://"))
	if err != nil {
		d.t.Fatal(err)
	}
	defer c.Close()
	s, err := c.GetSession(d.t.Context(), uid)
	if err != nil {
		d.t.Fatal(err)
	}
	return s.GetLastSeq()
}
func (d *demo) evidence() map[string]any {
	d.t.Helper()
	out, err := fixtureAdapter(d.t.Context(), "evidence", "--scenario", "v2", "--data", d.data)
	var v map[string]any
	if err != nil || json.Unmarshal(out, &v) != nil {
		d.t.Fatalf("evidence: %v %s", err, out)
	}
	return v
}
func (d *demo) stopWriters() { d.stopOne(); d.stopHarness(); d.stopExecutor() }
func (d *demo) rewrite(name string, mutate func(map[string]any)) {
	d.t.Helper()
	path := filepath.Join(d.data, name)
	raw, err := os.ReadFile(path)
	if err != nil {
		d.t.Fatal(err)
	}
	var v map[string]any
	if err = json.Unmarshal(raw, &v); err != nil {
		d.t.Fatal(err)
	}
	mutate(v)
	raw, _ = json.Marshal(v)
	if err = os.WriteFile(path, raw, 0600); err != nil {
		d.t.Fatal(err)
	}
}

func TestParkRestartApproveContinueVerifyThroughRealHost(t *testing.T) {
	d := newDemo(t)
	if got := mustCLI(t, "counter", "--data", d.data); got["modelHTTPCalls"] != float64(0) {
		t.Fatalf("initial counter %v", got)
	}
	parked := d.mustRPC("park")
	uid, _ := parked["session"].(string)
	pending, _ := parked["pending"].(map[string]any)
	if uid == "" || pending["executionID"] == "" || pending["requestSeq"] == nil || parked["headHash"] == "" || parked["headSeq"] == nil || parked["draft"] != testDraft {
		t.Fatalf("park output: %v", parked)
	}
	info, err := os.Stat(filepath.Join(d.data, "park.json"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("park snapshot: %v %v", info, err)
	}
	if _, err = d.rpc("park"); err == nil {
		t.Fatal("park retried implicitly")
	}
	ev := d.evidence()
	if ev["realModelCalls"] != float64(1) || ev["fakeModelCalls"] != float64(0) || ev["publicationCount"] != float64(0) {
		t.Fatalf("park evidence: %v", ev)
	}
	head := d.head(uid)
	// Approval and Continue are separate explicit steps. Skipping Approve must not execute.
	if _, err = d.rpc("continue"); err == nil {
		t.Fatal("continue ran without approval proof")
	}
	if d.head(uid) != head || !reflect.DeepEqual(d.evidence(), ev) {
		t.Fatal("refused continue mutated journal or effects")
	}

	// Real host replacement over the same durable volume.
	d.stopOne()
	d.startHost()
	if got := d.mustRPC("check-parked"); !reflect.DeepEqual(got, map[string]any{"session": uid, "parked": true}) {
		t.Fatalf("check-parked: %v", got)
	}
	if d.head(uid) != head || !reflect.DeepEqual(d.evidence(), ev) {
		t.Fatal("check-parked mutated state")
	}

	// A changed expected tuple refuses before any decision is sent.
	d.rewrite("park.json", func(v map[string]any) { v["headHash"] = strings.Repeat("0", 64) })
	for _, command := range []string{"check-parked", "approve"} {
		if _, err = d.rpc(command); err == nil {
			t.Fatalf("%s accepted changed hash", command)
		}
	}
	if d.head(uid) != head || !reflect.DeepEqual(d.evidence(), ev) {
		t.Fatal("changed-state refusal mutated state")
	}
	d.rewrite("park.json", func(v map[string]any) { v["headHash"] = parked["headHash"] })

	approved := d.mustRPC("approve")
	if approved["session"] != uid || approved["approved"] != true {
		t.Fatalf("approve: %v", approved)
	}
	if _, err = d.rpc("approve"); err == nil {
		t.Fatal("second approve accepted")
	}
	afterApprove := d.evidence()
	if !reflect.DeepEqual(afterApprove, ev) || afterApprove["publicationCount"] != float64(0) {
		t.Fatalf("Approve alone changed effects: %v", afterApprove)
	}
	if _, err = d.rpc("verify"); err == nil {
		t.Fatal("verify accepted an uncompleted session")
	}
	approvedHead := d.head(uid)
	if approvedHead <= head {
		t.Fatalf("approval did not advance head: %d <= %d", approvedHead, head)
	}
	d.rewrite("approved.json", func(v map[string]any) { v["headSeq"] = float64(approvedHead - 1) })
	if _, err = d.rpc("continue"); err == nil || d.head(uid) != approvedHead {
		t.Fatalf("continue accepted stale approval proof: %v", err)
	}
	d.rewrite("approved.json", func(v map[string]any) { v["headSeq"] = float64(approvedHead) })

	completed := d.mustRPC("continue")
	artifact, _ := completed["artifact"].(string)
	if completed["session"] != uid || completed["completed"] != true || !strings.HasSuffix(artifact, ".json") {
		t.Fatalf("continue: %v", completed)
	}
	if _, err = d.rpc("continue"); err == nil {
		t.Fatal("second continue accepted")
	}
	done := d.evidence()
	arts, _ := done["artifacts"].([]any)
	if done["publicationCount"] != float64(1) || done["receiptCount"] != float64(1) || done["realModelCalls"] != float64(1) || done["fakeModelCalls"] != float64(0) || len(arts) != 1 || arts[0].(map[string]any)["name"] != artifact {
		t.Fatalf("completed evidence: %v", done)
	}

	d.stopWriters()
	mustCLI(t, "seal", "--data", d.data)
	want := map[string]any{"session": uid, "completed": true, "provider_calls": float64(0), "executor_calls": float64(0), "publicationCount": float64(1), "receiptCount": float64(1), "artifacts": float64(1), "realModelCalls": float64(1), "fakeModelCalls": float64(0), "modelHTTPCalls": float64(1), "artifact": artifact}
	got := mustCLI(t, "verify", "--data", d.data)
	if got["headSeq"] == nil || got["headHash"] == "" {
		t.Fatalf("verify omitted head: %v", got)
	}
	completedHash := got["headHash"]
	delete(got, "headSeq")
	delete(got, "headHash")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("verify:\n got %v\nwant %v", got, want)
	}
	if !reflect.DeepEqual(d.evidence(), done) {
		t.Fatal("verify changed evidence")
	}

	// Verification fails closed on a changed head or a second model HTTP attempt.
	d.rewrite("completed.json", func(v map[string]any) { v["headHash"] = strings.Repeat("1", 64) })
	if _, err = cli(t, "verify", "--data", d.data); err == nil {
		t.Fatal("verify accepted a different completed head")
	}
	d.rewrite("completed.json", func(v map[string]any) { v["headHash"] = completedHash })
	f, err := os.OpenFile(filepath.Join(d.data, "demo-model-calls.jsonl"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("{\"accepted\":true}\n")
	f.Close()
	if _, err = cli(t, "verify", "--data", d.data); err == nil || !strings.Contains(err.Error(), "HTTP attempt") {
		t.Fatalf("verify did not refuse the extra HTTP attempt for its own reason: %v", err)
	}
}

func TestPublishedReplayOnReadOnlyMount(t *testing.T) {
	if os.Getenv("DEMO_DOCKER_REPLAY") != "1" {
		t.Skip("explicit Docker integration probe; ordinary CI has no container requirement")
	}
	d := newDemo(t)
	parked := d.mustRPC("park")
	d.mustRPC("approve")
	d.mustRPC("continue")
	d.stopWriters()
	before := d.evidence()
	completed, err := readState(d.data, "completed.json")
	if err != nil {
		t.Fatal(err)
	}
	mustCLI(t, "seal", "--data", d.data)
	sealed, err := readState(d.data, "sealed.json")
	if err != nil || !reflect.DeepEqual(completed, sealed) || !reflect.DeepEqual(before, d.evidence()) {
		t.Fatalf("seal changed logical state: %v", err)
	}
	if count, err := meter(d.data); err != nil || count != 1 {
		t.Fatalf("seal changed HTTP counter: %d %v", count, err)
	}
	for _, name := range []string{"journal.db", "publications.db"} {
		for _, suffix := range []string{"-wal", "-shm"} {
			if _, err := os.Lstat(filepath.Join(d.data, name+suffix)); !os.IsNotExist(err) {
				t.Fatalf("sidecar remains: %s%s: %v", name, suffix, err)
			}
		}
	}
	uid := parked["session"].(string)
	// Derive the probe target from the single chart pin source, so a pin bump
	// cannot silently leave this test proving an older published fixture.
	rawPins, err := os.ReadFile("../../charts/aks-durable-agents/values.yaml")
	if err != nil {
		t.Fatal(err)
	}
	pinPattern := regexp.MustCompile(`(?m)^  harness:\n    repository: "(ghcr\.io/azure/aks-durable-agents/session-fixture)"\n    digest: "(sha256:[0-9a-f]{64})"$`)
	pins := pinPattern.FindAllSubmatch(rawPins, -1)
	if len(pins) != 1 {
		t.Fatal("chart image pin layout changed; refusing an ambiguous fixture target")
	}
	image := string(pins[0][1]) + "@" + string(pins[0][2])
	command := exec.CommandContext(t.Context(), "docker", "run", "--rm", "--network=none", "--read-only", "--cap-drop=ALL", "--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), "--mount", "type=bind,source="+d.data+",target=/data,readonly", image, "verify-replay", "--scenario", "v2", "--journal", "/data/journal.db", "--instructions", "/data/instructions.txt", "--session", uid)
	raw, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("published read-only replay: %v\n%s", err, raw)
	}
	var proof replay
	if err := json.Unmarshal(raw, &proof); err != nil || !proof.Completed || proof.ProviderCalls != 0 || proof.ExecutorCalls != 0 {
		t.Fatalf("invalid read-only replay: %s %v", raw, err)
	}
}

func TestParkRefusesExistingSessionAndSnapshotIsOExcl(t *testing.T) {
	d := newDemo(t)
	d.mustRPC("park")
	os.Remove(filepath.Join(d.data, "park.json"))
	if _, err := d.rpc("park"); err == nil {
		t.Fatal("park created a second session after a lost snapshot")
	}
	if _, err := os.Stat(filepath.Join(d.data, "park.json")); err == nil {
		t.Fatal("refused park wrote snapshot")
	}
	if d.evidence()["realModelCalls"] != float64(1) {
		t.Fatal("refused park invoked the model")
	}
}
