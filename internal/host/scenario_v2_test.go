//go:build scenario_v2

package host

// This qualification uses the actual separately built release-notes fixture and native
// helper, not a replacement harness/executor. No Azure credential is acquired.
import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agent-primitives/sessions/authn"
)

func TestScenarioV2ActualFixture(t *testing.T) {
	fixture, native := os.Getenv("ADA_FIXTURE_BINARY"), os.Getenv("ADA_NATIVE_BINARY")
	if !filepath.IsAbs(fixture) || !filepath.IsAbs(native) {
		t.Fatal("scenario_v2 qualification requires absolute ADA_FIXTURE_BINARY and ADA_NATIVE_BINARY")
	}
	for _, mode := range []string{"success", "429", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			data, err := os.MkdirTemp("", "real-v2-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(data)
			ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
			defer cancel()
			command := func(args ...string) map[string]any {
				t.Helper()
				cmd := exec.CommandContext(ctx, fixture, args...)
				out, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("fixture %v: %v %s", args, err, out)
				}
				var v map[string]any
				if json.Unmarshal(out, &v) != nil {
					t.Fatalf("invalid fixture JSON: %s", out)
				}
				return v
			}
			command("init", "--scenario", "v2", "--data", data, "--socket", filepath.Join(data, "publish.sock"))
			start := func(args ...string) string {
				t.Helper()
				cmd := exec.CommandContext(ctx, fixture, args...)
				stdout, err := cmd.StdoutPipe()
				if err != nil {
					t.Fatal(err)
				}
				var logs bytes.Buffer
				cmd.Stderr = &logs
				if cmd.Start() != nil {
					t.Fatal("fixture failed to start")
				}
				t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
				scanner := bufio.NewScanner(stdout)
				if !scanner.Scan() {
					t.Fatalf("no startup response: %s", &logs)
				}
				return scanner.Text()
			}
			start("executor", "--scenario", "v2", "--socket", filepath.Join(data, "publish.sock"), "--database", filepath.Join(data, "publications.db"))
			line := start("harness", "--scenario", "v2", "--addr", "127.0.0.1:0", "--instructions", filepath.Join(data, "instructions.txt"), "--node-name", "offline-node", "--pod-uid", "offline-fixture")
			var address struct {
				Addr string `json:"addr"`
			}
			if json.Unmarshal([]byte(line), &address) != nil || address.Addr == "" {
				t.Fatalf("harness address missing: %s", line)
			}
			var posts atomic.Int32
			draft := "Northwind Lantern v2.4 — 18 October 2026\n\nThis fictional release introduces faster search and CSV export. This is an offline demo only; rollout pending approval. Review these release notes before the local publication simulation."
			provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				posts.Add(1)
				var body struct {
					Max    int  `json:"max_completion_tokens"`
					Stream bool `json:"stream"`
				}
				_ = json.NewDecoder(r.Body).Decode(&body)
				if body.Max != 4096 || !body.Stream {
					t.Error("actual adapter wire request lacks host completion cap/usage stream")
				}
				if mode == "429" {
					w.WriteHeader(429)
					return
				}
				if mode == "timeout" {
					<-r.Context().Done()
					return
				}
				w.Header().Set("Content-Type", "text/event-stream")
				delta, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"delta": map[string]any{"content": draft}}}})
				fmt.Fprintf(w, "data: %s\n\ndata: {\"choices\":[],\"usage\":{\"prompt_tokens\":250,\"completion_tokens\":84,\"total_tokens\":334,\"completion_tokens_details\":{\"reasoning_tokens\":12}}}\n\ndata: [DONE]\n\n", delta)
			}))
			defer provider.Close()
			budget := map[string]any{"version": 1, "runID": "offline-qualification", "ledgerPath": filepath.Join(data, "real-attempts.db"), "deployment": "test-deployment", "pricing": map[string]any{"inputMicroUSDPerMillionTokens": 100000, "outputMicroUSDPerMillionTokens": 500000, "extraMicroUSDPerCall": 0, "source": "https://example.test/dated-test-rates", "asOf": "2026-09-22"}}
			raw, _ := json.Marshal(budget)
			policy := filepath.Join(data, "model-policy.json")
			if os.WriteFile(policy, raw, 0600) != nil {
				t.Fatal("policy write failed")
			}
			c := Config{Addr: "127.0.0.1:0", HealthAddr: "127.0.0.1:0", Journal: filepath.Join(data, "journal.db"), Mode: authn.Off, Harnesses: map[string]string{"release-notes": address.Addr}, ToolExecutors: filepath.Join(data, "tools.json"), ModelEndpoint: provider.URL + "/openai/v1/", Deployment: "test-deployment", ModelScope: fixtureScope, ModelTransport: provider.Client().Transport.(*http.Transport), ModelPolicy: policy, PeerNodeFile: filepath.Join(data, "fixture-node.json"), NodeName: "offline-node"}
			app, err := newApplication(ctx, c, fixtureCredential{t}, slog.New(slog.NewTextHandler(io.Discard, nil)))
			if err != nil {
				t.Fatal(err)
			}
			defer app.Close()
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			go app.sessions.Serve(listener)
			if mode == "success" {
				// Feed the real CLI's empty-ledger JSON through the actual JS
				// reviewer before any proposal, not a hand-built evidence stub.
				baseline := command("evidence", "--scenario", "v2", "--data", data)
				wire, _ := json.Marshal(baseline)
				module := filepath.Clean(filepath.Join(filepath.Dir(native), "..", "..", "sessions.mjs"))
				script := `import {pathToFileURL} from 'node:url';
let raw=''; for await(const part of process.stdin) raw+=part;
const {createSessionsRuntime}=await import(pathToFileURL(process.argv[1]).href);
const review=await createSessionsRuntime({directory:process.argv[2],server:process.argv[3],rpcBinary:process.argv[4],scenario:'v2',operations:{evidence:async()=>JSON.parse(raw)}});
const state=await review.state(); if(state.realModelCalls!==0||state.fakeModelCalls!==0||!Array.isArray(state.realAttempts)||state.realAttempts.length!==0)throw Error('actual baseline evidence rejected'); await review.close();`
				node := exec.CommandContext(ctx, "node", "--input-type=module", "-e", script, module, filepath.Join(data, "reviewer"), listener.Addr().String(), native)
				node.Stdin = bytes.NewReader(wire)
				if output, err := node.CombinedOutput(); err != nil {
					t.Fatalf("actual fixture evidence / JS bridge contract: %v %s", err, output)
				}
			}
			rpc := func(input map[string]any) (map[string]any, error) {
				t.Helper()
				input["server"] = listener.Addr().String()
				raw, _ := json.Marshal(input)
				cmd := exec.CommandContext(ctx, native)
				cmd.Stdin = bytes.NewReader(raw)
				var out, stderr bytes.Buffer
				cmd.Stdout = &out
				cmd.Stderr = &stderr
				err := cmd.Run()
				if err != nil {
					return nil, fmt.Errorf("native: %w %s", err, &stderr)
				}
				var result map[string]any
				err = json.Unmarshal(out.Bytes(), &result)
				return result, err
			}
			created, err := rpc(map[string]any{"command": "create"})
			if err != nil {
				t.Fatal(err)
			}
			uid := created["metadata"].(map[string]any)["uid"].(string)
			// Exercise the actual 25s model deadline inside the 30s helper / 35s
			// bridge envelope. A missing response is never retried or auto-Resumed.
			started := time.Now()
			proposed, err := rpc(map[string]any{"command": "exec", "session": uid, "headSeq": 0, "input": "Write a fictional proposal."})
			if mode == "timeout" && (time.Since(started) < 24*time.Second || time.Since(started) > 29*time.Second) {
				t.Fatalf("model timeout outside expected envelope: %s", time.Since(started))
			}
			if mode != "success" {
				if err == nil {
					t.Fatal("failed model returned success")
				}
				if posts.Load() != 1 {
					t.Fatalf("expected one POST, got %d", posts.Load())
				}
				failed := command("evidence", "--scenario", "v2", "--data", data)
				attempts := failed["realAttempts"].([]any)
				if len(attempts) != 1 {
					t.Fatalf("failed-call ledger: %+v", failed)
				}
				attempt := attempts[0].(map[string]any)
				want := "failed"
				if mode == "timeout" {
					want = "unknown"
				}
				if attempt["outcome"] != want || attempt["inputTokens"] != nil || attempt["outputTokens"] != nil {
					t.Fatalf("failure outcome/usage fabricated: %+v", attempt)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			before := command("evidence", "--scenario", "v2", "--data", data)
			if before["realModelCalls"] != float64(1) || before["publicationCount"] != float64(0) {
				t.Fatalf("proposal effects: %+v", before)
			}
			attempt := before["realAttempts"].([]any)[0].(map[string]any)
			if attempt["outcome"] != "succeeded" || attempt["inputTokens"] != float64(250) || attempt["outputTokens"] != float64(84) || attempt["reasoningTokens"] != float64(12) {
				t.Fatalf("provider response usage not recorded: %+v", attempt)
			}
			session := proposed["session"].(map[string]any)
			journal := proposed["journal"].([]any)
			last := journal[len(journal)-1].(map[string]any)
			pending := session["pendingApproval"].(map[string]any)
			seq := pending["requestSeq"]
			if value, ok := seq.(string); ok {
				var n int
				fmt.Sscan(value, &n)
				pending["requestSeq"] = n
			}
			decided, err := rpc(map[string]any{"command": "decide", "session": uid, "headSeq": jsonNumber(session["lastSeq"]), "headHash": last["contentHash"], "pending": pending, "approved": true})
			if err != nil {
				t.Fatal(err)
			}
			afterApprove := command("evidence", "--scenario", "v2", "--data", data)
			if !reflect.DeepEqual(before, afterApprove) {
				t.Fatal("Approve-only mutated model ledger or publication inventory")
			}
			_ = decided
			inspected, err := rpc(map[string]any{"command": "inspect", "session": uid})
			if err != nil {
				t.Fatal(err)
			}
			session = inspected["session"].(map[string]any)
			journal = inspected["journal"].([]any)
			last = journal[len(journal)-1].(map[string]any)
			if _, err = rpc(map[string]any{"command": "resume", "session": uid, "headSeq": jsonNumber(session["lastSeq"]), "headHash": last["contentHash"]}); err != nil {
				t.Fatal(err)
			}
			published := command("evidence", "--scenario", "v2", "--data", data)
			if published["publicationCount"] != float64(1) || published["receiptCount"] != float64(1) || posts.Load() != 1 {
				t.Fatalf("publication counts %+v posts%d", published, posts.Load())
			}
			proof := command("verify-replay", "--scenario", "v2", "--journal", c.Journal, "--instructions", filepath.Join(data, "instructions.txt"), "--session", uid)
			if proof["completed"] != true || proof["provider_calls"] != float64(0) || proof["executor_calls"] != float64(0) {
				t.Fatalf("replay proof %+v", proof)
			}
			if got := command("evidence", "--scenario", "v2", "--data", data); !reflect.DeepEqual(published, got) || posts.Load() != 1 {
				t.Fatal("replay changed ledger/effects or called model")
			}
		})
	}
}
func jsonNumber(value any) int64 {
	switch v := value.(type) {
	case float64:
		return int64(v)
	case string:
		var n int64
		fmt.Sscan(v, &n)
		return n
	default:
		return -1
	}
}
