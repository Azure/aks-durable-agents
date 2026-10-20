package demohost

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Azure/aks-durable-agents/modeltransport"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

func arguments(t *testing.T) []string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return []string{"--auth-mode=off", "--journal=" + filepath.Join(dir, "journal.db"), "--harness-service=demo-harness:9000", "--harness=release-notes=demo-harness:9000", "--tool-executors=/config/executors.json", "--model-policy=/config/model-policy.json", "--model-base-url=https://fake-model.invalid/openai/v1/", "--model=demo-model", "--model-scope=" + modeltransport.DefaultScope}
}

func TestRejectsNonDemoAuthority(t *testing.T) {
	for _, override := range []string{"--auth-mode=required", "--addr=0.0.0.0:8080", "--health-addr=0.0.0.0:8081", "--model=live-model", "--model-base-url=https://example.com/openai/v1/", "--model-scope=https://example.com/.default", "--credential=file", "--tenant-id=tenant"} {
		t.Run(override, func(t *testing.T) {
			_, closeServer, err := Config(append(arguments(t), override))
			if closeServer != nil {
				closeServer()
			}
			if err == nil {
				t.Fatal("non-demo configuration accepted")
			}
		})
	}
}

func TestScopedCredentialAndRealTLSResponse(t *testing.T) {
	c, closeServer, err := Config(arguments(t))
	if err != nil {
		t.Fatal(err)
	}
	defer closeServer()
	if _, err := c.ModelCredential.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{"https://example.com/.default"}}); err == nil {
		t.Fatal("off-scope credential accepted")
	}
	token, err := c.ModelCredential.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{modeltransport.DefaultScope}})
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("POST", c.ModelEndpoint+"chat/completions", strings.NewReader(`{"model":"demo-model","max_completion_tokens":4096,"stream":true}`))
	req.Header.Set("Authorization", "Bearer "+token.Token)
	response, err := c.ModelTransport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != 200 || !strings.Contains(string(raw), "offline demo only") || !strings.Contains(string(raw), "data: [DONE]") {
		t.Fatalf("invalid fake completion: %d %s %v", response.StatusCode, raw, err)
	}
	meter, err := os.ReadFile(filepath.Join(filepath.Dir(c.Journal), "demo-model-calls.jsonl"))
	if err != nil || string(meter) != "{\"accepted\":true}\n" {
		t.Fatalf("HTTP attempt not durably recorded: %s %v", meter, err)
	}
}

func TestInvalidRequestIsCountedAndOffPinIsNotDialed(t *testing.T) {
	c, closeServer, err := Config(arguments(t))
	if err != nil {
		t.Fatal(err)
	}
	defer closeServer()
	req, _ := http.NewRequest("POST", c.ModelEndpoint+"chat/completions", strings.NewReader(`{"model":"demo-model","max_completion_tokens":4096,"stream":true}`))
	response, err := c.ModelTransport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing fake token accepted: %d", response.StatusCode)
	}
	req, _ = http.NewRequest("GET", "https://not-the-fake.invalid/", nil)
	if response, err = c.ModelTransport.RoundTrip(req); err == nil {
		response.Body.Close()
		t.Fatal("off-pin request was allowed")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(c.Journal), "demo-model-calls.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var event struct {
		Accepted bool `json:"accepted"`
	}
	if err := json.Unmarshal(raw, &event); err != nil || event.Accepted || strings.Count(string(raw), "\n") != 1 {
		t.Fatalf("invalid attempt meter: %s %v", raw, err)
	}
}

func TestMeterSymlinkIsRefusedWithoutTouchingTarget(t *testing.T) {
	c, closeServer, err := Config(arguments(t))
	if err != nil {
		t.Fatal(err)
	}
	defer closeServer()
	target := filepath.Join(t.TempDir(), "untouched")
	if err := os.WriteFile(target, []byte("sentinel"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(filepath.Dir(c.Journal), "demo-model-calls.jsonl")); err != nil {
		t.Fatal(err)
	}
	token, err := c.ModelCredential.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{modeltransport.DefaultScope}})
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("POST", c.ModelEndpoint+"chat/completions", strings.NewReader(`{"model":"demo-model","max_completion_tokens":4096,"stream":true}`))
	req.Header.Set("Authorization", "Bearer "+token.Token)
	response, err := c.ModelTransport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 500 {
		t.Fatalf("unsafe meter path accepted: %d", response.StatusCode)
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != "sentinel" {
		t.Fatalf("symlink target mutated: %s %v", got, err)
	}
}
