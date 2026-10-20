package main

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Azure/aks-durable-agents/modeltransport"
)

func fixtureInputs(t *testing.T) ([]string, string, string) {
	t.Helper()
	raw, err := os.ReadFile("../../../charts/aks-durable-agents/tests/native-host-args.json")
	if err != nil {
		t.Fatal(err)
	}
	var args []string
	if err = json.Unmarshal(raw, &args); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	for i, arg := range args {
		if strings.HasPrefix(arg, "-journal=") {
			args[i] = "-journal=" + filepath.Join(root, "journal.db")
		}
	}
	assets := t.TempDir()
	for _, kind := range []string{"writer", "reviewer"} {
		if err = os.WriteFile(filepath.Join(assets, kind+".json"), []byte(`{"changes":[{"document":"announcement","operation":"replace","content":"`+kind+`"}]}`), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return args, assets, root
}

func TestNativeFakeUsesTLSCapSchemaAndPersistentHTTPLedger(t *testing.T) {
	args, assets, root := fixtureInputs(t)
	for _, kind := range []string{"writer", "reviewer"} {
		c, closeFake, err := newDrillConfig(args, assets)
		if err != nil {
			t.Fatal(err)
		}
		if c.ModelCredential == nil || c.ModelTransport == nil || len(c.Harnesses) != 2 || c.HarnessService == "" || len(c.HarnessServices) != 1 || c.ToolExecutors != "" {
			t.Fatalf("native chart mapping lost: %+v", c)
		}
		client, err := modeltransport.NewClient(modeltransport.Config{Endpoint: c.ModelEndpoint, Deployment: c.Deployment, Scope: c.ModelScope, Credential: c.ModelCredential, Transport: c.ModelTransport})
		if err != nil {
			t.Fatal(err)
		}
		prompt := "canvas-kind-" + kind
		if kind == "reviewer" {
			prompt = `{"request":"canvas-kind-reviewer","documents":{"announcement":{"path":"announcement.md"}},"evidence":{"announcement.md":"writer"}}`
		}
		encoded, _ := json.Marshal(prompt)
		body := `{"model":"test-deployment","stream":true,"max_completion_tokens":4096,"response_format":{"type":"json_schema","json_schema":{"strict":true}},"messages":[{"role":"user","content":` + string(encoded) + `}]}`
		req, err := http.NewRequest(http.MethodPost, c.ModelEndpoint+"chat/completions", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		client.CloseIdleConnections()
		closeFake()
		if response.StatusCode != 200 || !strings.Contains(string(wire), kind) || !strings.Contains(string(wire), `"finish_reason":"stop"`) || !strings.Contains(string(wire), "data: [DONE]") {
			t.Fatalf("not complete fake response: %d %s", response.StatusCode, wire)
		}
	}
	raw, err := os.ReadFile(filepath.Join(root, "fake-http.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 2 {
		t.Fatalf("lost independent HTTP history: %s", raw)
	}
	for i, line := range lines {
		var event map[string]any
		if err = json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatal(err)
		}
		if event["valid"] != true || event["completionCap"] != float64(4096) {
			t.Fatalf("invalid HTTP observation %d: %v", i, event)
		}
	}
	credentialHistory, err := os.ReadFile(filepath.Join(root, "fake-credential.jsonl"))
	if err != nil || len(strings.Split(strings.TrimSpace(string(credentialHistory)), "\n")) != 2 {
		t.Fatalf("lost independent durable credential count: %v %s", err, credentialHistory)
	}
	if strings.Contains(string(raw), "canvas-kind-") || strings.Contains(string(raw), "Bearer") {
		t.Fatal("HTTP evidence captured prompt or credential")
	}
}

func TestReviewerCannotPassWithoutExactAcceptedDocument(t *testing.T) {
	args, assets, _ := fixtureInputs(t)
	c, cleanup, err := newDrillConfig(args, assets)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	client, err := modeltransport.NewClient(modeltransport.Config{Endpoint: c.ModelEndpoint, Deployment: c.Deployment, Scope: c.ModelScope, Credential: c.ModelCredential, Transport: c.ModelTransport})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	for _, prompt := range []string{
		`{"request":"canvas-kind-reviewer"}`,
		`{"request":"canvas-kind-reviewer","documents":{"announcement":{"path":"announcement.md"}},"evidence":{"announcement.md":"changed writer"}}`,
		`{"request":"canvas-kind-reviewer","documents":{"announcement":{"path":"announcement.md"}},"evidence":{"other.md":"writer"}}`,
	} {
		text, _ := json.Marshal(prompt)
		body := `{"model":"test-deployment","max_completion_tokens":4096,"response_format":{"type":"json_schema","json_schema":{"strict":true}},"messages":[{"role":"user","content":` + string(text) + `}]}`
		req, _ := http.NewRequest("POST", c.ModelEndpoint+"chat/completions", strings.NewReader(body))
		r, err := client.Do(req)
		if r != nil {
			r.Body.Close()
		}
		if err == nil || !strings.Contains(err.Error(), "provider returned HTTP 400") {
			t.Fatalf("reviewer admitted without exact accepted bytes: %v", err)
		}
	}
}

func TestNativeDrillRejectsCredentialAndIdentityFlags(t *testing.T) {
	args, assets, _ := fixtureInputs(t)
	for _, extra := range []string{"-model-credential=injected", "-auth-config=/auth/auth.json", "-auth-mode=required", "-tls-key=/key", "unexpected"} {
		if _, closeFake, err := newDrillConfig(append(append([]string{}, args...), extra), assets); err == nil {
			closeFake()
			t.Fatalf("unsafe drill flag admitted: %s", extra)
		}
	}
}
