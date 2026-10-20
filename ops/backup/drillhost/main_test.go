package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Azure/aks-durable-agents/internal/host"
	"github.com/Azure/aks-durable-agents/modeltransport"
	"github.com/agent-primitives/sessions/authn"
)

func chartArgs(policy string) []string {
	return []string{
		"-addr=127.0.0.1:8080", "-health-addr=127.0.0.1:8081",
		"-harness-service=fixture.agents.svc.cluster.local:9000",
		"-harness=release-notes=fixture.agents.svc.cluster.local:9000",
		"-peer-node-file=/data/fixture-node.json", "-node-name=kind-worker",
		"-model-policy=" + policy, "-auth-mode=off", "-journal=/data/journal.db",
		"-tool-executors=/data/tools.json", "-model=test-deployment",
		"-model-base-url=https://offline-model.invalid/openai/v1/",
		"-model-scope=https://ai.azure.com/.default",
	}
}

// A missing chart flag, unexpected cloud credential, or external dial breaks this test.
func TestDrillHostChartFlagsRouteFakeProviderLocally(t *testing.T) {
	t.Setenv("AZURE_CLIENT_ID", "")
	t.Setenv("AZURE_TENANT_ID", "")
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", "")
	c, closeProvider, err := newDrillConfig(chartArgs("/config/model-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer closeProvider()
	if c.Mode != authn.Off || c.Harnesses["release-notes"] != c.HarnessService ||
		c.ModelEndpoint != "https://offline-model.invalid/openai/v1/" || c.ModelScope != modeltransport.DefaultScope ||
		c.ModelPolicy != "/config/model-policy.json" || c.PeerNodeFile != "/data/fixture-node.json" ||
		c.NodeName != "kind-worker" || c.ToolExecutors != "/data/tools.json" || c.ModelCredential == nil || c.ModelTransport == nil {
		t.Fatalf("chart inputs or fake model injection missing: %+v", c)
	}
	client, err := modeltransport.NewClient(modeltransport.Config{Endpoint: c.ModelEndpoint, Deployment: c.Deployment, Scope: c.ModelScope, Credential: c.ModelCredential, Transport: c.ModelTransport})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	body := `{"model":"test-deployment","stream":true,"max_completion_tokens":4096,"messages":[{"role":"user","content":"draft"}]}`
	request, err := http.NewRequest(http.MethodPost, c.ModelEndpoint+"chat/completions", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	wire, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || !strings.Contains(string(wire), "Northwind Lantern v2.4") ||
		!strings.Contains(string(wire), `"prompt_tokens":250`) || !strings.Contains(string(wire), "data: [DONE]") {
		t.Fatalf("not the v2 fake model SSE response: %d %s", response.StatusCode, wire)
	}
}

func TestDrillHostRejectsUnsafeInputs(t *testing.T) {
	for _, args := range [][]string{
		append(chartArgs("/config/model-policy.json"), "-model-credential=bad"),
		append(chartArgs("/config/model-policy.json"), "-auth-config=/auth/auth.json"),
		append(chartArgs("/config/model-policy.json"), "-auth-mode=required"),
		append(chartArgs("/config/model-policy.json"), "-tls-key=/tls/tls.key"),
		append(chartArgs("/config/model-policy.json"), "unexpected"),
	} {
		if _, closeProvider, err := newDrillConfig(args); err == nil {
			closeProvider()
			t.Fatalf("accepted unsupported drillhost input %v", args)
		}
	}
}

// Run must receive the injected credential, not silently fall back to Azure.
func TestDrillHostRunsWithoutCloudCredential(t *testing.T) {
	t.Setenv("AZURE_CLIENT_ID", "")
	t.Setenv("AZURE_TENANT_ID", "")
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", "")
	data := t.TempDir()
	if err := os.Chmod(data, 0700); err != nil {
		t.Fatal(err)
	}
	policy := filepath.Join(data, "policy.json")
	raw := fmt.Sprintf(`{"version":1,"runID":"offline-drill","ledgerPath":%q,"deployment":"test-deployment","pricing":{"inputMicroUSDPerMillionTokens":100000,"outputMicroUSDPerMillionTokens":500000,"extraMicroUSDPerCall":0,"source":"https://example.invalid/dated-test-rates","asOf":"2026-09-22"}}`, filepath.Join(data, "attempts.db"))
	if err := os.WriteFile(policy, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	c, closeProvider, err := newDrillConfig([]string{
		"-addr=127.0.0.1:0", "-health-addr=127.0.0.1:0", "-harness=release-notes=127.0.0.1:9000",
		"-model-policy=" + policy, "-auth-mode=off", "-journal=" + filepath.Join(data, "journal.db"),
		"-model=test-deployment", "-model-base-url=https://offline-model.invalid/openai/v1/",
		"-model-scope=https://ai.azure.com/.default",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer closeProvider()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- host.Run(ctx, c, slog.New(slog.DiscardHandler)) }()
	select {
	case err := <-done:
		t.Fatalf("host stopped before cancellation (cloud fallback or bad assembly): %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(12 * time.Second):
		t.Fatal("drill host did not stop after cancellation")
	}
}
