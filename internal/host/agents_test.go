package host

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Azure/aks-durable-agents/internal/agentcontroller"
	"github.com/Azure/aks-durable-agents/modeltransport"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/agent-primitives/sessions/authn"
	"k8s.io/apimachinery/pkg/watch"
)

// Catches binding wire-format drift between ordinary hosting and preparation.
func TestAgentBindingSharedSerialization(t *testing.T) {
	c := agentHostConfig(t)
	c.ModelEndpoint = "https://model.example/?a=1&b=<value>\u2028"
	p, err := modeltransport.OpenPolicyFile(c.ModelPolicy)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	for _, scope := range []string{"", modeltransport.DefaultScope, "https://custom.example/.default"} {
		c.ModelScope = scope
		effective := scope
		if effective == "" {
			effective = modeltransport.DefaultScope
		}
		binding := agentcontroller.NativeBinding{Endpoint: c.ModelEndpoint, Deployment: c.Deployment, Scope: effective, Policy: p.Snapshot(), RunnerABI: agentcontroller.RunnerABI}
		got, err := binding.JSON()
		if err != nil {
			t.Fatal(err)
		}
		want, err := json.Marshal(struct {
			Endpoint, Deployment, Scope string
			Policy                      json.RawMessage
			RunnerABI                   string
		}{c.ModelEndpoint, c.Deployment, effective, p.Snapshot(), agentcontroller.RunnerABI})
		if err != nil || !bytes.Equal(got, want) || !bytes.Equal(got, agentBinding(c, p)) {
			t.Fatalf("binding wire-format mismatch: %v", err)
		}
	}
}

type agentNoCredential struct{ t *testing.T }

func (c agentNoCredential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	c.t.Error("agent startup/reconciliation requested model credentials")
	return azcore.AccessToken{}, errors.New("unexpected model credential request")
}

type emptyAgentSource struct {
	lists   atomic.Int32
	watcher *watch.RaceFreeFakeWatcher
	err     error
}

func (s *emptyAgentSource) List(context.Context) ([]agentcontroller.Agent, string, error) {
	s.lists.Add(1)
	return nil, "1", s.err
}
func (*emptyAgentSource) Get(context.Context, string) (agentcontroller.Agent, error) {
	return agentcontroller.Agent{}, errors.New("unexpected Get")
}
func (*emptyAgentSource) UpdateStatus(context.Context, agentcontroller.Agent, agentcontroller.Status) error {
	return errors.New("unexpected status update")
}
func (s *emptyAgentSource) Watch(context.Context, string) (watch.Interface, error) {
	return s.watcher, nil
}

type agentRegistryTransport struct{ calls atomic.Int32 }

func (r *agentRegistryTransport) RoundTrip(*http.Request) (*http.Response, error) {
	r.calls.Add(1)
	return nil, errors.New("unexpected registry request")
}

func agentHostConfig(t *testing.T) Config {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "policy.json")
	raw := fmt.Sprintf(`{"version":1,"runID":"agent-test","ledgerPath":%q,"deployment":"test-deployment","pricing":{"inputMicroUSDPerMillionTokens":100000,"outputMicroUSDPerMillionTokens":500000,"extraMicroUSDPerCall":0,"source":"https://example.invalid/prices","asOf":"2026-10-19"}}`, filepath.Join(dir, "budget.db"))
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	return Config{Addr: "127.0.0.1:0", HealthAddr: "127.0.0.1:0", Journal: filepath.Join(dir, "journal.db"), Mode: authn.Off,
		Harnesses: map[string]string{"static": "127.0.0.1:1"}, ModelEndpoint: "https://model.example/openai/v1/", Deployment: "test-deployment", ModelPolicy: path,
		Agents: AgentConfig{Namespace: "agents", Repositories: []string{"registry.example/agents"}}}
}

func TestAgentConfigBoundary(t *testing.T) {
	good := agentHostConfig(t)
	if err := good.validate(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*Config)
	}{
		{"namespace", func(c *Config) { c.Agents.Namespace = "Invalid" }},
		{"partial repository", func(c *Config) { c.Agents.Namespace = "" }},
		{"journal URI", func(c *Config) { c.Journal = "file:/data/journal.db" }},
		{"journal escape", func(c *Config) { c.Journal = "/data/journal%23.db" }},
		{"partial credentials", func(c *Config) { c.Agents = AgentConfig{CredentialsFile: "missing"} }},
		{"partial HTTP", func(c *Config) { c.Agents = AgentConfig{HTTPRegistry: "registry.example"} }},
		{"partial source", func(c *Config) { c.Agents = AgentConfig{Source: &emptyAgentSource{}} }},
		{"partial transport", func(c *Config) { c.Agents = AgentConfig{RegistryTransport: &agentRegistryTransport{}} }},
		{"memory", func(c *Config) { c.Journal = ":memory:" }},
		{"memory URI", func(c *Config) { c.Journal = "file::memory:?cache=shared" }},
		{"memory DSN", func(c *Config) { c.Journal = "journal?mode=memory" }},
		{"policy", func(c *Config) { c.ModelPolicy = "" }},
		{"substrate", func(c *Config) { c.Substrate = &SubstrateConfig{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := good
			tc.change(&c)
			if err := c.validate(); err == nil {
				t.Fatal("unsafe agent config accepted")
			}
		})
	}
}

func TestAgentAssemblyEmptySourceAndDisabledStatic(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			c := agentHostConfig(t)
			source := &emptyAgentSource{watcher: watch.NewRaceFreeFake()}
			transport := &agentRegistryTransport{}
			if enabled {
				c.Agents.Source = source
				c.Agents.RegistryTransport = transport
			} else {
				c.Agents = AgentConfig{}
			}
			app, err := newApplication(t.Context(), c, agentNoCredential{t}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer app.Close()
			if (app.agents != nil) != enabled || (source.lists.Load() > 0) != enabled {
				t.Fatal("controller activation mismatch")
			}
			if transport.calls.Load() != 0 {
				t.Fatal("empty source caused registry traffic")
			}
			if _, err := os.Stat(c.Journal + ".agents"); (err == nil) != enabled {
				t.Fatalf("runtime state activation: %v", err)
			}
			app.Close()
			app.Close()
			if enabled && !source.watcher.IsStopped() {
				t.Fatal("watch not joined/stopped")
			}
			// Closing must release both the retained-directory lock and policy ledger.
			if enabled {
				c.Agents.Source = &emptyAgentSource{watcher: watch.NewRaceFreeFake()}
			}
			app, err = newApplication(t.Context(), c, agentNoCredential{t}, nil)
			if err != nil {
				t.Fatalf("reopen: %v", err)
			}
			app.Close()
		})
	}
}

func TestAgentStartupAPIErrorFailsClosedAndReleasesState(t *testing.T) {
	c := agentHostConfig(t)
	c.Agents.Source = &emptyAgentSource{err: errors.New("API unavailable")}
	if app, err := newApplication(t.Context(), c, agentNoCredential{t}, nil); err == nil || app != nil {
		if app != nil {
			app.Close()
		}
		t.Fatal("unreadable API admitted host")
	}
	c.Agents.Source = &emptyAgentSource{watcher: watch.NewRaceFreeFake()}
	app, err := newApplication(t.Context(), c, agentNoCredential{t}, nil)
	if err != nil {
		t.Fatalf("failed startup leaked resources: %v", err)
	}
	app.Close()
}

func TestAgentRegistryPolicyAndCredentialFileBoundary(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		change    func(*Config)
	}{
		{"unscoped", `{"other.example/private":{"Password":"private-secret"}}`, nil},
		{"refresh", `{"registry.example/agents":{"RefreshToken":"private-secret"}}`, nil},
		{"plaintext", `{"registry.example/agents":{"Username":"user","Password":"private-secret"}}`, func(c *Config) { c.Agents.HTTPRegistry = "registry.example" }},
		{"unknown field", `{"registry.example/agents":{"Secret":"private-secret"}}`, nil},
		{"trailing", `{} {}`, nil},
		{"malformed", `{"private-secret"`, nil},
		{"oversized", strings.Repeat("x", (1<<20)+1), nil},
		{"missing file", "", func(c *Config) { c.Agents.CredentialsFile = "/does-not-exist/private-secret" }},
		{"missing repositories", `{}`, func(c *Config) { c.Agents.Repositories = nil }},
		{"repository URL", `{}`, func(c *Config) { c.Agents.Repositories = []string{"https://private-secret@registry.example/agents"} }},
		{"HTTP scope", `{}`, func(c *Config) { c.Agents.HTTPRegistry = "other.example" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := agentHostConfig(t)
			c.Agents.CredentialsFile = filepath.Join(t.TempDir(), "credentials.json")
			if err := os.WriteFile(c.Agents.CredentialsFile, []byte(tc.raw), 0600); err != nil {
				t.Fatal(err)
			}
			if tc.change != nil {
				tc.change(&c)
			}
			if _, err := startAgentController(t.Context(), c, nil, nil, nil, nil, nil); err == nil || strings.Contains(err.Error(), "private-secret") {
				t.Fatalf("unsafe config or error: %v", err)
			}
		})
	}
	// Explicit repository credentials are accepted without accessing ambient stores.
	c := agentHostConfig(t)
	c.Agents.CredentialsFile = filepath.Join(t.TempDir(), "credentials.json")
	if err := os.WriteFile(c.Agents.CredentialsFile, []byte(`{"registry.example/agents":{"Username":"user","Password":"private-secret"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	c.Agents.Source = &emptyAgentSource{watcher: watch.NewRaceFreeFake()}
	transport := &agentRegistryTransport{}
	c.Agents.RegistryTransport = transport
	t.Setenv("DOCKER_CONFIG", "/does-not-exist")
	app, err := newApplication(t.Context(), c, agentNoCredential{t}, nil)
	if err != nil {
		t.Fatal(err)
	}
	app.Close()
	if transport.calls.Load() != 0 {
		t.Fatal("startup requested registry")
	}
}

func TestAgentBindingEffectiveScopeAndPolicyRestart(t *testing.T) {
	c := agentHostConfig(t)
	p, err := modeltransport.OpenPolicyFile(c.ModelPolicy)
	if err != nil {
		t.Fatal(err)
	}
	before := agentBinding(c, p)
	var frozen frozenAgentBinding
	if err := json.Unmarshal(before, &frozen); err != nil || frozen.RunnerABI != agentcontroller.RunnerABI || !bytes.Equal(frozen.Policy, p.Snapshot()) {
		t.Fatalf("binding omitted policy fields or runner ABI: %s %v", before, err)
	}
	explicit := c
	explicit.ModelScope = modeltransport.DefaultScope
	if !bytes.Equal(before, agentBinding(explicit, p)) {
		t.Fatal("empty and default scope differ")
	}
	rotated := c
	rotated.Agents.CredentialsFile = "rotated"
	rotated.Agents.RegistryTransport = &agentRegistryTransport{}
	rotated.ModelCredential = agentNoCredential{t}
	rotated.ModelTransport = http.DefaultTransport.(*http.Transport).Clone()
	if !bytes.Equal(before, agentBinding(rotated, p)) {
		t.Fatal("secret/transport rotation changed binding")
	}
	for _, change := range []func(*Config){func(c *Config) { c.Deployment = "changed" }, func(c *Config) { c.ModelScope = "https://different.example/.default" }, func(c *Config) { c.ModelEndpoint = "https://other.example/openai/v1/" }} {
		changed := c
		change(&changed)
		if bytes.Equal(before, agentBinding(changed, p)) {
			t.Fatal("effective model change did not drift")
		}
	}
	p.Close()
	// Reformatting the same policy is not a semantic change.
	raw, err := os.ReadFile(c.ModelPolicy)
	if err != nil {
		t.Fatal(err)
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, raw, "", "  "); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.ModelPolicy, pretty.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	p, err = modeltransport.OpenPolicyFile(c.ModelPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, agentBinding(c, p)) {
		t.Fatal("same parsed policy changed on restart")
	}
	p.Close()
	for _, field := range []string{"runID", "ledgerPath", "pricing", "limits"} {
		t.Run(field, func(t *testing.T) {
			var policy map[string]any
			if err := json.Unmarshal(raw, &policy); err != nil {
				t.Fatal(err)
			}
			ledger := filepath.Join(t.TempDir(), "private", "policy.db")
			policy["ledgerPath"] = ledger
			baselineData, _ := json.Marshal(policy)
			if err := os.WriteFile(c.ModelPolicy, baselineData, 0600); err != nil {
				t.Fatal(err)
			}
			baselinePolicy, err := modeltransport.OpenPolicyFile(c.ModelPolicy)
			if err != nil {
				t.Fatal(err)
			}
			baseline := agentBinding(c, baselinePolicy)
			baselinePolicy.Close()
			// Preserve the baseline DB but free the same path for this binding-only
			// comparison; the budget ledger independently rejects snapshot drift.
			if err := os.Rename(ledger, ledger+".baseline"); err != nil {
				t.Fatal(err)
			}
			switch field {
			case "runID":
				policy["runID"] = "changed"
			case "ledgerPath":
				policy["ledgerPath"] = filepath.Join(filepath.Dir(ledger), "changed.db")
			case "pricing":
				policy["pricing"].(map[string]any)["asOf"] = "2026-10-20"
			case "limits":
				policy["maxInputTokens"] = 32768
			}
			data, _ := json.Marshal(policy)
			if err := os.WriteFile(c.ModelPolicy, data, 0600); err != nil {
				t.Fatal(err)
			}
			p, err := modeltransport.OpenPolicyFile(c.ModelPolicy)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			if bytes.Equal(baseline, agentBinding(c, p)) {
				t.Fatal("isolated policy change did not drift")
			}
		})
	}
}
