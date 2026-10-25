package host

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/Azure/aks-durable-agents/internal/agentcontroller"
	"github.com/Azure/aks-durable-agents/internal/agentpackage"
	"github.com/Azure/aks-durable-agents/modeltransport"
	"github.com/agent-primitives/sessions/controller"
	"github.com/agent-primitives/sessions/placement"
	"github.com/agent-primitives/sessions/sqlitelog"
	"k8s.io/apimachinery/pkg/util/validation"
	"oras.land/oras-go/v2/registry/remote/auth"
)

// AgentConfig opts into namespace-scoped Agents; zero preserves static hosting.
type AgentConfig struct {
	Namespace, HTTPRegistry, CredentialsFile string
	Repositories                             []string
	// Trusted in-process boundary injectors, never CLI or resource input.
	Source            agentcontroller.Source `json:"-"`
	RegistryTransport http.RoundTripper      `json:"-"`
}

func (c Config) validateAgents() error {
	a := c.Agents
	if a.Namespace == "" {
		if len(a.Repositories) != 0 || a.HTTPRegistry != "" || a.CredentialsFile != "" || a.Source != nil || a.RegistryTransport != nil {
			return errors.New("agent options require agents namespace")
		}
		return nil
	}
	if len(validation.IsDNS1123Label(a.Namespace)) != 0 {
		return errors.New("invalid agents namespace")
	}
	if c.Substrate != nil {
		return errors.New("agents cannot be combined with Substrate")
	}
	// The state root is journal+".agents"; reject SQLite URI/DSN aliases.
	if c.Journal == "" || c.Journal == ":memory:" || strings.HasPrefix(c.Journal, "file:") || strings.ContainsAny(c.Journal, "?#%") {
		return errors.New("agents require a durable plain journal file path")
	}
	if c.ModelPolicy == "" {
		return errors.New("agents require explicit model policy")
	}
	return nil
}

type frozenAgentBinding struct {
	Endpoint, Deployment, Scope string
	Policy                      json.RawMessage
	RunnerABI                   string
}

func agentBinding(c Config, policy *modeltransport.Policy) []byte {
	scope := c.ModelScope
	if scope == "" {
		scope = modeltransport.DefaultScope
	}
	data, _ := json.Marshal(frozenAgentBinding{c.ModelEndpoint, c.Deployment, scope, policy.Snapshot(), agentcontroller.RunnerABI})
	return data
}

func startAgentController(ctx context.Context, c Config, policy *modeltransport.Policy, store *sqlitelog.Store, registry *placement.Registry, model controller.ModelFunc, stream controller.StreamFunc) (*agentcontroller.Controller, error) {
	if c.Agents.Namespace == "" {
		return nil, nil
	}
	credentials := make(map[string]auth.Credential)
	if c.Agents.CredentialsFile != "" {
		f, err := os.Open(c.Agents.CredentialsFile)
		if err != nil {
			return nil, errors.New("agent credentials file unavailable")
		}
		defer f.Close()
		raw, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
		if err != nil || len(raw) > 1<<20 {
			return nil, errors.New("agent credentials exceed 1 MiB or cannot be read")
		}
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if d.Decode(&credentials) != nil || credentials == nil || d.Decode(new(any)) != io.EOF {
			return nil, errors.New("invalid agent credentials JSON")
		}
	}
	transport := c.Agents.RegistryTransport
	if transport == nil {
		// Explicit host choice: retain operator proxy configuration, unlike nil Puller transport.
		transport = http.DefaultTransport.(*http.Transport).Clone()
	}
	puller, err := agentpackage.New(agentpackage.Policy{Repositories: c.Agents.Repositories, HTTPRegistry: c.Agents.HTTPRegistry, Credentials: credentials}, transport)
	if err != nil {
		return nil, err
	}
	source := c.Agents.Source
	if source == nil {
		source, err = agentcontroller.Kubernetes(c.Agents.Namespace, nil)
		if err != nil {
			return nil, errors.New("agent Kubernetes configuration unavailable")
		}
	}
	return agentcontroller.Start(ctx, agentcontroller.Config{Namespace: c.Agents.Namespace, Directory: c.Journal + ".agents", Model: c.Deployment, Binding: agentBinding(c, policy), Puller: puller, Source: source}, store, registry, model, stream)
}
