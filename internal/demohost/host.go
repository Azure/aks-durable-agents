// Package demohost assembles an explicitly unauthenticated, fake-model host for
// the disposable kind demo. Production commands never import this package.
package demohost

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Azure/aks-durable-agents/internal/host"
	"github.com/Azure/aks-durable-agents/modeltransport"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/agent-primitives/sessions/authn"
)

const fakeToken = "demo-only-not-an-azure-token"
const endpoint = "https://fake-model.invalid/openai/v1/"
const draft = "Northwind Lantern v2.4 — 18 October 2026\n\nThis fictional release introduces faster search and CSV export. This is an offline demo only; rollout pending approval. Review these release notes before the local publication simulation."

type credential struct{}

func (credential) GetToken(_ context.Context, options policy.TokenRequestOptions) (azcore.AccessToken, error) {
	if len(options.Scopes) != 1 || options.Scopes[0] != modeltransport.DefaultScope {
		return azcore.AccessToken{}, errors.New("demo fake credential refuses other audiences")
	}
	return azcore.AccessToken{Token: fakeToken, ExpiresOn: time.Now().Add(time.Hour)}, nil
}

func loopback(address string) bool {
	hostname, _, err := net.SplitHostPort(address)
	return err == nil && net.ParseIP(hostname).IsLoopback()
}

// Config exposes only the chart's local-demo assembly flags, not the production
// credential, identity or TLS configuration surface.
func Config(args []string) (host.Config, func(), error) {
	c := host.Config{Harnesses: make(map[string]string)}
	fs := flag.NewFlagSet("demo-host", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&c.Addr, "addr", "127.0.0.1:8080", "loopback Sessions listener")
	fs.StringVar(&c.HealthAddr, "health-addr", "127.0.0.1:8081", "loopback health listener")
	fs.StringVar(&c.Journal, "journal", "/data/journal.db", "private demo journal")
	fs.StringVar(&c.HarnessService, "harness-service", "", "chart harness service")
	fs.StringVar(&c.PeerNodeFile, "peer-node-file", "", "fixture placement marker")
	fs.StringVar(&c.NodeName, "node-name", "", "node name")
	fs.StringVar(&c.ToolExecutors, "tool-executors", "", "chart executor configuration")
	fs.StringVar(&c.ModelPolicy, "model-policy", "", "bounded demo model policy")
	fs.StringVar(&c.ModelEndpoint, "model-base-url", "", "must be the fake-model.invalid endpoint")
	fs.StringVar(&c.Deployment, "model", "", "must be demo-model")
	fs.StringVar(&c.ModelScope, "model-scope", modeltransport.DefaultScope, "fake credential audience")
	mode := fs.String("auth-mode", "", "must explicitly be off; identity not exercised")
	fs.Func("harness", "unique name=address", func(value string) error {
		name, address, ok := strings.Cut(value, "=")
		if !ok || name == "" || address == "" || c.Harnesses[name] != "" {
			return errors.New("harness requires unique name=address")
		}
		c.Harnesses[name] = address
		return nil
	})
	if err := fs.Parse(args); err != nil {
		return c, nil, err
	}
	if fs.NArg() != 0 || *mode != "off" || !loopback(c.Addr) || !loopback(c.HealthAddr) || c.ModelEndpoint != endpoint || c.Deployment != "demo-model" || c.ModelScope != modeltransport.DefaultScope || c.ModelPolicy == "" || c.ToolExecutors == "" || len(c.Harnesses) == 0 || !filepath.IsAbs(c.Journal) || filepath.Clean(c.Journal) != c.Journal {
		return c, nil, errors.New("demo requires loopback listeners, auth-mode=off, chart policy/executor/harness, demo-model and the fixed fake endpoint")
	}
	parent := filepath.Dir(c.Journal)
	info, err := os.Lstat(parent)
	if err != nil {
		return c, nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || info.Mode().Perm() != 0700 || !ok || int(stat.Uid) != os.Getuid() {
		return c, nil, errors.New("demo journal requires an owned private directory")
	}
	c.Mode = authn.Off
	var mu sync.Mutex
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Model  string          `json:"model"`
			Max    int             `json:"max_completion_tokens"`
			Legacy json.RawMessage `json:"max_tokens"`
			Stream bool            `json:"stream"`
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
		accepted := err == nil && len(raw) <= 1<<20 && json.Unmarshal(raw, &body) == nil && r.Method == http.MethodPost && r.URL.Path == "/openai/v1/chat/completions" && r.Header.Get("Authorization") == "Bearer "+fakeToken && r.Header.Get("api-key") == "" && body.Model == "demo-model" && body.Max == 4096 && body.Legacy == nil && body.Stream
		mu.Lock()
		err = recordAttempt(filepath.Join(parent, "demo-model-calls.jsonl"), accepted)
		mu.Unlock()
		if err != nil {
			http.Error(w, "demo attempt evidence unavailable", 500)
			return
		}
		if !accepted {
			http.Error(w, "invalid demo request", 400)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		delta, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"delta": map[string]any{"content": draft}}}})
		fmt.Fprintf(w, "data: %s\n\ndata: {\"choices\":[],\"usage\":{\"prompt_tokens\":250,\"completion_tokens\":84,\"total_tokens\":334,\"completion_tokens_details\":{\"reasoning_tokens\":12}}}\n\ndata: [DONE]\n\n", delta)
	}))
	cert := provider.Certificate()
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	serverName := cert.IPAddresses[0].String()
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: serverName}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "fake-model.invalid:443" {
			return nil, errors.New("off-pin demo model destination refused")
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", provider.Listener.Addr().String())
	}}
	c.ModelTransport = transport
	c.ModelCredential = credential{}
	return c, func() { transport.CloseIdleConnections(); provider.Close() }, nil
}

func recordAttempt(path string, accepted bool) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !ok || int(stat.Uid) != os.Getuid() {
		return errors.New("unsafe demo meter file")
	}
	if err := json.NewEncoder(f).Encode(struct {
		Accepted bool `json:"accepted"`
	}{accepted}); err != nil {
		return err
	}
	return f.Sync()
}
