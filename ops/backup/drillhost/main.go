// Command drillhost is a local-only kind backup drill binary. Build it as /host
// only in the drill image; the production host image and CLI never use it.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Azure/aks-durable-agents/internal/host"
	"github.com/Azure/aks-durable-agents/modeltransport"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/agent-primitives/sessions/authn"
)

const fakeToken = "local-drill-model-only"

// No environment, JSON, credential, auth-config, or TLS flags are accepted.
// This is deliberately a separate parser, not an extension of cmd/host.
func parseDrill(args []string) (host.Config, error) {
	c := host.Config{Harnesses: make(map[string]string)}
	fs := flag.NewFlagSet("local-drillhost", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&c.Addr, "addr", "127.0.0.1:8080", "loopback sessions listener")
	fs.StringVar(&c.HealthAddr, "health-addr", "127.0.0.1:8081", "loopback health listener")
	fs.StringVar(&c.Journal, "journal", "/data/journal.db", "journal")
	fs.StringVar(&c.HarnessService, "harness-service", "", "chart harness service")
	fs.StringVar(&c.PeerNodeFile, "peer-node-file", "", "co-location marker")
	fs.StringVar(&c.NodeName, "node-name", "", "node name")
	fs.StringVar(&c.ModelPolicy, "model-policy", "", "bounded model policy")
	fs.StringVar(&c.ToolExecutors, "tool-executors", "", "tool executor config")
	fs.StringVar(&c.Deployment, "model", "", "fake deployment")
	fs.StringVar(&c.ModelEndpoint, "model-base-url", "", "HTTPS model URL routed to the local fake")
	fs.StringVar(&c.ModelScope, "model-scope", "", "model scope")
	mode := fs.String("auth-mode", "", "must be off for this local drill")
	fs.Func("harness", "name=address", func(value string) error {
		name, addr, ok := strings.Cut(value, "=")
		if !ok || name == "" || addr == "" || c.Harnesses[name] != "" {
			return errors.New("harness requires unique name=address")
		}
		c.Harnesses[name] = addr
		return nil
	})
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	if fs.NArg() != 0 || *mode != string(authn.Off) || c.ModelPolicy == "" || c.ModelEndpoint == "" || c.Deployment == "" || len(c.Harnesses) == 0 || (c.ModelScope != "" && c.ModelScope != modeltransport.DefaultScope) {
		return c, errors.New("local drill requires auth-mode=off, chart harness, bounded model policy, and fake model endpoint/deployment/scope")
	}
	c.Mode = authn.Off
	return c, nil
}

type fakeCredential struct{}

func (fakeCredential) GetToken(_ context.Context, options policy.TokenRequestOptions) (azcore.AccessToken, error) {
	if len(options.Scopes) != 1 || options.Scopes[0] != modeltransport.DefaultScope {
		return azcore.AccessToken{}, errors.New("local drill only supports the fake model audience")
	}
	return azcore.AccessToken{Token: fakeToken, ExpiresOn: time.Now().Add(time.Hour)}, nil
}

func newDrillConfig(args []string) (host.Config, func(), error) {
	c, err := parseDrill(args)
	if err != nil {
		return c, nil, err
	}
	endpoint, err := url.Parse(c.ModelEndpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.Path != "/openai/v1/" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return c, nil, errors.New("local drill requires an HTTPS /openai/v1/ model endpoint")
	}
	// The fake returns the same fictional approved release-notes SSE and usage
	// as internal/host/scenario_v2_test.go, using only a loopback provider.
	const draft = "Northwind Lantern v2.4 — 18 October 2026\n\nThis fictional release introduces faster search and CSV export. This is an offline demo only; rollout pending approval. Review these release notes before the local publication simulation."
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Model  string `json:"model"`
			Max    int    `json:"max_completion_tokens"`
			Stream bool   `json:"stream"`
		}
		if r.Method != http.MethodPost || r.URL.Path != "/openai/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer "+fakeToken || r.Header.Get("api-key") != "" || json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body) != nil || body.Model != c.Deployment || body.Max != 4096 || !body.Stream {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		delta, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"delta": map[string]any{"content": draft}}}})
		_, _ = fmt.Fprintf(w, "data: %s\n\ndata: {\"choices\":[],\"usage\":{\"prompt_tokens\":250,\"completion_tokens\":84,\"total_tokens\":334,\"completion_tokens_details\":{\"reasoning_tokens\":12}}}\n\ndata: [DONE]\n\n", delta)
	}))
	cert := provider.Certificate()
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	serverName := ""
	if len(cert.DNSNames) > 0 {
		serverName = cert.DNSNames[0]
	} else if len(cert.IPAddresses) > 0 {
		serverName = cert.IPAddresses[0].String()
	}
	if serverName == "" {
		provider.Close()
		return c, nil, errors.New("local fake provider has no TLS identity")
	}
	port := endpoint.Port()
	if port == "" {
		port = "443"
	}
	pinned := net.JoinHostPort(endpoint.Hostname(), port)
	c.ModelTransport = &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: serverName},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != pinned {
				return nil, errors.New("local drill model destination refused")
			}
			return (&net.Dialer{}).DialContext(ctx, "tcp", provider.Listener.Addr().String())
		},
	}
	c.ModelCredential = fakeCredential{}
	return c, provider.Close, nil
}

func main() {
	syscall.Umask(0077)
	c, closeProvider, err := newDrillConfig(os.Args[1:])
	if err == nil {
		defer closeProvider()
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		err = host.Run(ctx, c, slog.Default())
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "local drillhost:", err)
		os.Exit(1)
	}
}
