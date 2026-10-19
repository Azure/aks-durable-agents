// Command drillhost is an isolated fake-provider assembly for local kind only.
// It is never built into the production host image.
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
	"os/exec"
	"os/signal"
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

const fakeToken = "canvas-kind-model-only"

type fakeCredential struct{ ledger string }

func (f fakeCredential) GetToken(_ context.Context, o policy.TokenRequestOptions) (azcore.AccessToken, error) {
	if len(o.Scopes) != 1 || o.Scopes[0] != modeltransport.DefaultScope {
		return azcore.AccessToken{}, errors.New("drill fake audience refused")
	}
	file, err := os.OpenFile(f.ledger, os.O_CREATE|os.O_WRONLY|os.O_APPEND|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return azcore.AccessToken{}, err
	}
	_, err = file.WriteString("{\"issued\":true}\n")
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return azcore.AccessToken{}, err
	}
	return azcore.AccessToken{Token: fakeToken, ExpiresOn: time.Now().Add(time.Hour)}, nil
}

func newDrillConfig(args []string, assets string) (host.Config, func(), error) {
	c := host.Config{Harnesses: map[string]string{}}
	fs := flag.NewFlagSet("canvas-drillhost", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&c.Addr, "addr", "127.0.0.1:8080", "loopback sessions")
	fs.StringVar(&c.HealthAddr, "health-addr", "127.0.0.1:8081", "loopback health")
	fs.StringVar(&c.Journal, "journal", "/data/journal.db", "journal")
	fs.StringVar(&c.ModelPolicy, "model-policy", "", "policy")
	fs.StringVar(&c.ModelEndpoint, "model-base-url", "", "fake endpoint")
	fs.StringVar(&c.Deployment, "model", "", "pinned fake model")
	fs.StringVar(&c.ModelScope, "model-scope", modeltransport.DefaultScope, "scope")
	mode := fs.String("auth-mode", "", "must be off")
	fs.Func("harness-service", "exact service", func(v string) error {
		if c.HarnessService == "" {
			c.HarnessService = v
		} else {
			c.HarnessServices = append(c.HarnessServices, v)
		}
		return nil
	})
	fs.Func("harness", "static name=address", func(v string) error {
		name, addr, ok := strings.Cut(v, "=")
		if !ok || name == "" || addr == "" || c.Harnesses[name] != "" {
			return errors.New("invalid static route")
		}
		c.Harnesses[name] = addr
		return nil
	})
	if err := fs.Parse(args); err != nil {
		return c, nil, err
	}
	if fs.NArg() != 0 || *mode != "off" || !filepath.IsAbs(c.Journal) || c.ModelPolicy == "" || c.Deployment == "" || len(c.Harnesses) == 0 || c.ModelScope != modeltransport.DefaultScope {
		return c, nil, errors.New("drill requires native routes, bounded policy, absolute journal and explicit auth-mode=off")
	}
	c.Mode = authn.Off
	endpoint, err := url.Parse(c.ModelEndpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.Path != "/openai/v1/" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return c, nil, errors.New("invalid drill model endpoint")
	}
	payloads := map[string]string{}
	for _, kind := range []string{"writer", "reviewer"} {
		raw, err := os.ReadFile(filepath.Join(assets, kind+".json"))
		if err != nil || len(raw) > 1<<20 || !json.Valid(raw) {
			return c, nil, errors.New("invalid retained drill payload")
		}
		payloads[kind] = string(raw)
	}
	var mu sync.Mutex
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Model    string          `json:"model"`
			Max      int             `json:"max_completion_tokens"`
			Legacy   json.RawMessage `json:"max_tokens"`
			Stream   bool            `json:"stream"`
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
			Format struct {
				Type   string `json:"type"`
				Schema struct {
					Strict bool `json:"strict"`
				} `json:"json_schema"`
			} `json:"response_format"`
		}
		raw, readErr := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
		kind := ""
		for _, candidate := range []string{"writer", "reviewer"} {
			if strings.Contains(string(raw), "canvas-kind-"+candidate) {
				if kind != "" {
					kind = "ambiguous"
					break
				}
				kind = candidate
			}
		}
		valid := readErr == nil && len(raw) <= 1<<20 && json.Unmarshal(raw, &body) == nil && r.Method == "POST" && r.URL.Path == "/openai/v1/chat/completions" && r.Header.Get("Authorization") == "Bearer "+fakeToken && r.Header.Get("api-key") == "" && body.Model == c.Deployment && body.Max == 4096 && body.Legacy == nil && body.Format.Type == "json_schema" && body.Format.Schema.Strict && payloads[kind] != ""
		acceptedObserved := false
		if kind == "reviewer" {
			var expected struct {
				Changes []struct{ Document, Content string }
			}
			if json.Unmarshal([]byte(payloads["writer"]), &expected) == nil && len(expected.Changes) > 0 {
				for _, message := range body.Messages {
					var input struct {
						Documents map[string]struct{ Path string }
						Evidence  map[string]string
					}
					if json.Unmarshal([]byte(message.Content), &input) != nil {
						continue
					}
					matched := true
					for _, change := range expected.Changes {
						path := input.Documents[change.Document].Path
						actual, ok := input.Evidence[path]
						if path == "" || !ok || actual != change.Content {
							matched = false
							break
						}
					}
					if matched {
						acceptedObserved = true
						break
					}
				}
			}
			valid = valid && acceptedObserved
		}
		// Independent durable HTTP-attempt history: never prompts, documents or tokens.
		event, _ := json.Marshal(map[string]any{"role": kind, "valid": valid, "completionCap": body.Max, "model": c.Deployment, "acceptedDocumentsObserved": acceptedObserved, "requestBytes": len(raw)})
		mu.Lock()
		file, err := os.OpenFile(filepath.Join(filepath.Dir(c.Journal), "fake-http.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND|syscall.O_NOFOLLOW, 0600)
		if err == nil {
			_, err = file.Write(append(event, '\n'))
			if err == nil {
				err = file.Sync()
			}
			closeErr := file.Close()
			if err == nil {
				err = closeErr
			}
		}
		mu.Unlock()
		if err != nil {
			http.Error(w, "drill evidence unavailable", 500)
			return
		}
		if !valid {
			http.Error(w, "invalid bounded fake request", 400)
			return
		}
		if body.Stream {
			w.Header().Set("Content-Type", "text/event-stream")
			delta, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"delta": map[string]any{"content": payloads[kind]}}}})
			fmt.Fprintf(w, "data: %s\n\ndata: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: {\"choices\":[],\"usage\":{\"prompt_tokens\":750,\"completion_tokens\":120}}\n\ndata: [DONE]\n\n", delta)
		} else {
			json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"role": "assistant", "content": payloads[kind]}, "finish_reason": "stop"}}, "usage": map[string]int{"prompt_tokens": 750, "completion_tokens": 120}})
		}
	}))
	roots := x509.NewCertPool()
	roots.AddCert(provider.Certificate())
	port := endpoint.Port()
	if port == "" {
		port = "443"
	}
	pinned := net.JoinHostPort(endpoint.Hostname(), port)
	c.ModelTransport = &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: provider.Certificate().DNSNames[0]}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != pinned {
			return nil, errors.New("off-pin drill destination")
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", provider.Listener.Addr().String())
	}}
	c.ModelCredential = fakeCredential{ledger: filepath.Join(filepath.Dir(c.Journal), "fake-credential.jsonl")}
	return c, func() { c.ModelTransport.CloseIdleConnections(); provider.Close() }, nil
}

func main() {
	syscall.Umask(0077)
	if len(os.Args) > 1 && os.Args[1] == "health-probe" {
		// Run the real production probe, not a drill implementation of health.
		command := exec.Command("/production-host", os.Args[1:]...)
		command.Stdout = os.Stdout
		command.Stderr = os.Stderr
		if err := command.Run(); err != nil {
			os.Exit(1)
		}
		return
	}
	c, closeFake, err := newDrillConfig(os.Args[1:], "/fixtures")
	if err == nil {
		defer closeFake()
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		err = host.Run(ctx, c, slog.Default())
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "canvas drillhost:", err)
		os.Exit(1)
	}
}
