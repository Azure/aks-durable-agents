// Command host runs the experimental loopback-only Azure sessions host.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/Azure/aks-durable-agents/entraauth"
	"github.com/Azure/aks-durable-agents/internal/host"
	"github.com/agent-primitives/sessions/api"
	"github.com/agent-primitives/sessions/authn"
)

type harnessFlags map[string]string

func (h harnessFlags) String() string { return "name=127.0.0.1:port" }
func (h harnessFlags) Set(value string) error {
	name, addr, ok := strings.Cut(value, "=")
	if !ok || name == "" || addr == "" || h[name] != "" {
		return errors.New("harness requires unique name=address")
	}
	h[name] = addr
	return nil
}

func parse(args []string) (host.Config, error) {
	c := host.Config{Harnesses: make(map[string]string)}
	fs := flag.NewFlagSet("host", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&c.Addr, "addr", "127.0.0.1:8080", "loopback Sessions listener")
	fs.StringVar(&c.HealthAddr, "health-addr", "127.0.0.1:8081", "separate loopback health/reflection listener")
	fs.StringVar(&c.Journal, "journal", "/data/journal.db", "single-writer SQLite journal")
	fs.StringVar(&c.Deployment, "model", "", "Azure model deployment")
	fs.StringVar(&c.ModelEndpoint, "model-base-url", "", "HTTPS OpenAI v1 endpoint ending /openai/v1/")
	fs.StringVar(&c.ModelScope, "model-scope", "", "model token scope; empty uses modeltransport default")
	fs.StringVar(&c.ToolExecutors, "tool-executors", "", "version-1 Unix executor config")
	fs.Func("harness-service", "repeatable exact service.namespace.svc.cluster.local:port exception", func(value string) error {
		if c.HarnessService == "" {
			c.HarnessService = value
		} else {
			c.HarnessServices = append(c.HarnessServices, value)
		}
		return nil
	})
	fs.StringVar(&c.PeerNodeFile, "peer-node-file", "", "shared fixture node marker; requires node-name")
	fs.StringVar(&c.NodeName, "node-name", "", "own Downward API node name for co-location check")
	fs.StringVar(&c.ModelPolicy, "model-policy", "", "required bounded model policy JSON with dated prices and durable ledger")
	fs.StringVar(&c.TLSCert, "tls-cert", "", "PEM server certificate file")
	fs.StringVar(&c.TLSKey, "tls-key", "", "PEM server private key file")
	mode := fs.String("auth-mode", "required", "off or required; neither supplies sessions c1/c2")
	authFile := fs.String("auth-config", "", "Entra identity and explicit approval allowlist JSON")
	fs.Var(harnessFlags(c.Harnesses), "harness", "repeatable static name=loopback-address")
	sub := &host.SubstrateConfig{}
	seen := make(map[string]bool)
	for _, f := range []struct {
		name, help string
		target     *string
	}{
		{"substrate-harness", "single name=atespace/template stateless-replay route", nil},
		{"substrate-atespace", "Actor atespace", &sub.ActorAtespace},
		{"ateapi-addr", "private TLS control endpoint", &sub.ControlAddr},
		{"ateapi-server-name", "control certificate name (default endpoint host)", &sub.ControlServerName},
		{"ateapi-ca-file", "control CA PEM file", &sub.CAFile},
		{"ateapi-token-file", "short-lived bearer token file, re-read per RPC", &sub.TokenFile},
		{"atenet-router", "required private trusted-network h2c router endpoint", &sub.RouterAddr},
	} {
		fs.Func(f.name, f.help, func(value string) error {
			if seen[f.name] {
				return errors.New("substrate flags cannot be repeated")
			}
			seen[f.name] = true
			if f.target != nil {
				*f.target = value
				return nil
			}
			name, ref, ok := strings.Cut(value, "=")
			space, template, refOK := strings.Cut(ref, "/")
			if !ok || !refOK || name == "" || space == "" || template == "" || strings.ContainsAny(name+space+template, "/=") {
				return errors.New("substrate-harness requires name=atespace/template")
			}
			sub.Harness, sub.TemplateAtespace, sub.Template = name, space, template
			return nil
		})
	}
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	if fs.NArg() != 0 {
		return c, errors.New("unexpected positional arguments")
	}
	if len(seen) != 0 {
		if sub.Harness == "" {
			return c, errors.New("substrate flags require -substrate-harness")
		}
		mixed := len(c.Harnesses) != 0
		fs.Visit(func(f *flag.Flag) {
			if f.Name == "harness-service" || f.Name == "peer-node-file" || f.Name == "node-name" {
				mixed = true
			}
		})
		if mixed {
			return c, errors.New("substrate cannot be combined with remote harness or fixture flags")
		}
		c.Substrate = sub
	}
	c.Mode = authn.Mode(*mode)
	if c.Mode != authn.Required && c.Mode != authn.Off {
		return c, errors.New("auth-mode must be off or required")
	}
	if *authFile != "" {
		f, err := os.Open(*authFile)
		if err != nil {
			return c, errors.New("cannot open auth config")
		}
		defer f.Close()
		var a struct {
			Identity struct {
				TenantID         string   `json:"tenantID"`
				Issuer           string   `json:"issuer"`
				Audience         string   `json:"audience"`
				AllowedClientIDs []string `json:"allowedClientIDs"`
				RequiredScope    string   `json:"requiredScope"`
				SubjectClaim     string   `json:"subjectClaim"`
			} `json:"identity"`
			Approvers []struct {
				Issuer  string `json:"issuer"`
				Subject string `json:"subject"`
			} `json:"approvers"`
		}
		raw, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
		if err != nil || len(raw) > 1<<20 {
			return c, errors.New("auth config exceeds 1 MiB or cannot be read")
		}
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if err := d.Decode(&a); err != nil {
			return c, errors.New("invalid auth config")
		}
		var extra any
		if d.Decode(&extra) != io.EOF {
			return c, errors.New("trailing auth config data")
		}
		c.Identity = entraauth.Config{TenantID: a.Identity.TenantID, Issuer: a.Identity.Issuer, Audience: a.Identity.Audience, AllowedClientIDs: a.Identity.AllowedClientIDs, RequiredScope: a.Identity.RequiredScope, SubjectClaim: a.Identity.SubjectClaim}
		for _, caller := range a.Approvers {
			c.Approvers = append(c.Approvers, api.CallerIdentity{Issuer: caller.Issuer, Subject: caller.Subject})
		}
	}
	return c, nil
}

func main() {
	// Journal and runtime files must not become readable to other container users.
	syscall.Umask(0077)
	if len(os.Args) >= 2 && os.Args[1] == "health-probe" {
		if len(os.Args) != 3 {
			fmt.Fprintln(os.Stderr, "host: health-probe requires one literal loopback address")
			os.Exit(1)
		}
		if err := healthProbe(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, "host:", err)
			os.Exit(1)
		}
		return
	}
	c, err := parse(os.Args[1:])
	if err == nil {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		err = host.Run(ctx, c, slog.Default())
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "host:", err)
		os.Exit(1)
	}
}
