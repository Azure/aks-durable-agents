package host

import (
	"context"
	"log/slog"
	"net"
	"testing"
	"time"

	v1 "github.com/agent-primitives/sessions/api/genpb"
	"github.com/agent-primitives/sessions/authn"
	"github.com/agent-primitives/sessions/client"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func TestTrustedNetworkSessionsBoundary(t *testing.T) {
	good := Config{Addr: "0.0.0.0:8080", HealthAddr: "127.0.0.1:8081", Journal: ":memory:", Mode: authn.Off, TLSCert: "cert", TLSKey: "key", TrustedNetworkSessions: true, Harnesses: map[string]string{"test": "127.0.0.1:9000"}}
	if err := good.validate(); err != nil {
		t.Fatalf("explicit private TLS listener refused: %v", err)
	}
	for _, tc := range []struct {
		name   string
		change func(*Config)
	}{
		{"no opt-in", func(c *Config) { c.TrustedNetworkSessions = false }},
		{"required mode", func(c *Config) { c.Mode = authn.Required }},
		{"no TLS", func(c *Config) { c.TLSCert, c.TLSKey = "", "" }},
		{"partial TLS", func(c *Config) { c.TLSKey = "" }},
		{"loopback opt-in", func(c *Config) { c.Addr = "127.0.0.1:8080" }},
		{"hostname", func(c *Config) { c.Addr = "sessions.agents.svc.cluster.local:8080" }},
		{"non-wildcard", func(c *Config) { c.Addr = "192.0.2.1:8080" }},
		{"IPv6 wildcard", func(c *Config) { c.Addr = "[::]:8080" }},
		{"invalid port", func(c *Config) { c.Addr = "0.0.0.0:65536" }},
		{"ambiguous port", func(c *Config) { c.Addr = "0.0.0.0:08080" }},
		{"public health", func(c *Config) { c.HealthAddr = "0.0.0.0:8081" }},
		{"same port", func(c *Config) { c.HealthAddr = "127.0.0.1:8080" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := good
			tc.change(&c)
			if err := c.validate(); err == nil {
				t.Fatal("unsafe private listener configuration accepted")
			}
		})
	}
}

func TestTrustedNetworkSessionsTLSAcceptsInstanceProject(t *testing.T) {
	f := newHostFixture(t)
	f.config.Addr = "0.0.0.0:0"
	f.config.TrustedNetworkSessions = true
	app, err := newApplication(t.Context(), f.config, fixtureCredential{t}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Close)
	ln, err := net.Listen("tcp4", f.config.Addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go app.sessions.Serve(ln)
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	creds, err := credentials.NewClientTLSFromFile(f.config.TLSCert, "")
	if err != nil {
		t.Fatal(err)
	}
	const project = "independent-engine-instance"
	c, err := client.Dial(net.JoinHostPort("127.0.0.1", port), client.WithProject(project), client.WithDialOptions(grpc.WithTransportCredentials(creds), grpc.WithNoProxy(), grpc.WithDisableRetry()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	session, err := c.CreateSession(ctx, &v1.Session{Metadata: &v1.ResourceMetadata{Project: project}, Harness: "release-notes", Model: "test-deployment"})
	if err != nil {
		t.Fatal(err)
	}
	if session.GetMetadata().GetProject() != project || session.GetMetadata().GetUid() == "" {
		t.Fatalf("instance project lost: %+v", session.GetMetadata())
	}
	if f.models.Load() != 0 || f.sockets.Load() != 0 {
		t.Fatal("creating instance session executed model or tool")
	}
}
