package host

import (
	"encoding/json"
	"github.com/Azure/aks-durable-agents/entraauth"
	"github.com/agent-primitives/sessions/api"
	"github.com/agent-primitives/sessions/authn"
	"testing"
)

// Missing opt-in selection must not require a remote harness or touch I/O.
func TestSubstrateConfigWithoutRemote(t *testing.T) {
	var c Config
	if err := json.Unmarshal([]byte(`{"Addr":"127.0.0.1:0","HealthAddr":"127.0.0.1:0","Journal":":memory:","Mode":"off","Substrate":{"Harness":"echo","ActorAtespace":"app","TemplateAtespace":"assets","Template":"echo-v1","ControlAddr":"127.0.0.1:7443","CAFile":"ca.pem","TokenFile":"token","RouterAddr":"router.system.svc.cluster.local:8080"}}`), &c); err != nil {
		t.Fatal(err)
	}
	if err := c.validate(); err != nil {
		t.Fatalf("valid opt-in Substrate config refused: %v", err)
	}
}

func TestSubstrateConfigBoundary(t *testing.T) {
	good := Config{Addr: "127.0.0.1:0", HealthAddr: "127.0.0.1:0", Journal: ":memory:", Mode: authn.Off,
		Substrate: &SubstrateConfig{Harness: "echo", ActorAtespace: "app", TemplateAtespace: "assets", Template: "echo-v1", ControlAddr: "127.0.0.1:7443", CAFile: "ca.pem", TokenFile: "token", RouterAddr: "router.system.svc.cluster.local:8080"}}
	for _, tc := range []struct {
		name   string
		change func(*Config)
	}{
		{"mixed", func(c *Config) { c.Harnesses = map[string]string{"remote": "127.0.0.1:1"} }},
		{"fixture service", func(c *Config) { c.HarnessService = "fixture.app.svc.cluster.local:80" }},
		{"fixture marker", func(c *Config) { c.PeerNodeFile = "/missing" }},
		{"fixture node", func(c *Config) { c.NodeName = "node" }},
		{"no harness", func(c *Config) { c.Substrate.Harness = "" }},
		{"bad harness", func(c *Config) { c.Substrate.Harness = "Echo" }},
		{"bad actor atespace", func(c *Config) { c.Substrate.ActorAtespace = "a.b" }},
		{"missing template atespace", func(c *Config) { c.Substrate.TemplateAtespace = "" }},
		{"bad template", func(c *Config) { c.Substrate.Template = "-bad" }},
		{"no CA", func(c *Config) { c.Substrate.CAFile = "" }},
		{"no token", func(c *Config) { c.Substrate.TokenFile = "" }},
		{"no router", func(c *Config) { c.Substrate.RouterAddr = "" }},
		{"router public", func(c *Config) { c.Substrate.RouterAddr = "10.0.0.1:80" }},
		{"router DNS", func(c *Config) { c.Substrate.RouterAddr = "localhost:80" }},
		{"router bad service", func(c *Config) { c.Substrate.RouterAddr = "router.app.svc.cluster.local.evil:80" }},
		{"router zero port", func(c *Config) { c.Substrate.RouterAddr = "127.0.0.1:0" }},
		{"control empty", func(c *Config) { c.Substrate.ControlAddr = "" }},
		{"control URI", func(c *Config) { c.Substrate.ControlAddr = "https://127.0.0.1:443" }},
		{"control public", func(c *Config) { c.Substrate.ControlAddr = "example.com:443" }},
		{"control bad port", func(c *Config) { c.Substrate.ControlAddr = "127.0.0.1:65536" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, sub := good, *good.Substrate
			c.Substrate = &sub
			tc.change(&c)
			if err := c.validate(); err == nil {
				t.Fatal("unsafe Substrate configuration admitted")
			}
		})
	}
	for _, address := range []string{"[::1]:443", "control.app.svc.cluster.local:7443"} {
		c, sub := good, *good.Substrate
		c.Substrate = &sub
		sub.ControlAddr, sub.RouterAddr = address, address
		if err := c.validate(); err != nil {
			t.Fatalf("valid private endpoint %s: %v", address, err)
		}
	}
}

func TestConfigBoundary(t *testing.T) {
	good := Config{Addr: "127.0.0.1:0", HealthAddr: "127.0.0.1:0", Journal: ":memory:", Mode: authn.Off, Harnesses: map[string]string{"release-notes": "127.0.0.1:9000"}, ModelEndpoint: "https://model.example/openai/v1/", Deployment: "deployment"}
	if err := good.validate(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*Config)
	}{
		{"invalid mode", func(c *Config) { c.Mode = "typo" }},
		{"public sessions", func(c *Config) { c.Addr = "0.0.0.0:8080" }},
		{"hostname sessions", func(c *Config) { c.Addr = "localhost:8080" }},
		{"public health", func(c *Config) { c.HealthAddr = ":8081" }},
		{"same listener", func(c *Config) { c.Addr = "127.0.0.1:8080"; c.HealthAddr = c.Addr }},
		{"required no TLS", func(c *Config) { c.Mode = authn.Required }},
		{"partial TLS", func(c *Config) { c.TLSCert = "cert" }},
		{"no harness", func(c *Config) { c.Harnesses = nil }},
		{"remote harness", func(c *Config) { c.Harnesses = map[string]string{"release-notes": "example.com:9000"} }},
		{"no journal", func(c *Config) { c.Journal = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := good
			tc.change(&c)
			if err := c.validate(); err == nil {
				t.Fatal("unsafe configuration admitted")
			}
		})
	}
}

// Required-mode approvers must match what the verifier emits; a mismatch would
// otherwise pass startup and silently deny every approval.
func TestApproverIdentityBoundary(t *testing.T) {
	const tenant, oid = "11111111-2222-3333-4444-555555555555", "0a1b2c3d-4e5f-6789-abcd-ef0123456789"
	good := Config{Addr: "127.0.0.1:0", HealthAddr: "127.0.0.1:0", Journal: ":memory:", Mode: authn.Required, TLSCert: "cert", TLSKey: "key",
		Harnesses: map[string]string{"release-notes": "127.0.0.1:9000"},
		Identity:  entraauth.Config{TenantID: tenant, Issuer: fixtureIssuer, Audience: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", AllowedClientIDs: []string{"12345678-1234-1234-1234-123456789abc"}, RequiredScope: "sessions.access"},
		Approvers: []api.CallerIdentity{{Issuer: fixtureIssuer, Subject: oid}}}
	for _, tc := range []struct {
		name   string
		change func(*Config)
		ok     bool
	}{
		{"matching oid", func(*Config) {}, true},
		{"matching explicit oid", func(c *Config) { c.Identity.SubjectClaim = "oid" }, true},
		{"sub pairwise subject", func(c *Config) {
			c.Identity.SubjectClaim = "sub"
			c.Approvers = []api.CallerIdentity{{Issuer: fixtureIssuer, Subject: "pairwise-subject"}}
		}, true},
		{"off mode keeps existing check", func(c *Config) {
			c.Mode = authn.Off
			c.Approvers = []api.CallerIdentity{{Issuer: "https://sts.windows.net/" + tenant + "/", Subject: "user@contoso.example"}}
		}, true},
		{"v1 issuer", func(c *Config) { c.Approvers[0].Issuer = "https://sts.windows.net/" + tenant + "/" }, false},
		{"trailing slash issuer", func(c *Config) { c.Approvers[0].Issuer = fixtureIssuer + "/" }, false},
		{"UPN subject", func(c *Config) { c.Approvers[0].Subject = "user@contoso.example" }, false},
		{"uppercase oid", func(c *Config) { c.Approvers[0].Subject = "0A1B2C3D-4E5F-6789-ABCD-EF0123456789" }, false},
		{"one bad of two", func(c *Config) {
			c.Approvers = append(c.Approvers, api.CallerIdentity{Issuer: fixtureIssuer, Subject: "../x@y"})
		}, false},
		{"sub mode wrong issuer", func(c *Config) {
			c.Identity.SubjectClaim = "sub"
			c.Approvers[0].Issuer = fixtureIssuer + "/"
		}, false},
		{"incomplete", func(c *Config) { c.Approvers[0].Subject = "" }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := good
			c.Approvers = append([]api.CallerIdentity(nil), good.Approvers...)
			tc.change(&c)
			if err := c.validate(); (err == nil) != tc.ok {
				t.Fatalf("validate() = %v, want ok=%v", err, tc.ok)
			}
		})
	}
}
