package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/agent-primitives/sessions/authn"
)

func TestAuthConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	good := `{"identity":{"tenantID":"tenant","issuer":"issuer","audience":"audience","allowedClientIDs":["client"],"requiredScope":"sessions.access"},"approvers":[{"issuer":"issuer","subject":"approver"}]}`
	if err := os.WriteFile(path, []byte(good), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := parse([]string{"-auth-config=" + path})
	if err != nil {
		t.Fatal(err)
	}
	if c.Identity.TenantID != "tenant" || c.Identity.RequiredScope != "sessions.access" || len(c.Approvers) != 1 || c.Approvers[0].Subject != "approver" || c.ModelCredential != nil {
		t.Fatal("auth config not mapped to verifier and policy")
	}
	for _, value := range []string{`{"unknown":1}`, `{"modelCredential":{"token":"injected"}}`, good + ` {}`, good + strings.Repeat(" ", 1<<20)} {
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := parse([]string{"-auth-config=" + path}); err == nil {
			t.Fatal("invalid or oversized auth config accepted")
		}
	}
}

func TestOptionalAuthPolicyConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	raw := `{"identity":{"requiredRoles":["Reviewer","Approver"],"requiredGroups":["group"],"memberOnly":true,"approverRoles":["Approver"]},"approvers":[]}`
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := parse([]string{"-auth-config=" + path})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(c.Identity.RequiredRoles, []string{"Reviewer", "Approver"}) || !slices.Equal(c.Identity.RequiredGroups, []string{"group"}) || !c.Identity.MemberOnly || !slices.Equal(c.Identity.ApproverRoles, []string{"Approver"}) {
		t.Fatal("policy not mapped")
	}
}

func TestSubstrateFlags(t *testing.T) {
	args := []string{"-auth-mode=off", "-substrate-harness=echo=assets/echo-v1", "-substrate-atespace=app", "-ateapi-addr=127.0.0.1:7443", "-ateapi-ca-file=ca.pem", "-ateapi-token-file=token", "-atenet-router=router.system.svc.cluster.local:8080"}
	c, err := parse(args)
	if err != nil {
		t.Fatalf("valid Substrate flags refused: %v", err)
	}
	if len(c.Harnesses) != 0 || c.Substrate == nil || c.Substrate.Harness != "echo" || c.Substrate.ActorAtespace != "app" || c.Substrate.TemplateAtespace != "assets" || c.Substrate.Template != "echo-v1" || c.Substrate.CAFile != "ca.pem" || c.Substrate.TokenFile != "token" || c.Substrate.RouterAddr != "router.system.svc.cluster.local:8080" {
		t.Fatal("Substrate flags not mapped to one distinct route")
	}
	for _, extra := range [][]string{
		{"-substrate-harness=other=assets/echo"}, {"-harness=remote=127.0.0.1:80"}, {"-harness-service=fixture.app.svc.cluster.local:80"}, {"-peer-node-file=/marker"}, {"-node-name=node"}, {"-atenet-router=127.0.0.1:80"},
	} {
		if _, err := parse(append(append([]string{}, args...), extra...)); err == nil {
			t.Fatalf("accepted mixed/duplicate flags %v", extra)
		}
	}
	for _, value := range []string{"broken", "echo=assets", "echo=/template", "echo=assets/", "echo=assets/template/extra", "=assets/template"} {
		if _, err := parse([]string{"-substrate-harness=" + value}); err == nil {
			t.Fatalf("accepted malformed reference %q", value)
		}
	}
	for _, arg := range args[2:] {
		if _, err := parse([]string{arg}); err == nil {
			t.Fatalf("accepted orphan flag %q", arg)
		}
	}
	for _, flag := range []string{"-ateapi-server-name=name", "-atenet-router=", "-substrate-atespace="} {
		if _, err := parse([]string{flag}); err == nil {
			t.Fatalf("accepted orphan flag %q", flag)
		}
	}
}

func TestSubstratePlacementFlagIsExplicitAndNotStandalone(t *testing.T) {
	if _, err := parse([]string{"-substrate-placement-file=/data/substrate-placement.json"}); err == nil {
		t.Fatal("standalone placement flag accepted")
	}
	c, err := parse([]string{"-auth-mode=off", "-substrate-harness=release-notes=assets/release-notes", "-substrate-placement-file=/data/substrate-placement.json"})
	if err != nil || c.Substrate == nil || c.Substrate.PlacementFile != "/data/substrate-placement.json" {
		t.Fatalf("placement flag not mapped: %+v %v", c.Substrate, err)
	}
}

func TestRepeatedHarnessServiceKeepsEveryExactPort(t *testing.T) {
	const first = "native.agents.svc.cluster.local:9000"
	const second = "native.agents.svc.cluster.local:9001"
	c, err := parse([]string{"-auth-mode=off", "-harness-service=" + first, "-harness-service=" + second, "-harness=bundle-v4-" + strings.Repeat("a", 64) + "=" + first, "-harness=bundle-v4-" + strings.Repeat("b", 64) + "=" + second})
	if err != nil {
		t.Fatal(err)
	}
	if c.HarnessService != first || len(c.HarnessServices) != 1 || c.HarnessServices[0] != second || len(c.Harnesses) != 2 {
		t.Fatalf("repeat overwrote first exact service: %+v", c)
	}
}

// Chart tests compare their real rendered args to the same fixture. This tests
// the production CLI path without adding a fake-credential flag or parser fork.
func TestNativeChartArgumentsUseProductionParser(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "charts", "aks-durable-agents", "tests", "native-host-args.json"))
	if err != nil {
		t.Fatal(err)
	}
	var args []string
	if err = json.Unmarshal(raw, &args); err != nil {
		t.Fatal(err)
	}
	c, err := parse(args)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Harnesses) != 2 || c.HarnessService != "test-aks-durable-agents-harness.agents.svc.cluster.local:9000" || len(c.HarnessServices) != 1 || c.HarnessServices[0] != "test-aks-durable-agents-harness.agents.svc.cluster.local:9001" || c.Mode != authn.Off || c.ToolExecutors != "" || c.PeerNodeFile != "" || c.NodeName != "" || c.ModelCredential != nil || c.ModelPolicy != "/config/model-policy.json" {
		t.Fatalf("native chart args changed meaning: %+v", c)
	}
}

func TestFlags(t *testing.T) {
	c, err := parse([]string{"-harness=release-notes=127.0.0.1:9000", "-model=deployment", "-model-base-url=https://model.example/openai/v1/"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Mode != authn.Required || c.Journal != "/data/journal.db" || c.Harnesses["release-notes"] != "127.0.0.1:9000" || c.Deployment != "deployment" {
		t.Fatalf("flags not wired: %+v", c)
	}
	if c.ModelCredential != nil {
		t.Fatal("ordinary host parse constructed a model credential")
	}
	for _, args := range [][]string{{"-harness=broken"}, {"-harness=a=127.0.0.1:1", "-harness=a=127.0.0.1:2"}, {"-auth-mode=maybe"}, {"extra"}, {"-model-auth-header=api-key"}, {"-model-credential=injected"}} {
		if _, err := parse(args); err == nil {
			t.Fatalf("accepted invalid flags %v", args)
		}
	}
}

func TestNormalHostDoesNotDecodeOrReadInjectedCredential(t *testing.T) {
	t.Setenv("AZURE_CLIENT_ID", "not-a-real-cloud-identity")
	t.Setenv("MODEL_CREDENTIAL", "injected")
	c, err := parse([]string{"-harness=release-notes=127.0.0.1:9000", "-auth-mode=off"})
	if err != nil {
		t.Fatal(err)
	}
	if c.ModelCredential != nil {
		t.Fatal("environment populated trusted model credential")
	}
	if err := json.Unmarshal([]byte(`{"ModelCredential":{"token":"injected"}}`), &c); err != nil {
		t.Fatal(err)
	}
	if c.ModelCredential != nil {
		t.Fatal("JSON populated trusted model credential")
	}
}
