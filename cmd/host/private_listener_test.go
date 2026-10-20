package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/agent-primitives/sessions/authn"
)

// The chart tests pin this same literal fixture to actual rendered host args.
func TestCanvasChartArgumentsUseProductionParser(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "charts", "aks-durable-agents", "tests", "canvas-host-args.json"))
	if err != nil {
		t.Fatal(err)
	}
	var args []string
	if err := json.Unmarshal(raw, &args); err != nil {
		t.Fatal(err)
	}
	c, err := parse(args)
	if err != nil {
		t.Fatal(err)
	}
	if !c.TrustedNetworkSessions || c.Mode != authn.Off || c.Addr != "0.0.0.0:8080" || c.HealthAddr != "127.0.0.1:8081" || c.TLSCert != "/tls/tls.crt" || c.TLSKey != "/tls/tls.key" || len(c.Harnesses) != 2 || c.ToolExecutors != "" || c.ModelCredential != nil {
		t.Fatalf("hosted chart args changed meaning: %+v", c)
	}
}

func TestTrustedNetworkSessionsFlag(t *testing.T) {
	c, err := parse([]string{"-sessions-trusted-network", "-addr=0.0.0.0:8080", "-auth-mode=off", "-tls-cert=/tls/tls.crt", "-tls-key=/tls/tls.key"})
	if err != nil {
		t.Fatal(err)
	}
	if !c.TrustedNetworkSessions || c.Addr != "0.0.0.0:8080" || c.Mode != authn.Off || c.HealthAddr != "127.0.0.1:8081" || c.ModelCredential != nil {
		t.Fatalf("private TLS flags changed meaning: %+v", c)
	}
	legacy, err := parse(nil)
	if err != nil || legacy.TrustedNetworkSessions || legacy.Addr != "127.0.0.1:8080" {
		t.Fatal("legacy listener defaults changed")
	}
}
