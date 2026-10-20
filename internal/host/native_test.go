package host

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/agent-primitives/sessions/api"
	v1 "github.com/agent-primitives/sessions/api/genpb"
	"github.com/agent-primitives/sessions/client"
	"github.com/agent-primitives/sessions/harnesswire"
	"google.golang.org/grpc"
)

func TestNativeDescriptorMismatchStopsBeforeModel(t *testing.T) {
	f := newHostFixture(t)
	id := "bundle-v4-" + strings.Repeat("a", 64)
	address := f.config.Harnesses["release-notes"]
	f.config.Harnesses = map[string]string{id: address}
	f.config.ToolExecutors = ""
	_, cl, _ := f.start(t)
	if _, err := cl.Exec(t.Context(), client.ExecOptions{Harness: id, Inputs: []string{"draft"}}); err == nil {
		t.Fatal("descriptor mismatch accepted")
	}
	if f.models.Load() != 0 || f.harness.runs.Load() != 0 {
		t.Fatal("wrong descriptor reached harness or model")
	}
}

type namedStructuredHarness struct {
	structuredHarness
	id string
}

func (h namedStructuredHarness) Describe(ctx context.Context) (api.Descriptor, error) {
	d, err := h.structuredHarness.Describe(ctx)
	d.ID = h.id
	return d, err
}

func TestNativeRoutesKeepExactIdentityAcrossRestart(t *testing.T) {
	f := newHostFixture(t)
	f.config.ToolExecutors = ""
	f.config.Harnesses = map[string]string{}
	ids := []string{"bundle-v4-" + strings.Repeat("a", 64), "bundle-v4-" + strings.Repeat("b", 64)}
	for _, id := range ids {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		server := grpc.NewServer()
		v1.RegisterHarnessServer(server, harnesswire.NewServer(namedStructuredHarness{id: id}))
		go server.Serve(ln)
		t.Cleanup(server.Stop)
		f.config.Harnesses[id] = ln.Addr().String()
	}
	_, cl, stop := f.start(t)
	if _, err := cl.Exec(t.Context(), client.ExecOptions{Harness: ids[0], Inputs: []string{"writer"}}); err != nil {
		t.Fatal(err)
	}
	stop()
	_, cl, _ = f.start(t)
	if _, err := cl.Exec(t.Context(), client.ExecOptions{Harness: ids[1], Inputs: []string{"reviewer"}}); err != nil {
		t.Fatal(err)
	}
	if f.models.Load() != 2 {
		t.Fatalf("model calls=%d", f.models.Load())
	}
}
