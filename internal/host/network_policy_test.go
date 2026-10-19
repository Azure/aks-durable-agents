package host

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agent-primitives/sessions/authn"
	"google.golang.org/grpc"
)

func TestHarnessServiceIsAnExactOptIn(t *testing.T) {
	const service = "fixture-harness.fixture-tests.svc.cluster.local:9000"
	base := Config{Addr: "127.0.0.1:0", HealthAddr: "127.0.0.1:0", Journal: ":memory:", Mode: authn.Off, Harnesses: map[string]string{"release-notes": service}}
	if err := base.validate(); err == nil {
		t.Fatal("unconfigured remote harness admitted")
	}
	base.HarnessService = service
	if err := base.validate(); err != nil {
		t.Fatal(err)
	}
	for _, addr := range []string{"other.fixture-tests.svc.cluster.local:9000", "fixture-harness.fixture-tests.svc.cluster.local:9001", "example.com:9000", "10.0.0.1:9000"} {
		c := base
		c.Harnesses = map[string]string{"release-notes": addr}
		if c.validate() == nil {
			t.Fatalf("different address admitted: %s", addr)
		}
	}
	for _, configured := range []string{"example.com:9000", "10.0.0.1:9000", "x..svc.cluster.local:9000", "x.ns.svc.cluster.local:09000"} {
		c := base
		c.HarnessService = configured
		c.Harnesses = map[string]string{"release-notes": configured}
		if c.validate() == nil {
			t.Fatalf("invalid service allowlist %s", configured)
		}
	}
}

func TestHarnessServicesKeepSeparatePortsExact(t *testing.T) {
	const first = "native.agents.svc.cluster.local:9000"
	const second = "native.agents.svc.cluster.local:9001"
	base := Config{Addr: "127.0.0.1:0", HealthAddr: "127.0.0.1:0", Journal: filepath.Join(t.TempDir(), "journal.db"), Mode: authn.Off, Harnesses: map[string]string{"writer": first, "reviewer": second}, HarnessService: first, HarnessServices: []string{second}}
	if err := base.validate(); err != nil {
		t.Fatal(err)
	}
	for _, services := range [][]string{nil, {first}, {second, second}, {""}, {"native.agents.svc.cluster.local:09001"}, {"native.agents.svc.cluster.local:90010"}, {"native.agents.svc.cluster.local.evil:9001"}, {"10.0.0.1:9001"}} {
		c := base
		c.HarnessServices = services
		if c.validate() == nil {
			t.Fatalf("invalid exact service configuration accepted: %v", services)
		}
		if _, err := newApplication(t.Context(), c, nil, nil); err == nil {
			t.Fatalf("unsafe or missing exact exception admitted: %v", services)
		}
		if _, err := os.Stat(c.Journal); !os.IsNotExist(err) {
			t.Fatal("invalid routes opened journal")
		}
	}
	for _, name := range []string{"bundle-v4-x", "bundle-v4-" + strings.Repeat("A", 64), "bundle-v4-" + strings.Repeat("a", 63)} {
		c := base
		c.Harnesses = map[string]string{name: first}
		if c.validate() == nil {
			t.Fatalf("malformed native digest accepted: %s", name)
		}
	}
	c := base
	c.Substrate = &SubstrateConfig{}
	if c.validate() == nil {
		t.Fatal("native endpoints mixed with substrate")
	}
}

func TestPlacementMismatchFailsBeforeJournalOpen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fixture-node.json")
	c := Config{Addr: "127.0.0.1:0", HealthAddr: "127.0.0.1:0", Journal: filepath.Join(dir, "journal.db"), Mode: authn.Off, Harnesses: map[string]string{"release-notes": "127.0.0.1:9000"}, PeerNodeFile: path, NodeName: "node-a"}
	for _, raw := range []string{`{"nodeName":"node-b","podUID":"peer"}`, `{"nodeName":"node-a"}`, `{"nodeName":"node-a","podUID":"peer","unknown":true}`} {
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := newApplication(t.Context(), c, nil, nil); err == nil {
			t.Fatal("invalid peer placement accepted")
		}
		if _, err := os.Stat(c.Journal); !os.IsNotExist(err) {
			t.Fatal("journal touched before placement refusal")
		}
	}
	if err := os.WriteFile(path, []byte(`{"nodeName":"node-a","podUID":"peer"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	c.NodeName = ""
	if c.validate() == nil {
		t.Fatal("missing local node admitted")
	}
}

func TestRPCDeadlinesBoundBothHandlerKinds(t *testing.T) {
	check := func(ctx context.Context) {
		t.Helper()
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 30*time.Second || time.Until(deadline) < 29*time.Second {
			t.Fatal("missing 30s RPC deadline")
		}
	}
	_, err := rpcUnaryDeadline(context.Background(), nil, &grpc.UnaryServerInfo{}, func(ctx context.Context, _ any) (any, error) { check(ctx); return nil, nil })
	if err != nil {
		t.Fatal(err)
	}
	err = rpcStreamDeadline(nil, &deadlineTestStream{ctx: context.Background()}, &grpc.StreamServerInfo{}, func(_ any, s grpc.ServerStream) error { check(s.Context()); return nil })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = rpcUnaryDeadline(ctx, nil, &grpc.UnaryServerInfo{}, func(got context.Context, _ any) (any, error) {
		d, _ := got.Deadline()
		want, _ := ctx.Deadline()
		if !d.Equal(want) {
			t.Fatal("earlier parent deadline extended")
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

type deadlineTestStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *deadlineTestStream) Context() context.Context { return s.ctx }
