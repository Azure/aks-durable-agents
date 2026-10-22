package sessionfixture

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"

	"github.com/agent-primitives/sessions/api"
	v1 "github.com/agent-primitives/sessions/api/genpb"
	"github.com/agent-primitives/sessions/harnesswire"
	"google.golang.org/grpc"
)

// ActorHarness returns the frozen v2 harness without host-state initialization.
// Models and effects travel on the host-initiated harnesswire stream; this
// process needs no host PVC, executor socket, credentials or placement marker.
func ActorHarness() api.Harness { return newHarnessScenario("v2") }

func runActorHarness(ctx context.Context, addr string, check bool, out io.Writer) error {
	if addr != "0.0.0.0:80" {
		if err := harnessAddress(addr, "v1", true); err != nil {
			return fmt.Errorf("actor harness requires port80 or literal loopback: %w", err)
		}
	}
	h := ActorHarness()
	if check {
		d, err := h.Describe(ctx)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(map[string]any{"version": 1, "mode": "actor-v2", "harness": d.ID, "protocol": "harnesswire", "port": 80, "resumability": "STATELESS_REPLAY", "descriptor": d.Version})
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer listener.Close()
	server := grpc.NewServer()
	defer server.Stop()
	v1.RegisterHarnessServer(server, harnesswire.NewServer(h))
	if err := json.NewEncoder(out).Encode(map[string]any{"addr": listener.Addr().String(), "mode": "actor-v2", "harness": "release-notes", "resumability": "STATELESS_REPLAY"}); err != nil {
		return err
	}
	return serveGRPC(ctx, server, listener)
}
