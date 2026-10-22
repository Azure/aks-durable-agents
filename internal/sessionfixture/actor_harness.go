package sessionfixture

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

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
		return json.NewEncoder(out).Encode(map[string]any{"version": 1, "mode": "actor-v2", "harness": d.ID, "protocol": "harnesswire", "port": 80, "resumability": "STATELESS_REPLAY", "descriptor": d.Version, "readinessPort": 8081, "readinessPath": "/readyz"})
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer listener.Close()
	readyAddr := "0.0.0.0:8081"
	if addr != "0.0.0.0:80" {
		host, _, _ := net.SplitHostPort(addr) // validated literal loopback above
		readyAddr = net.JoinHostPort(host, "0")
	}
	readyListener, err := net.Listen("tcp", readyAddr)
	if err != nil {
		return err
	}
	defer readyListener.Close()
	server := grpc.NewServer()
	defer server.Stop()
	v1.RegisterHarnessServer(server, harnesswire.NewServer(h))
	if err := json.NewEncoder(out).Encode(map[string]any{"addr": listener.Addr().String(), "readinessAddr": readyListener.Addr().String(), "mode": "actor-v2", "harness": "release-notes", "resumability": "STATELESS_REPLAY"}); err != nil {
		return err
	}
	// Native wakeup polls this only after the harness listener is bound. A
	// started process alone is not readiness for the first Describe after Resume.
	serveCtx, stop := context.WithCancel(ctx)
	defer stop()
	ready := &http.Server{ReadHeaderTimeout: time.Second, WriteTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/readyz" || r.URL.RawQuery != "" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	})}
	readyDone := make(chan error, 1)
	go func() {
		readyDone <- ready.Serve(readyListener)
		stop()
	}()
	grpcErr := serveGRPC(serveCtx, server, listener)
	closeErr := ready.Close()
	readyErr := <-readyDone
	if grpcErr != nil {
		return grpcErr
	}
	if readyErr != nil && !errors.Is(readyErr, http.ErrServerClosed) {
		return readyErr
	}
	return closeErr
}
