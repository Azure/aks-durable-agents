package host

import (
	"context"
	"time"

	"github.com/agent-primitives/sessions/api"
	v1 "github.com/agent-primitives/sessions/api/genpb"
	"github.com/agent-primitives/sessions/authn"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

// Deadline cancellation is not a rollback guarantee: sessions persistence may
// continue. Operators must reconcile the original journal/ledger after timeout.
func rpcUnaryDeadline(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return handler(bounded, req)
}

type rpcDeadlineStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *rpcDeadlineStream) Context() context.Context { return s.ctx }
func rpcStreamDeadline(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	bounded, cancel := context.WithTimeout(stream.Context(), 30*time.Second)
	defer cancel()
	return handler(srv, &rpcDeadlineStream{ServerStream: stream, ctx: bounded})
}

func newServers(mode authn.Mode, verifier authn.CallerVerifier, policy api.Authorizer, svc v1.SessionsServer, transport grpc.ServerOption) (*grpc.Server, *grpc.Server, error) {
	unary, stream, err := authn.NewInterceptors(mode, verifier)
	if err != nil {
		return nil, nil, err
	}
	interceptors := []grpc.UnaryServerInterceptor{rpcUnaryDeadline, unary}
	if mode == authn.Required {
		interceptors = append(interceptors, approvalGate(policy))
	}
	opts := []grpc.ServerOption{grpc.ChainUnaryInterceptor(interceptors...), grpc.ChainStreamInterceptor(rpcStreamDeadline, stream), grpc.WaitForHandlers(true)}
	if transport != nil {
		opts = append(opts, transport)
	}
	s := grpc.NewServer(opts...)
	v1.RegisterSessionsServer(s, svc)
	ops := grpc.NewServer()
	h := health.NewServer()
	h.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(ops, h)
	reflection.Register(ops)
	return s, ops, nil
}
