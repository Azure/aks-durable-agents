package entraauth

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agent-primitives/sessions/authn"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type callerHealthServer struct {
	healthpb.UnimplementedHealthServer
	calls atomic.Int32
}

func (s *callerHealthServer) response(ctx context.Context) (*healthpb.HealthCheckResponse, error) {
	s.calls.Add(1)
	caller, ok := authn.Caller(ctx)
	if !ok || caller.Issuer != issuer || caller.Subject != objectID {
		return nil, status.Error(codes.Internal, "handler did not receive exact verified caller")
	}
	return &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_SERVING}, nil
}

func (s *callerHealthServer) Check(ctx context.Context, _ *healthpb.HealthCheckRequest) (*healthpb.HealthCheckResponse, error) {
	return s.response(ctx)
}

func (s *callerHealthServer) Watch(_ *healthpb.HealthCheckRequest, stream healthpb.Health_WatchServer) error {
	response, err := s.response(stream.Context())
	if err != nil {
		return err
	}
	return stream.Send(response)
}

// Omitting either real interceptor, admitting bad credentials, or replacing the
// verified oid with sub/forwarded metadata must fail this composition test.
func TestGRPCAuthentication(t *testing.T) {
	f := fixture(t) // Offline TLS discovery/JWKS; no public network fallback.
	life, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	v, err := New(life, f.config())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(v.Close)
	unary, stream, err := authn.NewInterceptors(authn.Required, v)
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(grpc.ChainUnaryInterceptor(unary), grpc.ChainStreamInterceptor(stream))
	handler := &callerHealthServer{}
	healthpb.RegisterHealthServer(server, handler)
	listener := bufconn.Listen(1024 * 1024)
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
		if err := <-serveErr; err != nil && err != grpc.ErrServerStopped {
			t.Errorf("serve: %v", err)
		}
	})
	// Only the in-memory gRPC hop is insecure; this is not host TLS activation.
	conn, err := grpc.NewClient("passthrough:///entraauth-test",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return listener.DialContext(ctx)
		}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := healthpb.NewHealthClient(conn)
	key, other := testKeys(t)
	// Use wall time, not the fixture's private clock: #180 checks time.Now().
	c := claims(time.Now())
	good := "Bearer " + signed(t, c, "initial", key, nil)
	badSignature := "Bearer " + signed(t, c, "initial", other, nil)
	for _, rpc := range []struct {
		name   string
		invoke func(context.Context) (*healthpb.HealthCheckResponse, error)
	}{
		{"unary", func(ctx context.Context) (*healthpb.HealthCheckResponse, error) {
			return client.Check(ctx, &healthpb.HealthCheckRequest{})
		}},
		{"stream", func(ctx context.Context) (*healthpb.HealthCheckResponse, error) {
			stream, err := client.Watch(ctx, &healthpb.HealthCheckRequest{})
			if err != nil {
				return nil, err
			}
			return stream.Recv()
		}},
	} {
		t.Run(rpc.name, func(t *testing.T) {
			for _, tc := range []struct {
				name   string
				values []string
				want   codes.Code
			}{
				{"verified despite spoofed identity", []string{good}, codes.OK},
				{"invalid signature", []string{badSignature}, codes.Unauthenticated},
				{"malformed", []string{"Bearer " + secret}, codes.Unauthenticated},
				{"duplicate", []string{good, good}, codes.Unauthenticated},
				{"forwarded identity without credentials", nil, codes.Unauthenticated},
			} {
				t.Run(tc.name, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					ctx = metadata.NewOutgoingContext(ctx, metadata.MD{
						"authorization":       tc.values,
						"x-forwarded-issuer":  {"https://forged.invalid"},
						"x-forwarded-subject": {"forged-subject"},
					})
					before := handler.calls.Load()
					response, err := rpc.invoke(ctx)
					if got := status.Code(err); got != tc.want {
						t.Errorf("status = %s, want %s", got, tc.want)
					}
					var wantCalls int32
					if tc.want == codes.OK {
						wantCalls = 1
						if response == nil || response.Status != healthpb.HealthCheckResponse_SERVING {
							t.Error("verified caller did not reach identity-checking handler")
						}
					} else if err == nil {
						t.Error("invalid credentials did not return an error")
					} else if st := status.Convert(err); st.Message() != "authentication required" || len(st.Details()) != 0 {
						t.Error("authentication rejection exposed non-generic diagnostics")
					}
					if got := handler.calls.Load() - before; got != wantCalls {
						t.Errorf("handler calls = %d, want %d", got, wantCalls)
					}
				})
			}
		})
	}
}
