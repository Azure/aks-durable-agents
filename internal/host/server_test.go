package host

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/agent-primitives/sessions/api"
	v1 "github.com/agent-primitives/sessions/api/genpb"
	"github.com/agent-primitives/sessions/authn"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	reflectionpb "google.golang.org/grpc/reflection/grpc_reflection_v1"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type probeService struct {
	v1.UnimplementedSessionsServer
}

func (*probeService) GetSession(context.Context, *v1.GetSessionRequest) (*v1.Session, error) {
	return &v1.Session{}, nil
}
func (*probeService) Replay(_ *v1.ReplayRequest, stream grpc.ServerStreamingServer[v1.LogRecord]) error {
	<-stream.Context().Done()
	return stream.Context().Err()
}

type expiringVerifier struct{}

func (expiringVerifier) Verify(context.Context) (authn.VerifiedCaller, error) {
	return authn.VerifiedCaller{Identity: api.CallerIdentity{Issuer: "issuer", Subject: "owner"}, ValidUntil: time.Now().Add(80 * time.Millisecond)}, nil
}

func dialServer(t *testing.T, s *grpc.Server) *grpc.ClientConn {
	t.Helper()
	l := bufconn.Listen(1 << 20)
	done := make(chan error, 1)
	go func() { done <- s.Serve(l) }()
	t.Cleanup(func() { s.Stop(); _ = l.Close(); <-done })
	conn, err := grpc.NewClient("passthrough:///host-test", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return l.DialContext(ctx) }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestServersSeparateServices(t *testing.T) {
	svc := &probeService{}
	sessions, health, err := newServers(authn.Required, testVerifier{api.CallerIdentity{Issuer: "issuer", Subject: "owner"}}, svc, nil)
	if err != nil {
		t.Fatal(err)
	}
	conn := dialServer(t, sessions)
	ops := dialServer(t, health)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("Sessions listener exposes health: %v", err)
	}
	_, err = v1.NewSessionsClient(ops).GetSession(ctx, &v1.GetSessionRequest{Uid: "session"})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("ops listener exposes Sessions: %v", err)
	}
	if _, err = healthpb.NewHealthClient(ops).Check(ctx, &healthpb.HealthCheckRequest{}); err != nil {
		t.Fatal(err)
	}
	stream, err := reflectionpb.NewServerReflectionClient(ops).ServerReflectionInfo(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = stream.Send(&reflectionpb.ServerReflectionRequest{MessageRequest: &reflectionpb.ServerReflectionRequest_ListServices{ListServices: ""}}); err != nil {
		t.Fatal(err)
	}
	reply, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	for _, service := range reply.GetListServicesResponse().Service {
		if service.Name == "agentsessions.v1.Sessions" {
			t.Fatal("ops reflection discloses Sessions")
		}
	}
}

func TestServerBoundsStreamByCredentialExpiry(t *testing.T) {
	sessions, health, err := newServers(authn.Required, expiringVerifier{}, &probeService{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer health.Stop()
	conn := dialServer(t, sessions)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stream, err := v1.NewSessionsClient(conn).Replay(ctx, &v1.ReplayRequest{Session: "session"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = stream.Recv()
	if err == nil || err == io.EOF || ctx.Err() != nil {
		t.Fatalf("stream not expired before caller deadline: %v", err)
	}
}
