package host

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/agent-primitives/sessions/api"
	ateadapter "github.com/agent-primitives/sessions/integrations/substrate"
	"github.com/agent-primitives/sessions/runtime/substrate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// SubstrateConfig selects one stateless-replay harness instead of remote fixtures.
// The control API uses verified TLS; RouterAddr is private, trusted-network h2c.
type SubstrateConfig struct {
	Harness, ActorAtespace, TemplateAtespace, Template            string
	ControlAddr, ControlServerName, CAFile, TokenFile, RouterAddr string
	PlacementFile                                                 string
}

func (s SubstrateConfig) validate() error {
	for _, name := range []string{s.Harness, s.ActorAtespace, s.TemplateAtespace, s.Template} {
		if !dnsLabel.MatchString(name) {
			return errors.New("substrate harness, atespaces and template must be DNS labels")
		}
	}
	if !substrateEndpoint(s.ControlAddr) || !substrateEndpoint(s.RouterAddr) {
		return errors.New("substrate control and router endpoints require literal loopback or exact service.namespace.svc.cluster.local:port with nonzero port")
	}
	if s.CAFile == "" || s.TokenFile == "" {
		return errors.New("substrate control requires CA and token files")
	}
	return nil
}

// openSubstrate validates local trust/credentials before any journal or model I/O.
// TLS is verified on the first RPC; dialing is lazy and the application owns conn.
func openSubstrate(s SubstrateConfig, logger *slog.Logger) (*substrate.Backend, *grpc.ClientConn, error) {
	if err := s.validate(); err != nil {
		return nil, nil, err
	}
	pem, err := readControlFile(s.CAFile, 1<<20)
	roots := x509.NewCertPool()
	if err != nil || !roots.AppendCertsFromPEM(pem) {
		return nil, nil, errors.New("cannot read valid Substrate control CA")
	}
	token := controlTokenFile(s.TokenFile)
	if _, err := token.GetRequestMetadata(context.Background()); err != nil {
		return nil, nil, err
	}
	name := s.ControlServerName
	if name == "" {
		name, _, _ = net.SplitHostPort(s.ControlAddr)
	}
	conn, err := grpc.NewClient(s.ControlAddr,
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: name})),
		grpc.WithPerRPCCredentials(token), grpc.WithUnaryInterceptor(substrateControlRPC(s.PlacementFile)))
	if err != nil {
		return nil, nil, errors.New("cannot configure Substrate control connection")
	}
	desc := api.Descriptor{ID: s.Harness, Capabilities: api.Capabilities{Resumability: api.ResumabilityStatelessReplay}}
	backend := substrate.New(ateadapter.New(conn), s.ActorAtespace, substrate.ObjectRef{Atespace: s.TemplateAtespace, Name: s.Template}, desc, substrate.WithRouter(s.RouterAddr), substrate.WithLogger(logger), substrate.WithVolumesOnly())
	return backend, conn, nil
}

// All control methods used by this pinned adapter are unary. Earlier caller
// deadlines/cancellation win; long lifecycle operations cannot hang indefinitely.
func boundControlRPC(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoke grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	return invoke(ctx, method, req, reply, cc, opts...)
}

type controlTokenFile string

var bearerToken = regexp.MustCompile(`^[A-Za-z0-9._~+/-]+=*$`)

func (p controlTokenFile) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	raw, err := readControlFile(string(p), 16384)
	if err != nil {
		return nil, errors.New("cannot read bounded Substrate control token")
	}
	token := strings.TrimSpace(string(raw))
	if !bearerToken.MatchString(token) {
		return nil, errors.New("invalid Substrate control token")
	}
	return map[string]string{"authorization": "Bearer " + token}, nil
}
func (controlTokenFile) RequireTransportSecurity() bool { return true }

// Projected credential symlinks may rotate. Reopen each time, refuse special
// files without blocking. Both callers replace OS errors to hide secret paths.
func readControlFile(path string, max int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > max {
		return nil, errors.New("not a bounded regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(raw)) > max {
		return nil, errors.New("cannot read bounded file")
	}
	return raw, nil
}

func substrateEndpoint(addr string) bool {
	_, port, err := net.SplitHostPort(addr)
	n, e := strconv.Atoi(port)
	return err == nil && e == nil && n > 0 && n <= 65535 && strconv.Itoa(n) == port && (loopback(addr) || inClusterService(addr))
}
