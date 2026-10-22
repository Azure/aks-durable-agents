//go:build squadproof

package squadproof

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/Azure/aks-durable-agents/internal/socketexec"
	"github.com/Azure/aks-durable-agents/modeltransport"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/agent-primitives/sessions/api"
	v1 "github.com/agent-primitives/sessions/api/genpb"
	"github.com/agent-primitives/sessions/authn"
	"github.com/agent-primitives/sessions/model/openai"
	"github.com/agent-primitives/sessions/placement"
	"github.com/agent-primitives/sessions/runtime/remote"
	"github.com/agent-primitives/sessions/session"
	"github.com/agent-primitives/sessions/sqlitelog"
	"google.golang.org/grpc"
)

type ProofHostConfig struct {
	Data, Addr, Lead, Member string
	proofOnly                bool
}

func localAddress(address string, zero bool) bool {
	name, port, err := net.SplitHostPort(address)
	n, e := strconv.Atoi(port)
	return err == nil && e == nil && net.ParseIP(name).IsLoopback() && n >= 0 && n <= 65535 && (zero || n > 0)
}
func privateDirectory(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil || real != path {
		return false
	}
	st, err := os.Stat(path)
	if err != nil || !st.IsDir() || st.Mode().Perm() != 0700 {
		return false
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	return ok && int(owner.Uid) == os.Getuid()
}
func (c ProofHostConfig) valid() bool {
	return c.proofOnly && privateDirectory(c.Data) && localAddress(c.Addr, true) && localAddress(c.Lead, false) && localAddress(c.Member, false) && c.Lead != c.Member
}
func HostConfig(args []string) (ProofHostConfig, error) {
	var c ProofHostConfig
	fs := flag.NewFlagSet("proof-host", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.BoolVar(&c.proofOnly, "proof-only", false, "explicit isolated proof opt-in")
	fs.StringVar(&c.Data, "data", "", "existing private proof directory")
	fs.StringVar(&c.Addr, "addr", "127.0.0.1:8080", "literal loopback Sessions address")
	fs.StringVar(&c.Lead, "lead", "127.0.0.1:9000", "literal loopback lead harness")
	fs.StringVar(&c.Member, "member", "127.0.0.1:9001", "literal loopback member harness")
	if fs.Parse(args) != nil || fs.NArg() != 0 || !c.valid() {
		return ProofHostConfig{}, ErrInvalid
	}
	return c, nil
}

type proofCredential struct{}

func (proofCredential) GetToken(_ context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	if len(opts.Scopes) != 1 || opts.Scopes[0] != modeltransport.DefaultScope {
		return azcore.AccessToken{}, ErrInvalid
	}
	return azcore.AccessToken{Token: proofToken, ExpiresOn: time.Now().Add(time.Hour)}, nil
}
func proofModel(l *Ledger) (*openai.Client, func(), error) {
	provider := httptest.NewTLSServer(&fakeModel{ledger: l})
	roots := x509.NewCertPool()
	roots.AddCert(provider.Certificate())
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: provider.Certificate().IPAddresses[0].String()}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "proof-model.invalid:443" {
			return nil, ErrInvalid
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", provider.Listener.Addr().String())
	}}
	cleanup := func() { transport.CloseIdleConnections(); provider.Close() }
	httpClient, err := modeltransport.NewClient(modeltransport.Config{Endpoint: proofEndpoint, Deployment: "proof-model", Credential: proofCredential{}, Transport: transport})
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	model, err := openai.New(openai.WithBaseURL(proofEndpoint), openai.WithModel("proof-model"), openai.WithHTTPClient(httpClient))
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	return model, cleanup, nil
}

func proofJournal(ctx context.Context, l *Ledger, data string) (*sqlitelog.Store, error) {
	path := filepath.Join(data, "journal.db")
	var marker string
	err := l.db.QueryRowContext(ctx, `SELECT operation FROM events WHERE kind='runtime-host' LIMIT 1`).Scan(&marker)
	fresh := errors.Is(err, sql.ErrNoRows)
	if err != nil && !fresh {
		return nil, err
	}
	if !fresh && marker != proofDigest() {
		return nil, ErrForeign
	}
	// SQLite may open or remove sidecars before recognizing the main database.
	// Never initialize beside foreign evidence or follow sidecar symlinks.
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		st, sideErr := os.Lstat(path + suffix)
		if errors.Is(sideErr, os.ErrNotExist) {
			continue
		}
		if sideErr != nil || fresh || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 {
			return nil, ErrForeign
		}
		owner, ok := st.Sys().(*syscall.Stat_t)
		if !ok || int(owner.Uid) != os.Getuid() {
			return nil, ErrForeign
		}
	}
	flags := os.O_RDWR | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	if fresh {
		flags |= os.O_CREATE | os.O_EXCL
	}
	f, err := os.OpenFile(path, flags, 0600)
	if err != nil {
		return nil, ErrForeign
	}
	st, err := f.Stat()
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return nil, ErrInvalid
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || !ok || int(owner.Uid) != os.Getuid() {
		return nil, ErrInvalid
	}
	store, err := sqlitelog.Open(path)
	if err != nil {
		return nil, err
	}
	if fresh {
		err = l.transaction(ctx, func(c *sql.Conn) error { return event(ctx, c, "runtime-host", proofDigest()) })
		if err != nil {
			store.Close()
			return nil, err
		}
	}
	return store, nil
}

// RunHost is an isolated proof composition of production's public Sessions
// components. It does not call or weaken the production host/model policy gate.
func RunHost(ctx context.Context, c ProofHostConfig, ready func(string)) error {
	if !c.valid() {
		return ErrInvalid
	}
	l, err := OpenLedger(filepath.Join(c.Data, "proof.db"))
	if err != nil {
		return err
	}
	defer l.Close()
	routes := map[string]string{"proof-lead": c.Lead, "proof-member": c.Member}
	entries := []map[string]any{}
	for role, tools := range map[string][]string{"lead": {"dispatch_member", "read_context", "checkpoint"}, "member": {"read_context", "publish"}} {
		for _, tool := range tools {
			entries = append(entries, map[string]any{"harness": "proof-" + role, "tool": tool, "executor": "proof", "durable_dedup": true})
		}
	}
	file, err := os.CreateTemp(c.Data, "proof-tools-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	err = json.NewEncoder(file).Encode(map[string]any{"version": 1, "executors": []any{map[string]any{"name": "proof", "type": "unix", "socket": filepath.Join(c.Data, "tools.sock")}}, "tools": entries})
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	bindings, err := socketexec.LoadBindings(file.Name(), routes)
	if err != nil {
		return err
	}
	model, cleanup, err := proofModel(l)
	if err != nil {
		return err
	}
	defer cleanup()
	call := func(ctx context.Context, r api.ModelRequest) (api.ModelResponse, error) {
		if r.Model != "proof-model" || len(r.Params) != 0 {
			return api.ModelResponse{}, ErrInvalid
		}
		bounded, cancel := context.WithTimeout(ctx, 25*time.Second)
		defer cancel()
		return model.Model(bounded, r)
	}
	stream := func(ctx context.Context, r api.ModelRequest, chunk func(string)) (api.ModelResponse, error) {
		if r.Model != "proof-model" || len(r.Params) != 0 {
			return api.ModelResponse{}, ErrInvalid
		}
		bounded, cancel := context.WithTimeout(ctx, 25*time.Second)
		defer cancel()
		return model.StreamModel(bounded, r, chunk)
	}
	placers := map[string]*placement.Placer{}
	for name, address := range routes {
		backend := remote.New(address)
		defer backend.Close()
		binding := bindings[name]
		placers[name] = placement.New(backend, call, placement.WithDescriptorID(name), placement.WithStreamingModel(stream), placement.WithToolExecutor(binding.Execute), placement.WithDurableDedup(binding.DurableDedup))
	}
	registry, err := placement.NewRegistry("proof-lead", placers)
	if err != nil {
		return err
	}
	store, err := proofJournal(ctx, l, c.Data)
	if err != nil {
		return err
	}
	defer store.Close()
	if err = session.ReserveStaticHarnessNames(store, registry); err != nil {
		return err
	}
	unary, streamAuth, err := authn.NewInterceptors(authn.Off, nil)
	if err != nil {
		return err
	}
	server := grpc.NewServer(grpc.ChainUnaryInterceptor(proofUnaryDeadline, unary), grpc.ChainStreamInterceptor(proofStreamDeadline, streamAuth), grpc.WaitForHandlers(true))
	defer server.Stop()
	v1.RegisterSessionsServer(server, session.NewService(store, registry))
	listener, err := net.Listen("tcp", c.Addr)
	if err != nil {
		return err
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	if ready != nil {
		ready(listener.Addr().String())
	}
	select {
	case err = <-done:
		return err
	case <-ctx.Done():
	}
	drained := make(chan struct{})
	go func() { server.GracefulStop(); close(drained) }()
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	select {
	case <-drained:
	case <-timer.C:
		server.Stop()
		<-drained
	}
	err = <-done
	if errors.Is(err, grpc.ErrServerStopped) {
		return nil
	}
	return err
}
func proofUnaryDeadline(ctx context.Context, req any, info *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return next(bounded, req)
}

type proofStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s proofStream) Context() context.Context { return s.ctx }
func proofStreamDeadline(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, next grpc.StreamHandler) error {
	bounded, cancel := context.WithTimeout(stream.Context(), 30*time.Second)
	defer cancel()
	return next(srv, proofStream{stream, bounded})
}
