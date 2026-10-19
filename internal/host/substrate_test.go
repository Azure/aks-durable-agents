package host

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agent-primitives/sessions/api"
	v1 "github.com/agent-primitives/sessions/api/genpb"
	"github.com/agent-primitives/sessions/authn"
	"github.com/agent-primitives/sessions/client"
	"github.com/agent-primitives/sessions/harnesswire"
	atepb "github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"google.golang.org/grpc"
	channelz "google.golang.org/grpc/channelz/grpc_channelz_v1"
	"google.golang.org/grpc/channelz/service"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Invalid control credentials must win over model validation and journal I/O.
func TestSubstrateTrustBeforeModelAndJournal(t *testing.T) {
	c := Config{Addr: "127.0.0.1:0", HealthAddr: "127.0.0.1:0", Mode: authn.Off, Journal: filepath.Join(t.TempDir(), "journal.db"),
		Substrate: &SubstrateConfig{Harness: "echo", ActorAtespace: "app", TemplateAtespace: "assets", Template: "echo-v1", ControlAddr: "127.0.0.1:7443", RouterAddr: "127.0.0.1:8080", CAFile: "/missing-ca", TokenFile: "/missing-token"}}
	a, err := newApplication(context.Background(), c, nil, nil)
	if a != nil {
		a.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "Substrate control CA") {
		t.Fatalf("control trust was not checked before model setup: %v", err)
	}
	if _, err := os.Stat(c.Journal); !os.IsNotExist(err) {
		t.Fatal("invalid control trust touched journal")
	}
}

type controlEvent struct {
	method, token string
	remaining     time.Duration
}

type controlFixture struct {
	atepb.UnimplementedControlServer
	sub     SubstrateConfig
	mu      sync.Mutex
	actors  map[string]*atepb.Actor
	created []*atepb.Actor
	events  chan controlEvent
	get     func(context.Context, *atepb.GetActorRequest) (*atepb.Actor, error)
}

func controlCertificate(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"control.test"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func newControlFixture(t *testing.T) *controlFixture {
	t.Helper()
	f := &controlFixture{actors: make(map[string]*atepb.Actor), events: make(chan controlEvent, 32)}
	cert, ca := controlCertificate(t)
	dir := t.TempDir()
	f.sub = SubstrateConfig{Harness: "release-notes", ActorAtespace: "app", TemplateAtespace: "assets", Template: "echo-v1", CAFile: filepath.Join(dir, "ca.pem"), TokenFile: filepath.Join(dir, "token"), RouterAddr: "127.0.0.1:8080"}
	for path, raw := range map[string][]byte{f.sub.CAFile: ca, f.sub.TokenFile: []byte("control-one\n")} {
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.sub.ControlAddr = ln.Addr().String()
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}})), grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
		md, _ := metadata.FromIncomingContext(ctx)
		deadline, _ := ctx.Deadline()
		f.events <- controlEvent{method: info.FullMethod, token: strings.Join(md.Get("authorization"), ","), remaining: time.Until(deadline)}
		return next(ctx, req)
	}))
	atepb.RegisterControlServer(server, f)
	service.RegisterChannelzServiceToServer(server)
	go server.Serve(ln)
	t.Cleanup(server.Stop)
	return f
}

func (f *controlFixture) GetActor(ctx context.Context, req *atepb.GetActorRequest) (*atepb.Actor, error) {
	if f.get != nil {
		return f.get(ctx, req)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	a := f.actors[req.GetActor().GetName()]
	if a == nil {
		return nil, status.Error(codes.NotFound, "missing")
	}
	return a, nil
}
func (f *controlFixture) CreateActor(_ context.Context, req *atepb.CreateActorRequest) (*atepb.Actor, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a := req.GetActor()
	f.created = append(f.created, a)
	a.Metadata.Uid = "compute-" + a.GetMetadata().GetName()
	a.Status = &atepb.ActorStatus{State: atepb.ActorState_ACTOR_STATE_SUSPENDED}
	f.actors[a.GetMetadata().GetName()] = a
	return a, nil
}
func (f *controlFixture) ResumeActor(_ context.Context, req *atepb.ResumeActorRequest) (*atepb.ResumeActorResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a := f.actors[req.GetActor().GetName()]
	if a == nil {
		return nil, status.Error(codes.NotFound, "missing")
	}
	a.Status.State = atepb.ActorState_ACTOR_STATE_RUNNING
	return &atepb.ResumeActorResponse{Actor: a}, nil
}

// Catches a cached credential, stripped caller deadline, or a wrong adapter/template mapping.
func TestSubstrateControlTLSRotationAndMapping(t *testing.T) {
	f := newControlFixture(t)
	f.sub.ControlServerName = "control.test"
	backend, conn, err := openSubstrate(f.sub, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for i, token := range []string{"control-one", "control-two"} {
		if err := os.WriteFile(f.sub.TokenFile, []byte(token+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		ctx := t.Context()
		cancel := func() {}
		if i == 1 {
			ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		}
		inc, err := backend.Create(ctx, &api.SessionSpec{SessionUID: "session" + token})
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		if inc.Address != "127.0.0.1:8080" || inc.Runtime != "substrate" || !reflect.DeepEqual(inc.CallMetadata, map[string]string{"ate-target-actor": "app/session" + token}) {
			t.Fatalf("wrong mapped incarnation: %+v", inc)
		}
		for _, method := range []string{"GetActor", "CreateActor", "ResumeActor"} {
			e := <-f.events
			if !strings.HasSuffix(e.method, "/"+method) || e.token != "Bearer "+token {
				t.Fatalf("wrong control routing/auth: %+v", e)
			}
			max := 2 * time.Minute
			if i == 1 {
				max = 5 * time.Second
			}
			if e.remaining <= max-time.Second || e.remaining > max {
				t.Fatalf("deadline not bounded or caller deadline lost: %v (max %v)", e.remaining, max)
			}
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, a := range f.created {
		if a.GetMetadata().GetAtespace() != "app" || a.GetActorTemplate().GetAtespace() != "assets" || a.GetActorTemplate().GetName() != "echo-v1" {
			t.Fatalf("wrong create mapping: %+v", a)
		}
	}
}

func TestSubstrateTLSRefusesWrongCAAndName(t *testing.T) {
	for _, wrong := range []string{"CA", "name"} {
		t.Run(wrong, func(t *testing.T) {
			f := newControlFixture(t)
			if wrong == "name" {
				f.sub.ControlServerName = "wrong.test"
			} else {
				_, otherCA := controlCertificate(t)
				if err := os.WriteFile(f.sub.CAFile, otherCA, 0600); err != nil {
					t.Fatal(err)
				}
			}
			backend, conn, err := openSubstrate(f.sub, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			if _, err := backend.Create(ctx, &api.SessionSpec{SessionUID: "blocked"}); err == nil {
				t.Fatal("untrusted control TLS accepted")
			}
			if len(f.events) != 0 {
				t.Fatal("untrusted TLS reached handler")
			}
		})
	}
}

func TestSubstrateTokenFailuresSanitizedBeforeHandler(t *testing.T) {
	f := newControlFixture(t)
	backend, conn, err := openSubstrate(f.sub, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for _, token := range []string{"", "\n", "secret\r\ninjected", "secret value", strings.Repeat("x", 16385), "bad-secret\x00", "bad-secret\u0080"} {
		t.Run("invalid token", func(t *testing.T) {
			if err := os.WriteFile(f.sub.TokenFile, []byte(token), 0600); err != nil {
				t.Fatal(err)
			}
			_, err := backend.Create(t.Context(), &api.SessionSpec{SessionUID: "blocked"})
			if err == nil || strings.Contains(err.Error(), "bad-secret") || strings.Contains(err.Error(), f.sub.TokenFile) || strings.Contains(err.Error(), "injected") {
				t.Fatalf("unsanitized/accepted token: %v", err)
			}
			if len(f.events) != 0 {
				t.Fatal("invalid credential reached handler")
			}
			c := Config{Addr: "127.0.0.1:0", HealthAddr: "127.0.0.1:0", Journal: filepath.Join(t.TempDir(), "journal.db"), Mode: authn.Off, Substrate: &f.sub}
			a, err := newApplication(t.Context(), c, nil, nil)
			if a != nil {
				a.Close()
			}
			if err == nil || !strings.Contains(err.Error(), "Substrate control token") {
				t.Fatalf("startup did not validate token before model: %v", err)
			}
			if _, err := os.Stat(c.Journal); !os.IsNotExist(err) {
				t.Fatal("bad token touched journal")
			}
		})
	}
	if err := os.Remove(f.sub.TokenFile); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.Create(t.Context(), &api.SessionSpec{SessionUID: "blocked"}); err == nil || strings.Contains(err.Error(), f.sub.TokenFile) {
		t.Fatalf("missing token not sanitized: %v", err)
	}
	if len(f.events) != 0 {
		t.Fatal("unreadable credential reached handler")
	}
}

func TestSubstrateCancellation(t *testing.T) {
	f := newControlFixture(t)
	entered := make(chan struct{})
	stopped := make(chan struct{})
	f.get = func(ctx context.Context, _ *atepb.GetActorRequest) (*atepb.Actor, error) {
		close(entered)
		<-ctx.Done()
		close(stopped)
		return nil, ctx.Err()
	}
	backend, conn, err := openSubstrate(f.sub, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := backend.Create(ctx, &api.SessionSpec{SessionUID: "cancel"}); done <- err }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("control not entered")
	}
	cancel()
	select {
	case err := <-done:
		if status.Code(err) != codes.Canceled && !errors.Is(err, context.Canceled) {
			t.Fatalf("lost cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("control call ignored cancellation")
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("server did not observe cancellation")
	}
}

type substrateEcho struct{}

func (substrateEcho) Describe(context.Context) (api.Descriptor, error) {
	return api.Descriptor{ID: "release-notes", Capabilities: api.Capabilities{Resumability: api.ResumabilityStatelessReplay}}, nil
}
func (substrateEcho) Run(ctx context.Context, s *api.Start, sink api.EventSink) error {
	return sink.Output(ctx, "echo: "+s.Inputs[0].Text())
}

// A failure after creating the lazy control connection must close it too.
func TestSubstrateLateStartupFailureCloses(t *testing.T) {
	f, control := newHostFixture(t), newControlFixture(t)
	_, observer, err := openSubstrate(control.sub, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close()
	channels := func() int {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()
		response, err := channelz.NewChannelzClient(observer).GetTopChannels(ctx, &channelz.GetTopChannelsRequest{})
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		for _, channel := range response.GetChannel() {
			if channel.GetData().GetTarget() == control.sub.ControlAddr {
				count++
			}
		}
		return count
	}
	before := channels()
	if before != 1 {
		t.Fatalf("expected exactly the observer connection, got %d", before)
	}
	f.config.Harnesses, f.config.Substrate = nil, &control.sub
	f.config.Journal = t.TempDir() // Opening a directory fails after backend setup.
	app, err := newApplication(t.Context(), f.config, fixtureCredential{t}, nil)
	if app != nil {
		app.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "open journal") {
		t.Fatalf("did not reach intended late startup failure: %v", err)
	}
	if after := channels(); after != before {
		t.Fatalf("late startup failure leaked control connection: %d -> %d", before, after)
	}
}

// Uses the actual host registry, adapter and placement dialer, not a metadata helper.
func TestSubstrateHostRoutesAndCloses(t *testing.T) {
	f, control := newHostFixture(t), newControlFixture(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	routed := make(chan metadata.MD, 8)
	router := grpc.NewServer(grpc.StreamInterceptor(func(srv any, stream grpc.ServerStream, _ *grpc.StreamServerInfo, next grpc.StreamHandler) error {
		md, _ := metadata.FromIncomingContext(stream.Context())
		routed <- md
		return next(srv, stream)
	}))
	v1.RegisterHarnessServer(router, harnesswire.NewServer(substrateEcho{}))
	go router.Serve(ln)
	t.Cleanup(router.Stop)
	control.sub.RouterAddr = ln.Addr().String()
	f.config.Harnesses, f.config.Substrate = nil, &control.sub
	app, c, _ := f.start(t)
	ctx, cancel := context.WithTimeout(bearer(t.Context(), "Bearer user-not-control"), 5*time.Second)
	defer cancel()
	result, err := c.Exec(ctx, client.ExecOptions{Harness: "release-notes", Inputs: []string{"hello"}})
	if err != nil {
		t.Fatal(err)
	}
	uid := result.Session.GetMetadata().GetUid()
	md := <-routed
	if !reflect.DeepEqual(md.Get("ate-target-actor"), []string{"app/" + uid}) || len(md.Get("authorization")) != 0 {
		t.Fatalf("wrong/private router metadata: %v", md)
	}
	for _, method := range []string{"GetActor", "CreateActor", "ResumeActor"} {
		e := <-control.events
		if !strings.HasSuffix(e.method, "/"+method) || e.token != "Bearer control-one" {
			t.Fatalf("host did not use real adapter with its own credential: %+v", e)
		}
	}
	records, err := c.Replay(ctx, uid, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range records {
		for _, part := range r.GetEvent().GetMessage().GetParts() {
			if part.GetText().GetText() == "echo: hello" {
				found = true
			}
		}
	}
	if !found || f.models.Load() != 0 || f.sockets.Load() != 0 {
		t.Fatal("Substrate execution skipped harness or caused model/tool side effects")
	}
	var conn *grpc.ClientConn
	for _, closer := range app.backends {
		if cc, ok := closer.(*grpc.ClientConn); ok {
			conn = cc
		}
	}
	if conn == nil {
		t.Fatal("control connection not owned by application")
	}
	app.Close()
	app.Close()
	if conn.GetState() != connectivity.Shutdown {
		t.Fatal("shutdown leaked control connection")
	}
}
