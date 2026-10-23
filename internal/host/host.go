package host

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/Azure/aks-durable-agents/entraauth"
	"github.com/Azure/aks-durable-agents/internal/socketexec"
	"github.com/Azure/aks-durable-agents/modeltransport"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/agent-primitives/sessions/api"
	"github.com/agent-primitives/sessions/authn"
	"github.com/agent-primitives/sessions/placement"
	"github.com/agent-primitives/sessions/runtime/remote"
	"github.com/agent-primitives/sessions/session"
	"github.com/agent-primitives/sessions/sqlitelog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type application struct {
	sessions, health *grpc.Server
	store            *sqlitelog.Store
	verifier         *entraauth.Verifier
	modelPolicy      *modeltransport.Policy
	backends         []io.Closer
	once             sync.Once
}

func newApplication(ctx context.Context, c Config, credential azcore.TokenCredential, logger *slog.Logger) (app *application, err error) {
	if err = c.validate(); err != nil {
		return nil, err
	}
	// Validate operator routes and TLS before journal migration or identity I/O.
	harnesses := c.Harnesses
	if c.Substrate != nil {
		// socketexec consumes only static names, not remote endpoint values.
		harnesses = map[string]string{c.Substrate.Harness: ""}
	}
	tools, err := socketexec.LoadBindings(c.ToolExecutors, harnesses)
	if err != nil {
		return nil, err
	}
	var transport grpc.ServerOption
	if c.TLSCert != "" {
		cert, e := tls.LoadX509KeyPair(c.TLSCert, c.TLSKey)
		if e != nil {
			return nil, errors.New("cannot load host TLS certificate/key")
		}
		transport = grpc.Creds(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}))
	}
	a := &application{}
	defer func() {
		if err != nil {
			a.Close()
		}
	}()
	var substrateBackend placement.Backend
	if c.Substrate != nil {
		backend, conn, e := openSubstrate(*c.Substrate, logger)
		if e != nil {
			return nil, e
		}
		substrateBackend = backend
		a.backends = append(a.backends, conn)
		if logger != nil {
			logger.Warn("Substrate router uses trusted-network private h2c; single host, recovery authority not yet boot-scoped")
		}
	}
	if c.ModelPolicy != "" {
		a.modelPolicy, err = modeltransport.OpenPolicyFile(c.ModelPolicy)
		if err != nil {
			return nil, fmt.Errorf("open bounded model policy: %w", err)
		}
		if logger != nil {
			logger.Info("explicit host model policy enabled", "input_limit", a.modelPolicy.InputLimit(), "max_completion_tokens", 4096, "max_posts", a.modelPolicy.AttemptLimit(), "model_deadline_seconds", 25, "ledger", "durable")
		}
	}
	model, err := newChatModel(c, a.modelPolicy, credential)
	if err != nil {
		return nil, err
	}
	var verifier authn.CallerVerifier
	approval := newApprovalPolicy(c.Approvers)
	if c.Mode == authn.Required {
		authLog := logger
		if authLog == nil {
			authLog = slog.New(slog.DiscardHandler)
		}
		identity := c.Identity
		if identity.OnRefreshError == nil {
			identity.OnRefreshError = refreshErrorLogger(authLog, time.Now)
		}
		a.verifier, err = newEntraVerifier(ctx, identity)
		if err != nil {
			return nil, err
		}
		logged := newLoggingVerifier(a.verifier, authLog, time.Now)
		verifier = logged
		if len(identity.ApproverRoles) > 0 {
			approval.verifyApproval = func(ctx context.Context) (authn.VerifiedCaller, bool, error) {
				caller, match, err := a.verifier.VerifyApproval(ctx)
				if err != nil {
					logged.approvalFailed(debugReason(err))
				}
				return caller, match, err
			}
		}
		authLog.Info("approval sources active", "subjects", len(approval.approvers), "app_roles", identity.ApproverRoles,
			"member_only", identity.MemberOnly, "required_roles", identity.RequiredRoles, "required_group_count", len(identity.RequiredGroups))
	}
	// The deployment is host policy, not a harness-controlled override.
	modelFn := func(ctx context.Context, r api.ModelRequest) (api.ModelResponse, error) {
		bounded, cancel := context.WithTimeout(ctx, 25*time.Second)
		defer cancel()
		r.Model = c.Deployment
		bounded, r, err := chatRequestContext(bounded, r)
		if err != nil {
			return api.ModelResponse{}, err
		}
		return model.Model(bounded, r)
	}
	streamFn := func(ctx context.Context, r api.ModelRequest, chunk func(string)) (api.ModelResponse, error) {
		bounded, cancel := context.WithTimeout(ctx, 25*time.Second)
		defer cancel()
		r.Model = c.Deployment
		bounded, r, err := chatRequestContext(bounded, r)
		if err != nil {
			return api.ModelResponse{}, err
		}
		return model.StreamModel(bounded, r, chunk)
	}
	placers := make(map[string]*placement.Placer, len(harnesses))
	names := make([]string, 0, len(harnesses))
	for name, addr := range harnesses {
		backend := substrateBackend
		if backend == nil {
			remoteBackend := remote.New(addr, remote.WithLogger(logger))
			a.backends = append(a.backends, remoteBackend)
			backend = remoteBackend
		}
		opts := []placement.Option{placement.WithLogger(logger), placement.WithStreamingModel(streamFn)}
		if c.Substrate == nil && nativeHarnessName.MatchString(name) {
			opts = append(opts, placement.WithDescriptorID(name))
		}
		if tool, ok := tools[name]; ok {
			opts = append(opts, placement.WithToolExecutor(tool.Execute), placement.WithDurableDedup(tool.DurableDedup))
		}
		placers[name] = placement.New(backend, modelFn, opts...)
		names = append(names, name)
	}
	sort.Strings(names)
	registry, err := placement.NewRegistry(names[0], placers)
	if err != nil {
		return nil, err
	}
	a.store, err = sqlitelog.Open(c.Journal)
	if err != nil {
		return nil, fmt.Errorf("open journal: %w", err)
	}
	if err = session.ReserveStaticHarnessNames(a.store, registry); err != nil {
		return nil, err
	}
	sessionOptions := []session.Option{session.WithLogger(logger)}
	if c.Mode == authn.Required {
		sessionOptions = append(sessionOptions, session.WithAuthorization(approval))
	}
	svc := session.NewService(a.store, registry, sessionOptions...)
	a.sessions, a.health, err = newServers(c.Mode, verifier, svc, transport)
	if err != nil {
		return nil, err
	}
	return a, nil
}

// newEntraVerifier lets ctx (the signal context in Run) cancel only the initial key
// load. The verifier must outlive it: Run drains admitted RPCs after the signal,
// and those still verify. application.Close ends the verifier after the drain.
func newEntraVerifier(ctx context.Context, c entraauth.Config) (*entraauth.Verifier, error) {
	life, cancel := context.WithCancelCause(context.WithoutCancel(ctx))
	// On success cancel is never called: nothing leaks (the parent is
	// WithoutCancel) and Verifier.Close ends the lifetime. The cause keeps an
	// expired startup deadline reported as DeadlineExceeded, not Canceled.
	stop := context.AfterFunc(ctx, func() { cancel(context.Cause(ctx)) })
	v, err := entraauth.New(life, c)
	if !stop() {
		// ctx ended during startup and canceled the lifetime: fail as before.
		if v != nil {
			v.Close()
		}
		if err == nil {
			err = ctx.Err()
		}
		return nil, err
	}
	return v, err
}

func (a *application) Close() {
	a.once.Do(func() {
		if a.sessions != nil {
			a.sessions.Stop()
		}
		if a.health != nil {
			a.health.Stop()
		}
		for _, backend := range a.backends {
			_ = backend.Close()
		}
		if a.verifier != nil {
			a.verifier.Close()
		}
		if a.store != nil {
			_ = a.store.Close()
		}
		if a.modelPolicy != nil {
			_ = a.modelPolicy.Close()
		}
	})
}

// Run owns both loopback listeners and all host resources until cancellation.
func Run(ctx context.Context, c Config, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}
	if err := c.validate(); err != nil {
		return err
	}
	if c.ModelPolicy == "" {
		return errors.New("host requires explicit -model-policy: unknown price or unbounded model calls are refused")
	}
	lis, err := net.Listen("tcp", c.Addr)
	if err != nil {
		return fmt.Errorf("sessions listener: %w", err)
	}
	defer lis.Close()
	ops, err := net.Listen("tcp", c.HealthAddr)
	if err != nil {
		return fmt.Errorf("health listener: %w", err)
	}
	defer ops.Close()
	a, err := newApplication(ctx, c, c.ModelCredential, logger)
	if err != nil {
		return err
	}
	defer a.Close()
	if c.Mode == authn.Off {
		logger.Warn("authentication off: anyone who can reach the host can act on and approve sessions; trusted-network development only")
	}
	logger.Warn("experimental proof only: host-RPC authorization in required mode, not journal-wide enforcement or verified approval attribution; no public exposure", "auth_mode", string(c.Mode))
	logger.Info("host listening", "sessions", lis.Addr().String(), "health", ops.Addr().String())
	results := make(chan error, 2)
	go func() { results <- a.sessions.Serve(lis) }()
	go func() { results <- a.health.Serve(ops) }()
	var result error
	remaining := 2
	select {
	case <-ctx.Done():
	case result = <-results:
		remaining--
	}
	// Bound graceful draining; a hung harness cannot prevent termination forever.
	drained := make(chan struct{})
	go func() { a.sessions.GracefulStop(); a.health.GracefulStop(); close(drained) }()
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	select {
	case <-drained:
	case <-timer.C:
		a.sessions.Stop()
		a.health.Stop()
		<-drained
	}
	for ; remaining > 0; remaining-- {
		if e := <-results; e != nil && !errors.Is(e, grpc.ErrServerStopped) && result == nil {
			result = e
		}
	}
	if errors.Is(result, grpc.ErrServerStopped) {
		return nil
	}
	return result
}
