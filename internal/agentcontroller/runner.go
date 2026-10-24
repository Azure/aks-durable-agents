package agentcontroller

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Azure/aks-durable-agents/internal/agentpackage"
	"github.com/agent-primitives/sessions/api"
	v1 "github.com/agent-primitives/sessions/api/genpb"
	"github.com/agent-primitives/sessions/harness/chatagent"
	"github.com/agent-primitives/sessions/harnesswire"
	"github.com/agent-primitives/sessions/placement"
	"github.com/agent-primitives/sessions/runtime/remote"
	"github.com/agent-primitives/suite/core"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

type frozenHarness struct {
	name, model string
	config      []byte
}

func (h *frozenHarness) Describe(ctx context.Context) (api.Descriptor, error) {
	d, err := (chatagent.Harness{Model: h.model}).Describe(ctx)
	d.ID, d.Version = h.name, RunnerABI
	return d, err
}
func (h *frozenHarness) Run(ctx context.Context, start *api.Start, sink api.EventSink) error {
	if start == nil || len(start.Config) != 0 || (start.Model != "" && start.Model != h.model) {
		return errRetained
	}
	copy := *start
	copy.Config, copy.Model = bytes.Clone(h.config), h.model
	return (chatagent.Harness{Model: h.model}).Run(ctx, &copy, sink)
}
func packagedHarness(p *agentpackage.Package, d definition) (*frozenHarness, error) {
	if p == nil || p.Report() == nil || p.Report().Agents != 1 || p.Report().ToolProviders != 0 || p.Report().ToolProviderCompositions != 0 || len(p.Report().Capabilities) != 0 {
		return nil, errRetained
	}
	read := func(path string, out any) error {
		b, err := p.ReadFile(path)
		if err != nil {
			return errRetained
		}
		if core.Unmarshal(b, out) != nil {
			return errRetained
		}
		return nil
	}
	var suite core.Suite
	if err := read("agentsuite.json", &suite); err != nil {
		return nil, err
	}
	if len(suite.Agents) != 1 || len(suite.RuntimeProfiles) != 0 || len(suite.ToolProviderCompositions) != 0 {
		return nil, errRetained
	}
	for _, e := range suite.Extensions {
		if e.Critical {
			return nil, errRetained
		}
	}
	ref := suite.Agents[0]
	if ref.ID != d.Spec.Member {
		return nil, errRetained
	}
	var agent core.Agent
	if err := read(ref.Path, &agent); err != nil {
		return nil, err
	}
	if agent.SchemaVersion != "1.0.0-draft" || agent.ID != d.Spec.Member || agent.Model.Protocol != "openai-compatible" || agent.Model.Model == "" || agent.Model.Capabilities != nil || agent.Model.EndpointEnv != "" || len(agent.Model.SecretRefs) != 0 || len(agent.ToolProviders) != 0 || len(agent.Invokes) != 0 || agent.Policy != nil {
		return nil, errRetained
	}
	for _, e := range agent.Extensions {
		if e.Critical {
			return nil, errRetained
		}
	}
	instructions, err := p.ReadFile(agent.Instructions.Path)
	if err != nil {
		return nil, errRetained
	}
	return &frozenHarness{name: d.Harness, model: d.Model, config: retainedJSON(map[string]string{"system_prompt": string(instructions)})}, nil
}

func (r *retained) spec(d definition) *v1.HarnessSpec {
	desc, _ := (&frozenHarness{name: d.Harness, model: d.Model}).Describe(context.Background())
	return &v1.HarnessSpec{Placement: &v1.HarnessSpec_Remote{Remote: &v1.RemotePlacement{Address: "unix://" + filepath.Join(r.socketDirectory, d.Harness+".sock")}}, DescriptorId: d.Harness, Capabilities: harnesswire.DescriptorToProto(desc).Capabilities}
}
func (r *retained) factory(name string, spec *v1.HarnessSpec) (*placement.Placer, func(), error) {
	d, ok := r.definitions[name]
	if !ok || r.validate(d) != nil || d.Harness != name || !bytes.Equal(d.Binding, r.binding) || r.config.Puller.ValidateReference(d.Spec.Package.Reference) != nil || d.Model != r.config.Model || r.servers[name] == nil || !proto.Equal(spec, r.spec(d)) {
		return nil, nil, errRetained
	}
	backend := remote.New(r.spec(d).GetRemote().Address)
	return placement.New(backend, r.model, placement.WithDescriptorID(name), placement.WithModelPolicy(api.ModelPolicy{Default: d.Model, Allowed: []string{d.Model}}), placement.WithStreamingModel(r.stream)), func() { _ = backend.Close() }, nil
}

type ownedServer struct {
	server   *grpc.Server
	listener *net.UnixListener
	root     *os.Root
	name, id string
	done     chan struct{}
}

func socketIdentity(info os.FileInfo) string {
	st := info.Sys().(*syscall.Stat_t)
	return fmt.Sprintf("%d:%d:%d", st.Dev, st.Ino, info.ModTime().UnixNano())
}
func (s *ownedServer) close() {
	s.server.Stop()
	_ = s.listener.Close()
	<-s.done
	if info, err := s.root.Lstat(s.name); err == nil && info.Mode()&os.ModeSocket != 0 && socketIdentity(info) == s.id {
		_ = s.root.Remove(s.name)
	}
}
func (r *retained) serve(d definition, p *agentpackage.Package) error {
	if r.servers[d.Harness] != nil {
		return nil
	}
	h, err := packagedHarness(p, d)
	if err != nil {
		return err
	}
	name := d.Harness + ".sock"
	path := filepath.Join(r.socketDirectory, name)
	// The manager lock excludes live owners. An inode record plus ECONNREFUSED
	// distinguishes our crashed listener from a foreign socket or full backlog.
	if info, e := r.sockets.Lstat(name); e == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return errRetained
		}
		id, e := retainedBytes(r.sockets, name+".id", 128)
		if e != nil || string(id) != socketIdentity(info) {
			return errRetained
		}
		conn, e := net.DialTimeout("unix", path, time.Second)
		if e == nil {
			conn.Close()
			return errRetained
		}
		if !errors.Is(e, syscall.ECONNREFUSED) {
			return errRetained
		}
		if e = r.sockets.Remove(name); e != nil {
			return e
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	rootInfo, err := r.sockets.Stat(".")
	if err != nil {
		return err
	}
	pathInfo, err := os.Lstat(r.socketDirectory)
	if err != nil || !os.SameFile(rootInfo, pathInfo) {
		return errRetained
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return err
	}
	listener.SetUnlinkOnClose(false)
	info, err := r.sockets.Lstat(name)
	if err != nil {
		listener.Close()
		return err
	}
	server := &ownedServer{server: grpc.NewServer(), listener: listener, root: r.sockets, name: name, id: socketIdentity(info), done: make(chan struct{})}
	v1.RegisterHarnessServer(server.server, harnesswire.NewServer(h))
	go func() { defer close(server.done); _ = server.server.Serve(listener) }()
	// Socket ownership records are ephemeral, separate from immutable definitions.
	lock, err := r.sockets.OpenFile(name+".id", os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err == nil {
		var fi os.FileInfo
		fi, err = lock.Stat()
		if err == nil && (!fi.Mode().IsRegular() || fi.Sys().(*syscall.Stat_t).Nlink != 1) {
			err = errRetained
		}
		if err == nil {
			err = lock.Truncate(0)
		}
		if err == nil {
			_, err = lock.WriteAt([]byte(server.id), 0)
		}
		if err == nil {
			err = lock.Sync()
		}
		_ = lock.Close()
	}
	if err != nil {
		server.close()
		return err
	}
	r.servers[d.Harness] = server
	return nil
}
