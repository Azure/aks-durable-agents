package democli

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Azure/aks-durable-agents/internal/host"
	fixture "github.com/Azure/aks-durable-agents/internal/sessionfixture"
	"github.com/agent-primitives/sessions/api"
	v1 "github.com/agent-primitives/sessions/api/genpb"
	"github.com/agent-primitives/sessions/client"
	"github.com/agent-primitives/sessions/harnesswire"
	atepb "github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// Only the native compute boundary is synthetic: host, released adapter,
// placement, harnesswire, frozen harness, journal and Unix executor are real.
// This exercises assembly, not gVisor or external object-store durability.
type nativeScenario struct {
	atepb.UnimplementedControlServer
	mu                sync.Mutex
	actor             *atepb.Actor
	resumes, suspends int
	placement         string
	t                 *testing.T
}

func (n *nativeScenario) GetActor(context.Context, *atepb.GetActorRequest) (*atepb.Actor, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.actor == nil {
		return nil, status.Error(codes.NotFound, "missing")
	}
	return proto.Clone(n.actor).(*atepb.Actor), nil
}
func (n *nativeScenario) CreateActor(_ context.Context, req *atepb.CreateActorRequest) (*atepb.Actor, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.actor = proto.Clone(req.GetActor()).(*atepb.Actor)
	n.actor.Metadata.Uid = "d6dcc1b8-a834-4cbf-b6cc-4a6392db7bde"
	n.actor.Status = &atepb.ActorStatus{State: atepb.ActorState_ACTOR_STATE_SUSPENDED}
	return proto.Clone(n.actor).(*atepb.Actor), nil
}
func (n *nativeScenario) ResumeActor(context.Context, *atepb.ResumeActorRequest) (*atepb.ResumeActorResponse, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.resumes++
	n.actor.Status.State = atepb.ActorState_ACTOR_STATE_RUNNING
	n.actor.Status.WorkerAssignment = &atepb.WorkerAssignment{Worker: &atepb.ObjectRef{Name: "worker"}, WorkerNamespace: "actors", WorkerPool: "gvisor", WorkerPod: "worker-pod", WorkerPodUid: "6ad2a6b6-b92f-4c93-bcab-f073524f5d66", NodeName: "node", SandboxRuntime: &atepb.SandboxRuntime{SandboxClass: "gvisor", Version: &atepb.VersionedSandboxCompat{SchemaVersion: "v1", Attributes: []*atepb.AttributeEntry{{Key: "gvisor_asset_hash", Value: strings.Repeat("a", 64)}}}}}
	return &atepb.ResumeActorResponse{Actor: proto.Clone(n.actor).(*atepb.Actor)}, nil
}
func (n *nativeScenario) SuspendActor(context.Context, *atepb.SuspendActorRequest) (*atepb.SuspendActorResponse, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.suspends++
	n.actor.Status.State = atepb.ActorState_ACTOR_STATE_SUSPENDED
	n.actor.Status.WorkerAssignment = nil
	n.actor.Status.LastAssignedGeneration = int32(n.suspends)
	n.actor.Status.Snapshots = []*atepb.Snapshot{{Uuid: "snapshot", Generation: int32(n.suspends), Fidelity: atepb.SnapshotFidelity_SNAPSHOT_FIDELITY_VOLUMES, DurableSnapshot: &atepb.SnapshotStorage{Status: atepb.SnapshotStorageStatus_SNAPSHOT_STORAGE_STATUS_COMPLETED, Object: &atepb.ObjectSnapshot{SnapshotUri: "s3://test/held"}}}}
	return &atepb.SuspendActorResponse{Actor: proto.Clone(n.actor).(*atepb.Actor)}, nil
}
func (n *nativeScenario) counts() [2]int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return [2]int{n.resumes, n.suspends}
}

func TestSubstratePlacementWriteFailureNeverInvokesHarness(t *testing.T) {
	n := &nativeScenario{t: t}
	control := grpc.NewServer()
	atepb.RegisterControlServer(control, n)
	t.Cleanup(control.Stop)
	controlHTTP := httptest.NewUnstartedServer(control)
	controlHTTP.EnableHTTP2 = true
	controlHTTP.StartTLS()
	t.Cleanup(controlHTTP.Close)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	router := grpc.NewServer(
		grpc.UnaryInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
			calls.Add(1)
			return next(ctx, req)
		}),
		grpc.StreamInterceptor(func(srv any, stream grpc.ServerStream, _ *grpc.StreamServerInfo, next grpc.StreamHandler) error {
			calls.Add(1)
			return next(srv, stream)
		}))
	v1.RegisterHarnessServer(router, harnesswire.NewServer(fixture.ActorHarness()))
	go router.Serve(listener)
	t.Cleanup(router.Stop)
	d := newDemo(t, func(d *demo) {
		d.stopHarness()
		ca, token := filepath.Join(d.data, "control-ca.pem"), filepath.Join(d.data, "control-token")
		if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: controlHTTP.Certificate().Raw}), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(token, []byte("control-test"), 0600); err != nil {
			t.Fatal(err)
		}
		n.placement = filepath.Join(d.data, "missing-parent", "proof.json")
		d.cfg.Harnesses, d.cfg.HarnessService, d.cfg.PeerNodeFile, d.cfg.NodeName = nil, "", "", ""
		d.cfg.Substrate = &host.SubstrateConfig{Harness: "release-notes", ActorAtespace: "app", TemplateAtespace: "assets", Template: "release-notes", ControlAddr: strings.TrimPrefix(controlHTTP.URL, "https://"), RouterAddr: listener.Addr().String(), CAFile: ca, TokenFile: token, PlacementFile: n.placement}
	})
	_, err = d.rpc("park")
	if err == nil || !strings.Contains(err.Error(), "placement proof") {
		t.Fatalf("expected placement persistence failure: %v", err)
	}
	if n.counts()[0] != 1 || calls.Load() != 0 {
		t.Fatalf("RUNNING write failure reached harness: resumes=%v harness=%d", n.counts(), calls.Load())
	}
	if got := d.evidence(); got["realModelCalls"] != float64(0) || got["publicationCount"] != float64(0) {
		t.Fatalf("failed placement performed work: %v", got)
	}
}

func TestSubstrateApprovalParkRestartContinueReplay(t *testing.T) {
	n := &nativeScenario{t: t}
	control := grpc.NewServer()
	atepb.RegisterControlServer(control, n)
	t.Cleanup(control.Stop)
	controlHTTP := httptest.NewUnstartedServer(control)
	controlHTTP.EnableHTTP2 = true
	controlHTTP.StartTLS()
	t.Cleanup(controlHTTP.Close)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	router := grpc.NewServer(grpc.StreamInterceptor(func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, next grpc.StreamHandler) error {
		md, _ := metadata.FromIncomingContext(stream.Context())
		n.mu.Lock()
		name := n.actor.GetMetadata().GetName()
		n.mu.Unlock()
		if got := md.Get("ate-target-actor"); len(got) != 1 || got[0] != "app/"+name {
			return status.Error(codes.PermissionDenied, "wrong actor route")
		}
		if _, err := os.Stat(n.placement); err != nil {
			return status.Error(codes.FailedPrecondition, "placement not persisted before harness invocation")
		}
		return next(srv, stream)
	}))
	v1.RegisterHarnessServer(router, harnesswire.NewServer(fixture.ActorHarness()))
	go router.Serve(listener)
	t.Cleanup(router.Stop)

	d := newDemo(t, func(d *demo) {
		d.stopHarness() // A live legacy fixture cannot be the fallback path.
		ca := filepath.Join(d.data, "control-ca.pem")
		token := filepath.Join(d.data, "control-token")
		if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: controlHTTP.Certificate().Raw}), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(token, []byte("control-test"), 0600); err != nil {
			t.Fatal(err)
		}
		n.placement = filepath.Join(d.data, "substrate-placement.json")
		d.cfg.Harnesses, d.cfg.HarnessService, d.cfg.PeerNodeFile, d.cfg.NodeName = nil, "", "", ""
		d.cfg.Substrate = &host.SubstrateConfig{Harness: "release-notes", ActorAtespace: "app", TemplateAtespace: "assets", Template: "release-notes", ControlAddr: strings.TrimPrefix(controlHTTP.URL, "https://"), RouterAddr: listener.Addr().String(), CAFile: ca, TokenFile: token, PlacementFile: n.placement}
	})
	park := d.mustRPC("park")
	uid := park["session"].(string)
	checkpoint := d.mustRPC("checkpoint")
	if !reflect.DeepEqual(checkpoint, map[string]any{"version": float64(1), "actor": uid, "uri": "s3://test/held", "memory": false}) {
		t.Fatalf("journal checkpoint projection: %v", checkpoint)
	}
	baseline := d.evidence()
	if baseline["realModelCalls"] != float64(1) || baseline["publicationCount"] != float64(0) || n.counts()[1] != 1 {
		t.Fatalf("park must hand off to external snapshot before returning: %v native=%v", baseline, n.counts())
	}
	c, err := client.Dial(strings.TrimPrefix(d.server, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	view, err := inspect(t.Context(), c, uid)
	c.Close()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range view.events {
		if e.Kind == api.EventLifecycle && e.Lifecycle.Kind == api.LifecycleSuspend {
			if e.Lifecycle.Snapshot == nil || e.Lifecycle.Snapshot.ExternalURI != "s3://test/held" || e.Lifecycle.Snapshot.Memory {
				t.Fatalf("wrong committed checkpoint: %+v", e.Lifecycle)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("approval park lacks committed SUSPEND")
	}
	before := n.counts()
	d.stopOne()
	d.startHost()
	d.mustRPC("check-parked")
	d.mustRPC("approve")
	if n.counts() != before || !reflect.DeepEqual(d.evidence(), baseline) {
		t.Fatal("restart/inspection/Approve resumed compute or effects")
	}
	completed := d.mustRPC("continue")
	final := d.evidence()
	if completed["completed"] != true || final["realModelCalls"] != float64(1) || final["publicationCount"] != float64(1) || final["receiptCount"] != float64(1) || len(final["artifacts"].([]any)) != 1 || n.counts()[0] != before[0]+1 {
		t.Fatalf("Continue lost replay/effect invariant: %v native=%v", final, n.counts())
	}
	var placement map[string]any
	raw, err := os.ReadFile(n.placement)
	if err != nil || json.Unmarshal(raw, &placement) != nil || placement["first"] == nil || placement["latest"] == nil {
		t.Fatalf("placement across restart: %s %v", raw, err)
	}
	beforeReplay := n.counts()
	d.stopWriters()
	mustCLI(t, "seal", "--data", d.data)
	replay := mustCLI(t, "verify", "--data", d.data)
	if replay["provider_calls"] != float64(0) || replay["executor_calls"] != float64(0) || !reflect.DeepEqual(d.evidence(), final) || n.counts() != beforeReplay {
		t.Fatalf("terminal replay reached external boundary or changed inventories: %v", replay)
	}
}
