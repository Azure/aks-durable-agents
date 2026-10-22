package host

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/agent-primitives/sessions/api"
	atepb "github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (f *controlFixture) SuspendActor(_ context.Context, req *atepb.SuspendActorRequest) (*atepb.SuspendActorResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a := f.actors[req.GetActor().GetName()]
	if a == nil {
		return nil, status.Error(codes.NotFound, "missing")
	}
	a.Status.State = atepb.ActorState_ACTOR_STATE_SUSPENDED
	return &atepb.SuspendActorResponse{Actor: a}, nil
}

func nativeSnapshot(generation int32, fidelity atepb.SnapshotFidelity, storage atepb.SnapshotStorageStatus, uri string) *atepb.Snapshot {
	return &atepb.Snapshot{Uuid: fmt.Sprintf("snapshot-%d", generation), Generation: generation, Fidelity: fidelity,
		DurableSnapshot: &atepb.SnapshotStorage{Status: storage, Object: &atepb.ObjectSnapshot{SnapshotUri: uri}}}
}

func snapshotActor(snapshots []*atepb.Snapshot, state atepb.ActorState) *atepb.Actor {
	return &atepb.Actor{Metadata: &atepb.ResourceMetadata{Atespace: "app", Name: "session", Uid: "compute-session"},
		Status: &atepb.ActorStatus{State: state, Snapshots: snapshots, LastAssignedGeneration: 3}}
}

// The actual TLS adapter must inspect native results, not a stateless declaration
// or the template's requested fidelity. Removing WithVolumesOnly breaks negatives.
func TestSubstrateHostRequiresDurableVolumesSnapshot(t *testing.T) {
	const held = "s3://snapshot-fixture/newest"
	completed := atepb.SnapshotStorageStatus_SNAPSHOT_STORAGE_STATUS_COMPLETED
	volumes := atepb.SnapshotFidelity_SNAPSHOT_FIDELITY_VOLUMES
	older := nativeSnapshot(1, volumes, completed, "s3://snapshot-fixture/older")
	for _, tc := range []struct {
		name      string
		snapshots []*atepb.Snapshot
		accept    bool
	}{
		{"newest completed volumes", []*atepb.Snapshot{nativeSnapshot(3, volumes, completed, held), older}, true},
		{"memory", []*atepb.Snapshot{nativeSnapshot(3, atepb.SnapshotFidelity_SNAPSHOT_FIDELITY_MEMORY, completed, held)}, false},
		{"rootfs", []*atepb.Snapshot{nativeSnapshot(3, atepb.SnapshotFidelity_SNAPSHOT_FIDELITY_ROOTFS, completed, held)}, false},
		{"unknown fidelity", []*atepb.Snapshot{nativeSnapshot(3, atepb.SnapshotFidelity(99), completed, held)}, false},
		{"missing URI", []*atepb.Snapshot{nativeSnapshot(3, volumes, completed, "")}, false},
		{"newest pending", []*atepb.Snapshot{nativeSnapshot(3, volumes, atepb.SnapshotStorageStatus_SNAPSHOT_STORAGE_STATUS_PENDING, held), older}, false},
		{"newest local only", []*atepb.Snapshot{{Generation: 3, Fidelity: volumes}, older}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newControlFixture(t)
			f.actors["session"] = snapshotActor(tc.snapshots, atepb.ActorState_ACTOR_STATE_RUNNING)
			backend, conn, err := openSubstrate(f.sub, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			ref, err := backend.Snapshot(ctx, api.Incarnation{ID: "session"}, api.SnapshotExternal)
			if tc.accept {
				if err != nil || ref.Local != "session" || ref.ExternalURI != held || ref.Memory {
					t.Fatalf("wrong newest VOLUMES checkpoint: %+v %v", ref, err)
				}
			} else if err == nil {
				t.Fatalf("host accepted invalid observed checkpoint: %+v", ref)
			}
			if len(f.events) != 1 || !strings.HasSuffix((<-f.events).method, "/SuspendActor") {
				t.Fatal("snapshot did not exercise the real Control suspend RPC")
			}
		})
	}
}

func TestSubstrateHostRefusesInvalidHeldSnapshotBeforeResume(t *testing.T) {
	const held = "s3://snapshot-fixture/held"
	completed := atepb.SnapshotStorageStatus_SNAPSHOT_STORAGE_STATUS_COMPLETED
	volumes := atepb.SnapshotFidelity_SNAPSHOT_FIDELITY_VOLUMES
	for _, tc := range []struct {
		name      string
		snapshots []*atepb.Snapshot
		accept    bool
	}{
		{"matching volumes", []*atepb.Snapshot{nativeSnapshot(3, volumes, completed, held)}, true},
		{"wrong fidelity", []*atepb.Snapshot{nativeSnapshot(3, atepb.SnapshotFidelity_SNAPSHOT_FIDELITY_MEMORY, completed, held)}, false},
		{"different held URI", []*atepb.Snapshot{nativeSnapshot(3, volumes, completed, "s3://snapshot-fixture/different")}, false},
		{"newest pending", []*atepb.Snapshot{nativeSnapshot(3, volumes, atepb.SnapshotStorageStatus_SNAPSHOT_STORAGE_STATUS_PENDING, held), nativeSnapshot(1, volumes, completed, held)}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newControlFixture(t)
			f.actors["session"] = snapshotActor(tc.snapshots, atepb.ActorState_ACTOR_STATE_SUSPENDED)
			backend, conn, err := openSubstrate(f.sub, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			inc, err := backend.Restore(ctx, api.SnapshotRef{Local: "session", ExternalURI: held})
			if tc.accept {
				if err != nil || inc.ID != "session" || inc.Runtime != "substrate" {
					t.Fatalf("valid held checkpoint refused: %+v %v", inc, err)
				}
			} else if err == nil {
				t.Fatal("invalid held checkpoint restored")
			}
			resumes := 0
			for len(f.events) != 0 {
				if strings.HasSuffix((<-f.events).method, "/ResumeActor") {
					resumes++
				}
			}
			want := 0
			if tc.accept {
				want = 1
			}
			if resumes != want {
				t.Fatalf("ResumeActor calls=%d, want %d", resumes, want)
			}
		})
	}
}
