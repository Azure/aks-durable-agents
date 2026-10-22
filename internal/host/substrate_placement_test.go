package host

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	atepb "github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"google.golang.org/protobuf/proto"
)

func placementActor() *atepb.Actor {
	return &atepb.Actor{Metadata: &atepb.ResourceMetadata{Atespace: "app", Name: "session", Uid: "f98c68d1-1f58-45ac-96aa-59e8b210903a"}, ActorTemplate: &atepb.ObjectRef{Atespace: "assets", Name: "release-notes"}, Status: &atepb.ActorStatus{State: atepb.ActorState_ACTOR_STATE_RUNNING, WorkerAssignment: &atepb.WorkerAssignment{Worker: &atepb.ObjectRef{Name: "worker"}, WorkerNamespace: "actors", WorkerPool: "gvisor", WorkerPod: "worker-pod", WorkerPodUid: "8849478c-dc69-471e-99dc-d442ba3f8cfe", NodeName: "node", SandboxRuntime: &atepb.SandboxRuntime{SandboxClass: "gvisor", Version: &atepb.VersionedSandboxCompat{SchemaVersion: "v1", Attributes: []*atepb.AttributeEntry{{Key: "gvisor_asset_hash", Value: strings.Repeat("a", 64)}}}}}}}
}
func placementDirectory(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func placementDocument(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	var v map[string]any
	if err != nil || json.Unmarshal(raw, &v) != nil {
		t.Fatalf("placement receipt: %s %v", raw, err)
	}
	return v
}
func TestSubstratePlacementFirstImmutableLatestSurvivesRestart(t *testing.T) {
	path := filepath.Join(placementDirectory(t), "placement.json")
	a := placementActor()
	if err := recordSubstratePlacement(path, a); err != nil {
		t.Fatal(err)
	}
	first := placementDocument(t, path)
	a.Status.WorkerAssignment.WorkerPod = "replacement"
	if err := recordSubstratePlacement(path, a); err != nil {
		t.Fatal(err)
	}
	latest := placementDocument(t, path)
	if latest["version"] != float64(1) || !reflect.DeepEqual(first["first"], latest["first"]) || reflect.DeepEqual(latest["first"], latest["latest"]) {
		t.Fatalf("first rewritten or latest lost: %v", latest)
	}
	if latest["latest"].(map[string]any)["pod"] != "replacement" {
		t.Fatal(latest)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("placement receipt is not private")
	}
}
func TestSubstratePlacementRefusesMismatchedOrMalformedState(t *testing.T) {
	for _, mutate := range []func(*atepb.Actor){
		func(a *atepb.Actor) { a.Metadata.Uid = "other" },
		func(a *atepb.Actor) { a.Metadata.Name = "other" },
		func(a *atepb.Actor) { a.ActorTemplate.Name = "other" },
		func(a *atepb.Actor) { a.Status.WorkerAssignment = nil },
		func(a *atepb.Actor) { a.Status.WorkerAssignment.SandboxRuntime = nil },
	} {
		path := filepath.Join(placementDirectory(t), "placement.json")
		a := placementActor()
		if err := recordSubstratePlacement(path, a); err != nil {
			t.Fatal(err)
		}
		before, _ := os.ReadFile(path)
		changed := proto.Clone(a).(*atepb.Actor)
		mutate(changed)
		if err := recordSubstratePlacement(path, changed); err == nil {
			t.Fatal("unbound/malformed placement accepted")
		}
		after, _ := os.ReadFile(path)
		if string(before) != string(after) {
			t.Fatal("failed observation damaged proof")
		}
	}
	for _, raw := range []string{`{}`, `{"version":1,"first":{},"latest":{}}`, `{"version":1,"unexpected":"secret"}`} {
		path := filepath.Join(placementDirectory(t), "placement.json")
		os.WriteFile(path, []byte(raw), 0600)
		if err := recordSubstratePlacement(path, placementActor()); err == nil {
			t.Fatal("malformed old receipt adopted")
		}
	}
}
func TestSubstratePlacementRefusesUnsafeTargetAndIOFailure(t *testing.T) {
	dir := placementDirectory(t)
	target := filepath.Join(dir, "target")
	os.WriteFile(target, []byte("unchanged"), 0600)
	link := filepath.Join(dir, "link")
	os.Symlink(target, link)
	for _, path := range []string{link, dir, filepath.Join(dir, "missing", "proof.json"), "relative.json"} {
		if err := recordSubstratePlacement(path, placementActor()); err == nil {
			t.Fatalf("unsafe path accepted: %s", path)
		}
	}
	public := filepath.Join(dir, "public")
	if err := os.Mkdir(public, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(public, 0755); err != nil {
		t.Fatal(err)
	}
	if err := recordSubstratePlacement(filepath.Join(public, "proof.json"), placementActor()); err == nil {
		t.Fatal("public placement directory accepted")
	}
	raw, _ := os.ReadFile(target)
	if string(raw) != "unchanged" {
		t.Fatal("followed proof symlink")
	}
}
