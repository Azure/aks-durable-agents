package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	atepb "github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

type substratePlacement struct {
	Atespace         string `json:"atespace"`
	Actor            string `json:"actor"`
	ActorUID         string `json:"actorUID"`
	TemplateAtespace string `json:"templateAtespace"`
	Template         string `json:"template"`
	Worker           string `json:"worker"`
	Namespace        string `json:"namespace"`
	Pool             string `json:"pool"`
	Pod              string `json:"pod"`
	PodUID           string `json:"podUID"`
	Node             string `json:"node"`
	Runtime          string `json:"runtime"`
	RuntimeSchema    string `json:"runtimeSchema"`
	RuntimeDigest    string `json:"runtimeDigest"`
}
type substratePlacements struct {
	Version int                `json:"version"`
	First   substratePlacement `json:"first"`
	Latest  substratePlacement `json:"latest"`
}

func (p substratePlacement) valid() bool {
	for _, s := range []string{p.Atespace, p.Actor, p.ActorUID, p.TemplateAtespace, p.Template, p.Worker, p.Namespace, p.Pool, p.Pod, p.PodUID, p.Node, p.RuntimeSchema} {
		if len(s) == 0 || len(s) > 253 || strings.ContainsAny(s, "\x00\r\n\t ") {
			return false
		}
	}
	_, err := hex.DecodeString(p.RuntimeDigest)
	return err == nil && len(p.RuntimeDigest) == 64 && (p.Runtime == "gvisor" || p.Runtime == "microvm")
}
func (p substratePlacement) sameActor(q substratePlacement) bool {
	return p.Atespace == q.Atespace && p.Actor == q.Actor && p.ActorUID == q.ActorUID && p.TemplateAtespace == q.TemplateAtespace && p.Template == q.Template
}

// The observer is opt-in for a single controlled scenario. Capturing the native
// response here happens before the released backend hands the harness its route;
// polling after an approval park would find SUSPENDED with no worker assignment.
func substrateControlRPC(path string) grpc.UnaryClientInterceptor {
	if path == "" {
		return boundControlRPC
	}
	var mu sync.Mutex
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoke grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		if err := boundControlRPC(ctx, method, req, reply, cc, invoke, opts...); err != nil {
			return err
		}
		var actor *atepb.Actor
		switch response := reply.(type) {
		case *atepb.Actor:
			actor = response
		case *atepb.ResumeActorResponse:
			actor = response.GetActor()
		}
		if actor.GetStatus().GetState() != atepb.ActorState_ACTOR_STATE_RUNNING {
			return nil
		}
		mu.Lock()
		defer mu.Unlock()
		if err := recordSubstratePlacement(path, actor); err != nil {
			return errors.New("cannot persist private Substrate placement proof")
		}
		return nil
	}
}

func recordSubstratePlacement(path string, a *atepb.Actor) error {
	wa := a.GetStatus().GetWorkerAssignment()
	runtime := wa.GetSandboxRuntime()
	version, err := proto.MarshalOptions{Deterministic: true}.Marshal(runtime.GetVersion())
	if err != nil {
		return err
	}
	hash := sha256.Sum256(version)
	p := substratePlacement{Atespace: a.GetMetadata().GetAtespace(), Actor: a.GetMetadata().GetName(), ActorUID: a.GetMetadata().GetUid(), TemplateAtespace: a.GetActorTemplate().GetAtespace(), Template: a.GetActorTemplate().GetName(), Worker: wa.GetWorker().GetName(), Namespace: wa.GetWorkerNamespace(), Pool: wa.GetWorkerPool(), Pod: wa.GetWorkerPod(), PodUID: wa.GetWorkerPodUid(), Node: wa.GetNodeName(), Runtime: runtime.GetSandboxClass(), RuntimeSchema: runtime.GetVersion().GetSchemaVersion(), RuntimeDigest: hex.EncodeToString(hash[:])}
	if !p.valid() || a.GetStatus().GetState() != atepb.ActorState_ACTOR_STATE_RUNNING || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("invalid Substrate placement")
	}
	dir := filepath.Dir(path)
	real, err := filepath.EvalSymlinks(dir)
	if err != nil || real != dir {
		return errors.New("unsafe placement directory")
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("placement directory must be private")
	}
	doc := substratePlacements{Version: 1, First: p, Latest: p}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err == nil {
		defer f.Close()
		info, e := f.Stat()
		if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 65536 {
			return errors.New("unsafe placement receipt")
		}
		raw, e := io.ReadAll(io.LimitReader(f, 65537))
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		doc = substratePlacements{}
		if e != nil || decoder.Decode(&doc) != nil || decoder.Decode(new(any)) != io.EOF || doc.Version != 1 || !doc.First.valid() || !doc.Latest.valid() || !doc.First.sameActor(doc.Latest) || !doc.First.sameActor(p) {
			return errors.New("unbound placement receipt")
		}
		doc.Latest = p
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("cannot read placement receipt")
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".substrate-placement-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err = tmp.Write(raw); err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	parent, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}
