package agentcontroller

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/Azure/aks-durable-agents/internal/agentpackage"
	v1 "github.com/agent-primitives/sessions/api/genpb"
	"github.com/agent-primitives/sessions/harness/chatagent"
	"github.com/agent-primitives/sessions/placement"
	"github.com/agent-primitives/sessions/runtime/local"
	"github.com/agent-primitives/sessions/sqlitelog"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
)

type sourceFixture struct {
	mu          sync.Mutex
	agents      map[string]Agent
	unavailable bool
	watcher     *watch.RaceFreeFakeWatcher
	lists       int
}

func (s *sourceFixture) List(context.Context) ([]Agent, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lists++
	if s.unavailable {
		return nil, "", errors.New("private API details")
	}
	var out []Agent
	for _, a := range s.agents {
		out = append(out, a)
	}
	return out, "1", nil
}
func (s *sourceFixture) Get(_ context.Context, name string) (Agent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.unavailable {
		return Agent{}, errors.New("private API details")
	}
	a, ok := s.agents[name]
	if !ok {
		return a, apierrors.NewNotFound(schema.GroupResource{Resource: "agents"}, name)
	}
	return a, nil
}
func (s *sourceFixture) UpdateStatus(_ context.Context, a Agent, status Status) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now, ok := s.agents[a.Name]
	if !ok || now.UID != a.UID || now.Generation != a.Generation {
		return errors.New("conflict")
	}
	a.Status = status
	s.agents[a.Name] = a
	return nil
}
func (s *sourceFixture) Watch(context.Context, string) (watch.Interface, error) {
	if s.watcher == nil {
		s.watcher = watch.NewRaceFreeFake()
	}
	return s.watcher, nil
}
func desired(name, uid, reference string) Agent {
	a := Agent{ObjectMeta: metav1.ObjectMeta{Namespace: "agents", Name: name, UID: types.UID(uid), Generation: 1}}
	a.Spec.Package.Reference = reference
	a.Spec.Member = "writer"
	a.Spec.ModelBindingRef.Name = "default"
	return a
}

func controllerPuller(t *testing.T, p *agentpackage.Package) (*agentpackage.Puller, string) {
	t.Helper()
	manifest, config, layer := p.OCIBytes()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body []byte
		switch r.URL.Path {
		case "/v2/suite/manifests/" + p.Digest():
			body = manifest
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
		case "/v2/suite/blobs/" + fixtureDigest(config):
			body = config
		case "/v2/suite/blobs/" + fixtureDigest(layer):
			body = layer
		default:
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Docker-Content-Digest", fixtureDigest(body))
		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)
	repo := strings.TrimPrefix(server.URL, "https://") + "/suite"
	puller, err := agentpackage.New(agentpackage.Policy{Repositories: []string{repo}}, server.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	return puller, repo + "@" + p.Digest()
}

func TestStartupAPIUnavailableDoesNotServe(t *testing.T) {
	s := &sourceFixture{unavailable: true, agents: map[string]Agent{}}
	store, err := sqlitelog.Open(t.TempDir() + "/journal.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	backend := local.New(chatagent.Harness{Model: "fixture-model"})
	defer backend.Close()
	reg, err := placement.NewRegistry("static", map[string]*placement.Placer{"static": placement.New(backend, nil)})
	if err != nil {
		t.Fatal(err)
	}
	cfg := retainedConfig(t)
	cfg.Namespace = "agents"
	cfg.Source = s
	_, err = Start(t.Context(), cfg, store, reg, nil, nil)
	if err == nil || s.lists == 0 {
		t.Fatalf("ownership barrier was bypassed or not exercised: %v", err)
	}
}

func TestStatusOnlyPublishesCoherentCurrentGeneration(t *testing.T) {
	a := desired("one", "uid-one", "registry.example/suite@sha256:abc")
	s := &sourceFixture{agents: map[string]Agent{a.Name: a}}
	c := &Controller{config: Config{Namespace: "agents", Source: s}}
	st := Status{AgentUID: string(a.UID), ObservedGeneration: a.Generation, Conditions: []metav1.Condition{{Type: "PackageVerified", Status: metav1.ConditionFalse, Reason: "Rejected", ObservedGeneration: 1}, {Type: "Registered", Status: metav1.ConditionFalse, Reason: "Rejected", ObservedGeneration: 1}}}
	if err := c.publish(t.Context(), a, st); err != nil {
		t.Fatal(err)
	}
	saved, _ := s.Get(t.Context(), a.Name)
	if saved.Status.ServedDigest != "" || saved.Status.Conditions[0].LastTransitionTime.IsZero() {
		t.Fatal("unsafe or undated refusal")
	}
	if err := c.publish(t.Context(), saved, st); err != nil {
		t.Fatal(err)
	}
	again, _ := s.Get(t.Context(), a.Name)
	if !reflect.DeepEqual(saved.Status, again.Status) {
		t.Fatal("unchanged status causes write loop")
	}
}

// Registry states are inspected, never re-registered to repair a retired row.
func TestRetiredRegistrationRemainsRetired(t *testing.T) {
	p := retainedFixture(t, nil)
	a := fixtureAgent(p)
	cfg := retainedConfig(t)
	cfg.Puller, a.Spec.Package.Reference = controllerPuller(t, p)
	source := &sourceFixture{agents: map[string]Agent{a.Name: a}}
	cfg.Source = source
	journal, err := sqlitelog.Open(t.TempDir() + "/journal.db")
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	start := func() *Controller {
		t.Helper()
		b := local.New(chatagent.Harness{Model: cfg.Model})
		t.Cleanup(func() { b.Close() })
		reg, err := placement.NewRegistry("static", map[string]*placement.Placer{"static": placement.New(b, nil)})
		if err != nil {
			t.Fatal(err)
		}
		c, err := Start(t.Context(), cfg, journal, reg, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	c := start()
	admitted, _ := source.Get(t.Context(), a.Name)
	if admitted.Status.ServedDigest != p.Digest() || admitted.Status.HarnessName == "" {
		c.Close()
		t.Fatalf("no coherent admission: %#v", admitted.Status)
	}
	name := admitted.Status.HarnessName
	if _, err := c.registry.RetireHarness(t.Context(), &v1.RetireHarnessRequest{Name: name, Reason: "simulate retirement after uncertain registration"}); err != nil {
		c.Close()
		t.Fatal(err)
	}
	if err := c.reconcile(t.Context(), []Agent{admitted}); err != nil {
		c.Close()
		t.Fatal(err)
	}
	row, err := c.registry.GetHarness(t.Context(), &v1.GetHarnessRequest{Name: name})
	if err != nil || row.State != v1.HarnessState_HARNESS_STATE_RETIRED {
		c.Close()
		t.Fatalf("retired row reactivated: %v %v", row, err)
	}
	c.Close()
	cfg.Source = &sourceFixture{agents: source.agents}
	restarted := start()
	defer restarted.Close()
	row, err = restarted.registry.GetHarness(t.Context(), &v1.GetHarnessRequest{Name: name, Observe: true})
	if err != nil || row.State != v1.HarnessState_HARNESS_STATE_RETIRED || row.UnservableReason != "" || row.ObserveError != "" {
		t.Fatalf("retired runner not restored without reactivation: %v %v", row, err)
	}
}
