package agentcontroller

import (
	"testing"

	v1 "github.com/agent-primitives/sessions/api/genpb"
	"github.com/agent-primitives/sessions/harness/chatagent"
	"github.com/agent-primitives/sessions/placement"
	"github.com/agent-primitives/sessions/runtime/local"
	"github.com/agent-primitives/sessions/sqlitelog"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func startTestController(t *testing.T, cfg Config, journal *sqlitelog.Store) *Controller {
	t.Helper()
	backend := local.New(chatagent.Harness{Model: cfg.Model})
	t.Cleanup(func() { backend.Close() })
	registry, err := placement.NewRegistry("static", map[string]*placement.Placer{"static": placement.New(backend, nil)})
	if err != nil {
		t.Fatal(err)
	}
	controller, err := Start(t.Context(), cfg, journal, registry, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(controller.Close)
	return controller
}
func TestControllerUIDDeletionRecreationOrphanAndCanonicalBinding(t *testing.T) {
	p := retainedFixture(t, nil)
	cfg := retainedConfig(t)
	cfg.Binding = []byte(`{"b":2,"a":1}`)
	one := fixtureAgent(p)
	cfg.Puller, one.Spec.Package.Reference = controllerPuller(t, p)
	two := one
	two.Name = "two"
	two.UID = "uid-two"
	source := &sourceFixture{agents: map[string]Agent{one.Name: one, two.Name: two}}
	cfg.Source = source
	journal, err := sqlitelog.Open(t.TempDir() + "/journal.db")
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	ctl := startTestController(t, cfg, journal)
	first, _ := source.Get(t.Context(), one.Name)
	second, _ := source.Get(t.Context(), two.Name)
	if first.Status.ServedDigest != p.Digest() || second.Status.ServedDigest != p.Digest() || first.Status.HarnessName == second.Status.HarnessName {
		t.Fatal("owners were not independently admitted")
	}
	source.mu.Lock()
	delete(source.agents, one.Name)
	source.mu.Unlock()
	if err := ctl.reconcile(t.Context(), []Agent{second}); err != nil {
		t.Fatal(err)
	}
	row, err := ctl.registry.GetHarness(t.Context(), &v1.GetHarnessRequest{Name: first.Status.HarnessName})
	if err != nil || row.State != v1.HarnessState_HARNESS_STATE_RETIRED {
		t.Fatal("deleted UID remained admitted")
	}
	row, err = ctl.registry.GetHarness(t.Context(), &v1.GetHarnessRequest{Name: second.Status.HarnessName})
	if err != nil || row.State != v1.HarnessState_HARNESS_STATE_ACTIVE {
		t.Fatal("shared-content owner was retired too")
	}
	one.UID = "uid-recreated"
	source.mu.Lock()
	source.agents[one.Name] = one
	source.mu.Unlock()
	if err := ctl.reconcile(t.Context(), []Agent{one, second}); err != nil {
		t.Fatal(err)
	}
	recreated, _ := source.Get(t.Context(), one.Name)
	if recreated.Status.ServedDigest != p.Digest() || recreated.Status.HarnessName == first.Status.HarnessName {
		t.Fatal("recreated resource adopted old UID registration")
	}
	ctl.Close()
	// Delete the second object while no controller is running; the startup snapshot
	// must retire it before admitting any new Sessions RPC.
	cfg.Binding = []byte(" { \"a\": 1, \"b\": 2 } ")
	cfg.Source = &sourceFixture{agents: map[string]Agent{one.Name: recreated}}
	ctl = startTestController(t, cfg, journal)
	current, _ := cfg.Source.Get(t.Context(), one.Name)
	if current.Status.ServedDigest != p.Digest() {
		t.Fatal("equivalent canonical binding drifted")
	}
	row, err = ctl.registry.GetHarness(t.Context(), &v1.GetHarnessRequest{Name: second.Status.HarnessName})
	if err != nil || row.State != v1.HarnessState_HARNESS_STATE_RETIRED {
		t.Fatal("startup orphan remained active")
	}
	ctl.Close()
	cfg.Binding = []byte(`{"a":3}`)
	cfg.Source = &sourceFixture{agents: map[string]Agent{one.Name: current}}
	ctl = startTestController(t, cfg, journal)
	refused, _ := cfg.Source.Get(t.Context(), one.Name)
	if refused.Status.ServedDigest != "" || refused.Status.Conditions[1].Reason != "BindingChanged" {
		t.Fatal("changed binding silently replaced frozen definition")
	}
	row, err = ctl.registry.GetHarness(t.Context(), &v1.GetHarnessRequest{Name: current.Status.HarnessName})
	if err != nil || row.State != v1.HarnessState_HARNESS_STATE_RETIRED {
		t.Fatal("drifted registration remained active")
	}
}
func TestStatusRejectsRecreatedTerminatingOrChangedGeneration(t *testing.T) {
	old := desired("one", "uid-old", "registry.example/suite@sha256:abc")
	for _, change := range []func(*Agent){func(a *Agent) { a.UID = "uid-new" }, func(a *Agent) { a.Generation++ }, func(a *Agent) { now := metav1.Now(); a.DeletionTimestamp = &now }} {
		fresh := old
		change(&fresh)
		source := &sourceFixture{agents: map[string]Agent{fresh.Name: fresh}}
		ctl := &Controller{config: Config{Source: source}}
		if err := ctl.publish(t.Context(), old, Status{AgentUID: string(old.UID), ServedDigest: "unverified"}); err != nil {
			t.Fatal(err)
		}
		saved, _ := source.Get(t.Context(), old.Name)
		if saved.Status.ServedDigest != "" {
			t.Fatal("stale or terminating object received admission status")
		}
	}
}
