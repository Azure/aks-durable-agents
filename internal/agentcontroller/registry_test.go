package agentcontroller

import (
	"testing"

	v1 "github.com/agent-primitives/sessions/api/genpb"
	"github.com/agent-primitives/sessions/harness/chatagent"
	"github.com/agent-primitives/sessions/placement"
	"github.com/agent-primitives/sessions/runtime/local"
	"github.com/agent-primitives/sessions/session"
	"github.com/agent-primitives/sessions/sqlitelog"
)

// Exercise our factory through the durable SDK registry, without the future
// Kubernetes controller or an admin endpoint. This is not the kind/resume proof.
func TestRuntimeRegistryLoadsRetiredWithoutReactivation(t *testing.T) {
	p := retainedFixture(t, nil)
	cfg := retainedConfig(t)
	journal, err := sqlitelog.Open(t.TempDir() + "/journal.db")
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	open := func() (*retained, *session.HarnessRegistry) {
		t.Helper()
		r, err := openRetained(cfg, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		static := local.New(chatagent.Harness{Model: cfg.Model})
		t.Cleanup(func() { static.Close() })
		placements, err := placement.NewRegistry("static", map[string]*placement.Placer{"static": placement.New(static, nil)})
		if err != nil {
			r.close()
			t.Fatal(err)
		}
		hr, err := session.NewHarnessRegistry(journal, placements, r.factory)
		if err != nil {
			r.close()
			t.Fatal(err)
		}
		return r, hr
	}
	r, hr := open()
	a := fixtureAgent(p)
	one, err := r.remember(t.Context(), a, p)
	if err != nil {
		hr.Close()
		r.close()
		t.Fatal(err)
	}
	a.Name = "second"
	a.UID = "uid-second"
	two, err := r.remember(t.Context(), a, p)
	if err != nil {
		hr.Close()
		r.close()
		t.Fatal(err)
	}
	for _, d := range []definition{one, two} {
		if _, err := hr.RegisterHarness(t.Context(), &v1.RegisterHarnessRequest{Name: d.Harness, Spec: r.spec(d)}); err != nil {
			hr.Close()
			r.close()
			t.Fatal(err)
		}
	}
	if _, err := hr.RetireHarness(t.Context(), &v1.RetireHarnessRequest{Name: one.Harness, Reason: "first Agent deleted"}); err != nil {
		hr.Close()
		r.close()
		t.Fatal(err)
	}
	other, err := hr.GetHarness(t.Context(), &v1.GetHarnessRequest{Name: two.Harness, Observe: true})
	if err != nil || other.State != v1.HarnessState_HARNESS_STATE_ACTIVE || other.ObserveError != "" {
		hr.Close()
		r.close()
		t.Fatalf("independent owner affected: %v %v", other, err)
	}
	hr.Close()
	r.close()
	restored, reloaded := open()
	defer restored.close()
	defer reloaded.Close()
	row, err := reloaded.GetHarness(t.Context(), &v1.GetHarnessRequest{Name: one.Harness, Observe: true})
	if err != nil || row.State != v1.HarnessState_HARNESS_STATE_RETIRED || row.UnservableReason != "" || row.ObserveError != "" || row.GetObserved().GetId() != one.Harness {
		t.Fatalf("retired definition not restored: %v %v", row, err)
	}
	active, err := reloaded.GetHarness(t.Context(), &v1.GetHarnessRequest{Name: two.Harness, Observe: true})
	if err != nil || active.State != v1.HarnessState_HARNESS_STATE_ACTIVE || active.ObserveError != "" {
		t.Fatalf("active independent definition not restored: %v %v", active, err)
	}
}
