package agentcontroller

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Azure/aks-durable-agents/internal/qualification"
	"github.com/Azure/aks-durable-agents/modeltransport"
)

// A valid inventory alone must not budget the candidate on a different native model tuple.
func TestPrepareRunBudgetAnchorsNativeCandidate(t *testing.T) {
	pkg := preparationFixture(t, preparationCases(), nil)
	expected := preparationExpected(t, pkg)
	expected.Binding.Endpoint = "https://candidate.example/openai/v1/"
	candidate, err := PrepareCandidate(pkg, expected)
	if err != nil {
		t.Fatal(err)
	}
	zero := int64(0)
	binding := modeltransport.RunBinding{ID: "candidate", Endpoint: expected.Binding.Endpoint, Scope: modeltransport.DefaultScope, Deployment: expected.Binding.Deployment, Pricing: modeltransport.RunPricing{Input: 100000, Output: 500000, Extra: &zero, Source: "https://example.invalid/pricing", AsOf: "2026-10-27"}}
	for _, tc := range []struct {
		name   string
		change func(*modeltransport.RunBinding, *NativeBinding, *PreparedCandidate)
	}{
		{"same", func(*modeltransport.RunBinding, *NativeBinding, *PreparedCandidate) {}},
		{"endpoint", func(b *modeltransport.RunBinding, _ *NativeBinding, _ *PreparedCandidate) {
			b.Endpoint = "https://other.example/openai/v1/"
		}},
		{"scope", func(b *modeltransport.RunBinding, _ *NativeBinding, _ *PreparedCandidate) {
			b.Scope = "https://other.example/.default"
		}},
		{"deployment", func(b *modeltransport.RunBinding, _ *NativeBinding, _ *PreparedCandidate) { b.Deployment = "different" }},
		{"changed native binding", func(b *modeltransport.RunBinding, n *NativeBinding, _ *PreparedCandidate) {
			b.Deployment = "different"
			n.Deployment = "different"
		}},
		{"wrong model digest", func(_ *modeltransport.RunBinding, _ *NativeBinding, p *PreparedCandidate) {
			p.Plan.Subject.ModelDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, n, p := binding, expected.Binding, candidate
			tc.change(&b, &n, &p)
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			r := qualification.BudgetRequest{RunID: "native-budget", LedgerPath: filepath.Join(dir, "run.sqlite"), Candidate: b}
			// The wrapper must use the prepared plan, not an unrelated caller's zero Plan.
			got, err := PrepareRunBudget(p, n, r)
			if tc.name == "same" {
				if err != nil {
					t.Fatal(err)
				}
				if len(got.Calls) != 4 || got.Config.PlanDigest == "" {
					t.Fatal("wrong native inventory")
				}
			} else if err == nil {
				t.Fatal("native model binding drift accepted")
			}
			if _, err := os.Stat(r.LedgerPath); !os.IsNotExist(err) {
				t.Fatal("native preflight opened ledger")
			}
		})
	}
}
