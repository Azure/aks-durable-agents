package agentcontroller

import (
	"github.com/Azure/aks-durable-agents/internal/agentpackage"
	"os"
	"path/filepath"
	"testing"
)

func TestRepositoryRevocationIsolatesFactoryWithoutDiscardingCache(t *testing.T) {
	p := retainedFixture(t, nil)
	cfg := retainedConfig(t)
	cfg.Puller, _ = agentpackage.New(agentpackage.Policy{Repositories: []string{"registry.example/suite", "registry.example/other"}}, nil)
	r, err := openRetained(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	a := fixtureAgent(p)
	first, err := r.remember(t.Context(), a, p)
	if err != nil {
		r.close()
		t.Fatal(err)
	}
	a.Name = "other"
	a.UID = "uid-other"
	a.Spec.Package.Reference = "registry.example/other@" + p.Digest()
	second, err := r.remember(t.Context(), a, p)
	if err != nil {
		r.close()
		t.Fatal(err)
	}
	r.close()
	cfg.Puller, _ = agentpackage.New(agentpackage.Policy{Repositories: []string{"registry.example/other"}}, nil)
	restored, err := openRetained(cfg, nil, nil)
	if err != nil {
		t.Fatalf("one revoked repo blocked all retained definitions: %v", err)
	}
	defer restored.close()
	if len(restored.definitions) != 2 {
		t.Fatal("revocation removed retained definitions")
	}
	if placer, release, err := restored.factory(first.Harness, restored.spec(first)); err == nil {
		if release != nil {
			release()
		}
		t.Fatalf("revoked repo supplied placer: %v", placer)
	}
	if _, release, err := restored.factory(second.Harness, restored.spec(second)); err != nil {
		t.Fatalf("other repo was isolated too: %v", err)
	} else {
		release()
	}
	a.Name = "revoked"
	a.UID = "uid-new"
	a.Spec.Package.Reference = first.Spec.Package.Reference
	if _, err := restored.remember(t.Context(), a, p); err == nil {
		t.Fatal("new definition admitted from revoked repo")
	}
}
func TestRetainedRejectsExposedOrHardlinkedCache(t *testing.T) {
	for _, kind := range []string{"permissions", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			p := retainedFixture(t, nil)
			cfg := retainedConfig(t)
			r, err := openRetained(cfg, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := r.remember(t.Context(), fixtureAgent(p), p); err != nil {
				r.close()
				t.Fatal(err)
			}
			r.close()
			path := filepath.Join(cfg.Directory, "p-"+p.Digest()[7:]+".json")
			if kind == "permissions" {
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Link(path, filepath.Join(t.TempDir(), "outside")); err != nil {
					t.Fatal(err)
				}
			}
			if restored, err := openRetained(cfg, nil, nil); err == nil {
				restored.close()
				t.Fatal("unsafe retained cache admitted")
			}
		})
	}
}

func TestRetainedModelIsPartOfImmutableRevision(t *testing.T) {
	p := retainedFixture(t, nil)
	cfg := retainedConfig(t)
	r, err := openRetained(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	d, err := r.remember(t.Context(), fixtureAgent(p), p)
	r.close()
	if err != nil {
		t.Fatal(err)
	}
	d.Model = "other-model"
	cfg.Model = d.Model
	if err := os.WriteFile(filepath.Join(cfg.Directory, "d-"+d.Harness+".json"), retainedJSON(d), 0600); err != nil {
		t.Fatal(err)
	}
	if restored, err := openRetained(cfg, nil, nil); err == nil {
		restored.close()
		t.Fatal("model changed without changing immutable revision")
	}
}
func TestStateDirectoryAliasesShareManagerLock(t *testing.T) {
	cfg := retainedConfig(t)
	cfg.Directory = filepath.Join(cfg.Directory, "state")
	r, err := openRetained(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(filepath.Dir(cfg.Directory), alias); err != nil {
		t.Fatal(err)
	}
	cfg.Directory = filepath.Join(alias, "state")
	if second, err := openRetained(cfg, nil, nil); err == nil {
		second.close()
		t.Fatal("second manager acquired same state via alias")
	}
}

func TestRetainedRequiresConfiguredReferencePolicy(t *testing.T) {
	cfg := retainedConfig(t)
	cfg.Puller = nil
	if r, err := openRetained(cfg, nil, nil); err == nil {
		r.close()
		t.Fatal("missing repository policy accepted")
	}
}
