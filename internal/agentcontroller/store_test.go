package agentcontroller

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRetainedDigestGrammar(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	for _, ref := range []string{"registry.example/suite@" + digest, "registry.example/suite:tag@" + digest} {
		if got := retainedReferenceDigest(ref); got != digest {
			t.Fatalf("valid digest reference refused: %q => %q", ref, got)
		}
	}
	for _, ref := range []string{"registry.example/suite:tag", "registry.example/suite@", "registry.example/suite@sha256:" + strings.Repeat("A", 64), "registry.example/suite@sha256:" + strings.Repeat("a", 63), "registry.example/suite@sha256:" + strings.Repeat("a", 65), "registry.example/suite@sha512:" + strings.Repeat("a", 128), "registry.example/INVALID@" + digest, "registry.example/suite@@" + digest} {
		if got := retainedReferenceDigest(ref); got != "" {
			t.Fatalf("invalid digest reference accepted: %q => %q", ref, got)
		}
	}
}

func TestRetainedIndependentOwnersShareOnlyPackageCache(t *testing.T) {
	c, p := retainedConfig(t), retainedFixture(t, nil)
	r := openFixture(t, c)
	a := fixtureAgent(p)
	first, err := r.remember(t.Context(), a, p)
	if err != nil {
		t.Fatal(err)
	}
	a.UID = "uid-two"
	second, err := r.remember(t.Context(), a, p)
	if err != nil {
		t.Fatal(err)
	}
	a.Generation++
	third, err := r.remember(t.Context(), a, p)
	if err != nil {
		t.Fatal(err)
	}
	if first.Revision != second.Revision || second.Revision != third.Revision || first.Harness == second.Harness || second.Harness == third.Harness || len(first.Harness) != 54 {
		t.Fatalf("content and owner identity conflated: %#v %#v %#v", first, second, third)
	}
	cache, err := filepath.Glob(filepath.Join(c.Directory, "p-*.json"))
	if err != nil || len(cache) != 1 {
		t.Fatalf("cache not keyed solely by digest: %v %v", cache, err)
	}
	r.close()
	reopened := openFixture(t, c)
	if len(reopened.definitions) != 3 {
		t.Fatal("restart lost independent owners")
	}
	if _, release, err := reopened.factory(first.Harness, reopened.spec(first)); err != nil {
		t.Fatal(err)
	} else {
		release()
	}
}

func TestRetainedBindingDriftPreservesDefinitionsButRefusesFactory(t *testing.T) {
	c, p := retainedConfig(t), retainedFixture(t, nil)
	r := openFixture(t, c)
	d, err := r.remember(t.Context(), fixtureAgent(p), p)
	if err != nil {
		t.Fatal(err)
	}
	r.close()
	c.Binding = []byte(`{"policy":{"maxAttempts":4},"endpoint":"https://operator.example","runnerABI":"ada-agent-chat-v1"}`)
	r = openFixture(t, c)
	if len(r.definitions) != 1 || !bytes.Equal(r.definitions[d.Harness].Binding, d.Binding) {
		t.Fatal("drift silently discarded or substituted frozen binding")
	}
	if _, release, err := r.factory(d.Harness, r.spec(d)); err == nil {
		if release != nil {
			release()
		}
		t.Fatal("drift admitted current callbacks")
	}
	a := fixtureAgent(p)
	a.UID = "new-uid"
	fresh, err := r.remember(t.Context(), a, p)
	if err != nil {
		t.Fatal(err)
	}
	if _, release, err := r.factory(fresh.Harness, r.spec(fresh)); err != nil {
		t.Fatal(err)
	} else {
		release()
	}
}

func TestRetainedCanonicalBindingIsStable(t *testing.T) {
	c := retainedConfig(t)
	c.Binding = []byte(`{"b":2,"a":1}`)
	r := openFixture(t, c)
	want := retainedHash(r.binding)
	r.close()
	c.Binding = []byte(" { \"a\": 1, \"b\": 2 } ")
	r = openFixture(t, c)
	if retainedHash(r.binding) != want {
		t.Fatal("binding identity depends on JSON key order")
	}
}

func TestRetainedTamperAndPartialPublication(t *testing.T) {
	for _, mutation := range []string{"cache", "metadata", "abi", "namespace", "generation", "reference", "filename", "partial"} {
		t.Run(mutation, func(t *testing.T) {
			c, p := retainedConfig(t), retainedFixture(t, nil)
			r := openFixture(t, c)
			d, err := r.remember(t.Context(), fixtureAgent(p), p)
			if err != nil {
				t.Fatal(err)
			}
			r.close()
			path := filepath.Join(c.Directory, "d-"+d.Harness+".json")
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]any
			if err := json.Unmarshal(b, &fields); err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "cache":
				path = filepath.Join(c.Directory, "p-"+strings.TrimPrefix(p.Digest(), "sha256:")+".json")
				b = []byte(`{"Manifest":"dGFtcGVy","Config":"e30=","Layer":""}`)
			case "metadata":
				fields["Revision"] = "sha256:" + strings.Repeat("a", 64)
				b = fixtureJSON(fields)
			case "abi":
				fields["ABI"] = "unknown"
				b = fixtureJSON(fields)
			case "namespace":
				fields["Namespace"] = "other"
				b = fixtureJSON(fields)
			case "generation":
				fields["Generation"] = 0
				b = fixtureJSON(fields)
			case "reference":
				fields["Spec"].(map[string]any)["package"].(map[string]any)["reference"] = "registry.example/suite:latest"
				b = fixtureJSON(fields)
			case "filename":
				if err := os.Rename(path, filepath.Join(c.Directory, "d-a-wrong.json")); err != nil {
					t.Fatal(err)
				}
			case "partial":
				path = filepath.Join(c.Directory, ".tmp-interrupted")
				b = []byte("partial publication")
			}
			if mutation != "filename" {
				if err := os.WriteFile(path, b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			reloaded, err := openRetained(c, nil, nil)
			if reloaded != nil {
				reloaded.close()
			}
			if mutation == "partial" {
				if err != nil || len(reloaded.definitions) != 1 {
					t.Fatalf("incomplete unpublished temp poisoned records: %v", err)
				}
			} else if err == nil {
				t.Fatal("accepted corrupt published state")
			}
		})
	}
}

func TestRetainedCreateOnlyAndRootSymlinkEscape(t *testing.T) {
	c, p := retainedConfig(t), retainedFixture(t, nil)
	r := openFixture(t, c)
	d, err := r.remember(t.Context(), fixtureAgent(p), p)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(c.Directory, "d-"+d.Harness+".json")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.remember(t.Context(), fixtureAgent(p), p); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(original, after) {
		t.Fatal("repeat overwrote immutable metadata")
	}
	outside := filepath.Join(t.TempDir(), "sentinel")
	if err := os.WriteFile(outside, []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	if _, err := r.remember(t.Context(), fixtureAgent(p), p); err == nil {
		t.Fatal("accepted symlink record")
	}
	if b, _ := os.ReadFile(outside); string(b) != "outside" {
		t.Fatal("wrote through root symlink")
	}
	r.close()
	c.Directory = filepath.Join(t.TempDir(), "root-link")
	if err := os.Symlink(filepath.Dir(outside), c.Directory); err != nil {
		t.Fatal(err)
	}
	if other, err := openRetained(c, nil, nil); err == nil {
		other.close()
		t.Fatal("followed retained root symlink")
	}
}
