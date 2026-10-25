package agentcontroller

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Azure/aks-durable-agents/internal/agentpackage"
	"github.com/Azure/aks-durable-agents/internal/qualification"
	"github.com/Azure/aks-durable-agents/modeltransport"
	"github.com/agent-primitives/suite/core"
	"github.com/gowebpki/jcs"
)

func preparationJSON(v any) []byte {
	b, err := jcs.Transform(fixtureJSON(v))
	if err != nil {
		panic(err)
	}
	return b
}
func preparationRef(path, media string, b []byte) core.FileRef {
	return core.FileRef{Path: path, Descriptor: core.Descriptor{MediaType: media, Digest: fixtureDigest(b), Size: int64(len(b))}}
}
func preparationCases() []core.EvaluationCase {
	runs, passes, critical := 3, 2, true
	return []core.EvaluationCase{
		{SchemaVersion: core.SpecVersion, MediaType: core.MediaTypeEvaluationCase, ID: "z-first", Input: "Kia ora 世界\n\r\n\u2028", Runs: &runs, MinPasses: &passes, Assertions: []core.EvaluationAssertion{
			{ID: "z", Type: "contains", Value: "hello", Critical: &critical},
			{ID: "a", Type: "notContains", Value: "goodbye"},
			{ID: "r", Type: "regex", Pattern: "^hello.*$"},
			{ID: "t", Type: "toolNotCalled", Tool: "send_mail"},
		}},
		{SchemaVersion: core.SpecVersion, MediaType: core.MediaTypeEvaluationCase, ID: "a-second", Input: "Next?", Assertions: []core.EvaluationAssertion{{ID: "ok", Type: "contains", Value: "yes"}}},
	}
}
func preparationFixture(t *testing.T, cases []core.EvaluationCase, change func(map[string]any, map[string]any, map[string][]byte)) *agentpackage.Package {
	t.Helper()
	return retainedFixtureFiles(t, []byte("System <&> 世界\r\n\u2028\u2029\n"), func(suite, agent map[string]any, files map[string][]byte) {
		index := core.EvaluationIndex{SchemaVersion: core.SpecVersion, MediaType: core.MediaTypeEvaluationIndex, Agent: "writer", Limits: core.EvaluationLimits{MaxCases: 128, MaxCaseBytes: 4 << 20}}
		for _, c := range cases {
			path := "evals/writer/cases/" + c.ID + ".json"
			files[path] = preparationJSON(c)
			index.Cases = append(index.Cases, preparationRef(path, core.MediaTypeEvaluationCase, files[path]))
		}
		const path = "evals/writer/index.json"
		files[path] = preparationJSON(index)
		var refs any
		if err := json.Unmarshal(preparationJSON([]core.FileRef{preparationRef(path, core.MediaTypeEvaluationIndex, files[path])}), &refs); err != nil {
			t.Fatal(err)
		}
		agent["evals"] = refs
		if change != nil {
			change(suite, agent, files)
		}
	})
}
func preparationExpected(t *testing.T, p *agentpackage.Package) CandidateExpectations {
	t.Helper()
	var suite core.Suite
	b, _ := p.ReadFile("agentsuite.json")
	if err := core.Unmarshal(b, &suite); err != nil {
		t.Fatal(err)
	}
	return CandidateExpectations{
		Workspace: "workspace 世界", Target: "target", MemberID: "writer", ManifestDigest: p.Digest(), CompositionDigest: suite.Compositions[0].Descriptor.Digest,
		Platform:  core.Platform{OS: "linux", Architecture: "amd64"},
		Binding:   NativeBinding{Endpoint: "https://model.example/?a=1&b=<value>", Deployment: "operator-model", Policy: json.RawMessage(`{ "z": "\u2028", "a": [1, true] }`), RunnerABI: RunnerABI},
		ExpiresAt: time.Date(2099, 3, 4, 5, 6, 7, 8, time.FixedZone("offset", 3600)),
	}
}

// Catches descriptor substitution, dropped/reordered assertions and model-label confusion.
func TestPrepareCandidateIdentityAndNativeParity(t *testing.T) {
	p := preparationFixture(t, preparationCases(), nil)
	e := preparationExpected(t, p)
	got, err := PrepareCandidate(p, e)
	if err != nil {
		t.Fatal(err)
	}
	s := got.Summary
	if s.ManifestDigest != p.Digest() || !bytes.Equal(s.SuiteManifest, mustPreparationFile(t, p, "agentsuite.json")) || s.Member.Path != "members/not-the-id.json" || s.Instructions.Path != "prompts/frozen.md" || s.Index.Path != "evals/writer/index.json" {
		t.Fatalf("source references changed: %+v", s)
	}
	plan := got.Plan
	wantCases := []qualification.Case{
		{ID: "z-first", Digest: s.Cases[0].Ref.Descriptor.Digest, InputDigest: fixtureDigest([]byte("Kia ora 世界\n\r\n\u2028")), Runs: 3, MinPasses: 2, Assertions: []qualification.Assertion{{ID: "z", Kind: "contains", Value: "hello"}, {ID: "a", Kind: "notContains", Value: "goodbye"}, {ID: "r", Kind: "regex", Value: "^hello.*$"}, {ID: "t", Kind: "toolNotCalled", Value: "send_mail"}}},
		{ID: "a-second", Digest: s.Cases[1].Ref.Descriptor.Digest, InputDigest: fixtureDigest([]byte("Next?")), Runs: 1, MinPasses: 1, Assertions: []qualification.Assertion{{ID: "ok", Kind: "contains", Value: "yes"}}},
	}
	if !reflect.DeepEqual(plan.Cases, wantCases) || !reflect.DeepEqual(plan.Members, []qualification.Member{{ID: "writer", Digest: s.Member.Descriptor.Digest}}) || plan.MemberID != "writer" || plan.IndexDigest != s.Index.Descriptor.Digest || plan.CompositionDigest != e.CompositionDigest || plan.Platform != "linux/amd64" || plan.Subject.Workspace != e.Workspace || plan.Subject.Target != e.Target || plan.Subject.SuiteDigest != p.Digest() {
		t.Fatalf("wrong qualification mapping: %+v", plan)
	}
	if plan.ExpiresAt.Location() != time.UTC || !plan.ExpiresAt.Equal(e.ExpiresAt) {
		t.Fatal("expiry not normalized")
	}
	if qualification.ValidatePlan(plan) != nil {
		t.Fatal("prepared plan fails qualification validation")
	}
	for _, pair := range []struct {
		ref core.FileRef
		b   []byte
	}{{core.FileRef{Path: s.Member.Path, Descriptor: s.Member.Descriptor}, s.MemberBytes}, {s.Instructions, s.InstructionBytes}, {core.FileRef{Path: s.Composition.Path, Descriptor: s.Composition.Descriptor}, s.CompositionBytes}, {s.Index, s.IndexBytes}, {s.Cases[0].Ref, s.Cases[0].Bytes}, {s.Cases[1].Ref, s.Cases[1].Bytes}} {
		if !bytes.Equal(pair.b, mustPreparationFile(t, p, pair.ref.Path)) || fixtureDigest(pair.b) != pair.ref.Descriptor.Digest {
			t.Fatal("summary lost exact verified bytes")
		}
	}
	if s.Cases[0].Input != "Kia ora 世界\n\r\n\u2028" || s.AuthoredModel != "author-model-not-host-model" || s.Model != e.Binding.Deployment {
		t.Fatal("input or selected/authored model changed")
	}
	h, err := packagedHarness(p, definition{Spec: Spec{Member: "writer"}, Model: e.Binding.Deployment})
	if err != nil || !bytes.Equal(s.NativeConfig, h.config) || s.Model != h.model {
		t.Fatalf("native mismatch: %v", err)
	}
	if string(s.NativeConfig) != `{"system_prompt":"System \u003c\u0026\u003e 世界\r\n\u2028\u2029\n"}` {
		t.Fatalf("native config bytes changed: %s", s.NativeConfig)
	}
	for _, d := range []string{plan.Subject.BindingDigest, plan.Subject.PolicyDigest, plan.Subject.ModelDigest, plan.Subject.JudgeDigest, plan.Subject.ProfileDigest, s.SourceDigest} {
		if len(d) != 71 {
			t.Fatalf("missing digest: %q", d)
		}
	}
	e.ProfileDigest = plan.Subject.ProfileDigest
	matched, err := PrepareCandidate(p, e)
	if err != nil || !reflect.DeepEqual(got, matched) {
		t.Fatalf("exact profile expectation changed output: %v", err)
	}
}
func mustPreparationFile(t *testing.T, p *agentpackage.Package, path string) []byte {
	t.Helper()
	b, err := p.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Catches aliasing of caller policy, verified file view, or previous results.
func TestPrepareCandidateReproducibilityAndOwnership(t *testing.T) {
	p := preparationFixture(t, preparationCases(), nil)
	e := preparationExpected(t, p)
	one, err := PrepareCandidate(p, e)
	if err != nil {
		t.Fatal(err)
	}
	m, c, l := p.OCIBytes()
	fresh, err := agentpackage.Verify(t.Context(), p.Digest(), m, c, l)
	if err != nil {
		t.Fatal(err)
	}
	two, err := PrepareCandidate(fresh, e)
	if err != nil || !reflect.DeepEqual(one, two) {
		t.Fatalf("nondeterministic fresh Verify: %v", err)
	}
	e.Binding.Policy[0] = '['
	one.Plan.Members[0].ID = "mutated"
	one.Plan.Cases[0].Assertions[0].Value = "mutated"
	for _, b := range [][]byte{one.Summary.SuiteManifest, one.Summary.MemberBytes, one.Summary.InstructionBytes, one.Summary.CompositionBytes, one.Summary.IndexBytes, one.Summary.NativeConfig, one.Summary.BindingJSON, one.Summary.CanonicalBinding, one.Summary.Cases[0].Bytes} {
		b[0] ^= 1
	}
	one.Summary.Cases[0].Input = "mutated"
	three, err := PrepareCandidate(p, preparationExpected(t, p))
	if err != nil || !reflect.DeepEqual(two, three) {
		t.Fatalf("mutable output/input changed preparation: %v", err)
	}
}

// The live retained manager's bytes and status digest must match preparation.
func TestPrepareCandidateBindingParity(t *testing.T) {
	p := preparationFixture(t, preparationCases(), nil)
	e := preparationExpected(t, p)
	got, err := PrepareCandidate(p, e)
	if err != nil {
		t.Fatal(err)
	}
	// Independent old host shape: no lower-case tags or changed RawMessage encoding.
	want, err := json.Marshal(struct {
		Endpoint, Deployment, Scope string
		Policy                      json.RawMessage
		RunnerABI                   string
	}{e.Binding.Endpoint, e.Binding.Deployment, modeltransport.DefaultScope, e.Binding.Policy, RunnerABI})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Summary.BindingJSON, want) {
		t.Fatalf("host serialization drift: %s != %s", got.Summary.BindingJSON, want)
	}
	cfg := retainedConfig(t)
	cfg.Binding = want
	r := openFixture(t, cfg)
	if !bytes.Equal(got.Summary.CanonicalBinding, r.binding) || got.Plan.Subject.BindingDigest != fixtureDigest(r.binding) {
		t.Fatal("candidate/live binding digest mismatch")
	}
	e.Binding.Scope = modeltransport.DefaultScope
	explicit, err := PrepareCandidate(p, e)
	if err != nil || !reflect.DeepEqual(explicit, got) {
		t.Fatalf("effective scope differs: %v", err)
	}
}

func assertPreparationRefused(t *testing.T, p *agentpackage.Package, e CandidateExpectations, reason string) {
	t.Helper()
	got, err := PrepareCandidate(p, e)
	if !errors.Is(err, ErrPreparation) || !reflect.DeepEqual(got, PreparedCandidate{}) {
		t.Fatalf("wanted whole refusal, got %+v / %v", got, err)
	}
	if reason != "" && !strings.Contains(err.Error(), reason) {
		t.Fatalf("missing plain reason %q: %v", reason, err)
	}
	for _, private := range []string{e.Workspace, e.Target, e.Binding.Endpoint, "private-source-marker"} {
		if private != "" && strings.Contains(err.Error(), private) {
			t.Fatalf("refusal leaked host/package input: %v", err)
		}
	}
}

func TestPrepareCandidateRefusesSubstitutionAndInvalidContext(t *testing.T) {
	p := preparationFixture(t, preparationCases(), nil)
	base := preparationExpected(t, p)
	if _, err := PrepareCandidate(p, base); err != nil {
		t.Fatal(err)
	}
	assertPreparationRefused(t, nil, base, "")
	assertPreparationRefused(t, new(agentpackage.Package), base, "")
	for _, tc := range []struct {
		name   string
		change func(*CandidateExpectations)
	}{
		{"manifest", func(e *CandidateExpectations) { e.ManifestDigest = "sha256:" + strings.Repeat("f", 64) }},
		{"absent manifest", func(e *CandidateExpectations) { e.ManifestDigest = "" }},
		{"member", func(e *CandidateExpectations) { e.MemberID = "other" }},
		{"composition", func(e *CandidateExpectations) { e.CompositionDigest = "sha256:" + strings.Repeat("f", 64) }},
		{"platform", func(e *CandidateExpectations) { e.Platform.Architecture = "arm64" }},
		{"variant", func(e *CandidateExpectations) { e.Platform.Variant = "v8" }},
		{"profile", func(e *CandidateExpectations) { e.ProfileDigest = "sha256:" + strings.Repeat("f", 64) }},
		{"ABI", func(e *CandidateExpectations) { e.Binding.RunnerABI = "other" }},
		{"endpoint", func(e *CandidateExpectations) { e.Binding.Endpoint = "" }},
		{"deployment", func(e *CandidateExpectations) { e.Binding.Deployment = "" }},
		{"policy null", func(e *CandidateExpectations) { e.Binding.Policy = json.RawMessage(`null`) }},
		{"policy malformed", func(e *CandidateExpectations) { e.Binding.Policy = json.RawMessage(`{private-source-marker`) }},
		{"policy array", func(e *CandidateExpectations) { e.Binding.Policy = json.RawMessage(`[]`) }},
		{"policy duplicate", func(e *CandidateExpectations) { e.Binding.Policy = json.RawMessage(`{"a":1,"a":2}`) }},
		{"binding bytes", func(e *CandidateExpectations) {
			e.Binding.Policy = json.RawMessage(`{"a":"` + strings.Repeat("x", 64<<10) + `"}`)
		}},
		{"workspace", func(e *CandidateExpectations) { e.Workspace = "bad\nworkspace" }},
		{"target", func(e *CandidateExpectations) { e.Target = "bad target" }},
		{"expiry", func(e *CandidateExpectations) { e.ExpiresAt = time.Time{} }},
	} {
		t.Run(tc.name, func(t *testing.T) { e := base; tc.change(&e); assertPreparationRefused(t, p, e, "") })
	}
}

func TestPrepareCandidateRefusesUnsupportedInventoryAndBounds(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func([]core.EvaluationCase)
		reason string
	}{
		{"advisory contains", func(c []core.EvaluationCase) { v := false; c[0].Assertions[0].Critical = &v }, "cannot preserve advisory meaning"},
		{"advisory negative", func(c []core.EvaluationCase) { v := false; c[0].Assertions[1].Critical = &v }, "cannot preserve advisory meaning"},
		{"advisory regex", func(c []core.EvaluationCase) { v := false; c[0].Assertions[2].Critical = &v }, "cannot preserve advisory meaning"},
		{"advisory tool", func(c []core.EvaluationCase) { v := false; c[0].Assertions[3].Critical = &v }, "cannot preserve advisory meaning"},
		{"unknown advisory", func(c []core.EvaluationCase) {
			v := false
			c[0].Assertions[0] = core.EvaluationAssertion{ID: "unknown", Type: "future", Value: "private-source-marker", Critical: &v}
		}, "cannot preserve advisory meaning"},
		{"toolCalled", func(c []core.EvaluationCase) {
			c[0].Assertions[0] = core.EvaluationAssertion{ID: "called", Type: "toolCalled", Tool: "send_mail"}
		}, "unsupported assertion"},
		{"llmJudge", func(c []core.EvaluationCase) {
			score := 75
			c[0].Assertions[0] = core.EvaluationAssertion{ID: "judge", Type: "llmJudge", Rubric: "private-source-marker", MinScore: &score, JudgeModel: "judge", JudgeVersion: "v1"}
		}, "unsupported assertion"},
		{"slots", func(c []core.EvaluationCase) { n := 64; c[0].Runs = &n }, "qualification bounds"},
		{"Unicode tool", func(c []core.EvaluationCase) { c[0].Assertions[3].Tool = "送信" }, "qualification bounds"},
		{"long tool", func(c []core.EvaluationCase) { c[0].Assertions[3].Tool = strings.Repeat("a", 129) }, "qualification bounds"},
		{"operand bytes", func(c []core.EvaluationCase) { c[0].Assertions[0].Value = strings.Repeat("a", 4097) }, "qualification bounds"},
		{"rows", func(c []core.EvaluationCase) {
			n := 63
			c[0].Runs = &n
			c[0].Assertions = nil
			for i := 0; i < 509; i++ {
				c[0].Assertions = append(c[0].Assertions, core.EvaluationAssertion{ID: "a" + strconv.Itoa(i), Type: "contains", Value: "x"})
			}
		}, "qualification bounds"},
		{"metadata", func(c []core.EvaluationCase) {
			c[0].Assertions = nil
			for i := 0; i < 128; i++ {
				c[0].Assertions = append(c[0].Assertions, core.EvaluationAssertion{ID: "a" + strconv.Itoa(i), Type: "contains", Value: strings.Repeat("a", 4096)})
			}
		}, "qualification bounds"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := preparationCases()
			tc.change(c)
			p := preparationFixture(t, c, nil)
			assertPreparationRefused(t, p, preparationExpected(t, p), tc.reason)
		})
	}
	for _, tc := range []struct {
		name   string
		change func(map[string]any, map[string]any, map[string][]byte)
	}{
		{"no evals", func(_, a map[string]any, f map[string][]byte) {
			delete(a, "evals")
			for path := range f {
				if strings.HasPrefix(path, "evals/") {
					delete(f, path)
				}
			}
		}},
		{"endpoint binding", func(_, a map[string]any, _ map[string][]byte) {
			a["model"].(map[string]any)["endpointEnv"] = "PRIVATE_ENDPOINT"
		}},
		{"multi member", func(_, a map[string]any, _ map[string][]byte) {
			a["invokes"] = []any{map[string]any{"agent": "worker", "maxConcurrent": 1, "maxDepth": 1}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := preparationFixture(t, preparationCases(), tc.change)
			assertPreparationRefused(t, p, preparationExpected(t, p), "")
		})
	}
}

func TestPrepareCandidateRunDefaultsAndExactBounds(t *testing.T) {
	for _, tc := range []struct {
		name                         string
		runs, assertions, valueBytes int
	}{
		{"default minPasses", 3, 1, 1}, {"64 slots and 32000 rows", 64, 500, 1}, {"operand bound", 1, 1, 4096},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := preparationCases()[:1]
			c[0].Runs = &tc.runs
			c[0].MinPasses = nil
			c[0].Assertions = nil
			for i := 0; i < tc.assertions; i++ {
				c[0].Assertions = append(c[0].Assertions, core.EvaluationAssertion{ID: "a" + strconv.Itoa(i), Type: "contains", Value: strings.Repeat("x", tc.valueBytes)})
			}
			p := preparationFixture(t, c, nil)
			got, err := PrepareCandidate(p, preparationExpected(t, p))
			if err != nil {
				t.Fatal(err)
			}
			if got.Plan.Cases[0].Runs != tc.runs || got.Plan.Cases[0].MinPasses != tc.runs || len(got.Plan.Cases[0].Assertions) != tc.assertions {
				t.Fatal("run defaults or exact bound changed")
			}
		})
	}
}

func TestPrepareCandidateDigestsBindNativeInputs(t *testing.T) {
	p := preparationFixture(t, preparationCases(), nil)
	e := preparationExpected(t, p)
	base, err := PrepareCandidate(p, e)
	if err != nil {
		t.Fatal(err)
	}
	if base.Plan.Subject.PolicyDigest != fixtureDigest([]byte("{\"a\":[1,true],\"z\":\"\u2028\"}")) || base.Plan.Subject.JudgeDigest != fixtureDigest([]byte("candidate-no-judge-v1\n")) {
		t.Fatal("policy/no-judge derivation changed")
	}
	for _, tc := range []struct {
		name          string
		change        func(*CandidateExpectations)
		model, policy bool
	}{
		{"deployment", func(e *CandidateExpectations) { e.Binding.Deployment = "other-model" }, true, false},
		{"endpoint", func(e *CandidateExpectations) { e.Binding.Endpoint = "https://other.example/" }, true, false},
		{"scope", func(e *CandidateExpectations) { e.Binding.Scope = "other-scope" }, true, false},
		{"policy", func(e *CandidateExpectations) { e.Binding.Policy = json.RawMessage(`{"a":[2,true],"z":"\u2028"}`) }, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := e
			tc.change(&changed)
			got, err := PrepareCandidate(p, changed)
			if err != nil {
				t.Fatal(err)
			}
			if (got.Plan.Subject.ModelDigest != base.Plan.Subject.ModelDigest) != tc.model || (got.Plan.Subject.PolicyDigest != base.Plan.Subject.PolicyDigest) != tc.policy || got.Plan.Subject.BindingDigest == base.Plan.Subject.BindingDigest {
				t.Fatal("digest ignored changed frozen binding")
			}
			if got.Plan.Subject.ProfileDigest != base.Plan.Subject.ProfileDigest || got.Plan.Subject.JudgeDigest != base.Plan.Subject.JudgeDigest || got.Summary.SourceDigest != base.Summary.SourceDigest {
				t.Fatal("binding changed independent profile/source/no-judge identity")
			}
		})
	}
	changed := preparationFixture(t, preparationCases(), func(_, a map[string]any, f map[string][]byte) {
		f["prompts/frozen.md"] = []byte("Changed system prompt\n")
		a["instructions"] = map[string]any{"path": "prompts/frozen.md", "descriptor": map[string]any{"mediaType": core.MediaTypeInstructions, "digest": fixtureDigest(f["prompts/frozen.md"]), "size": len(f["prompts/frozen.md"])}}
	})
	got, err := PrepareCandidate(changed, preparationExpected(t, changed))
	if err != nil {
		t.Fatal(err)
	}
	if got.Plan.Subject.ProfileDigest == base.Plan.Subject.ProfileDigest || got.Summary.SourceDigest == base.Summary.SourceDigest || got.Plan.Subject.ModelDigest != base.Plan.Subject.ModelDigest {
		t.Fatal("profile/source not bound to exact prompt bytes")
	}
}

// Corrupt/missing/bad inventory cannot cross the Verify boundary into preparation.
func TestPreparationRequiresVerifiedInventory(t *testing.T) {
	p := preparationFixture(t, preparationCases(), nil)
	for _, tc := range []struct {
		name   string
		change func(map[string][]byte)
	}{
		{"missing index", func(f map[string][]byte) { delete(f, "evals/writer/index.json") }},
		{"missing case", func(f map[string][]byte) { delete(f, "evals/writer/cases/z-first.json") }},
		{"corrupt index", func(f map[string][]byte) { f["evals/writer/index.json"] = []byte(`{}`) }},
		{"corrupt case", func(f map[string][]byte) { f["evals/writer/cases/z-first.json"] = []byte(`{}`) }},
		{"bad assertion", func(f map[string][]byte) { f["evals/writer/cases/z-first.json"] = []byte(`{"assertions":[]}`) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string][]byte{}
			for _, name := range []string{"agentsuite.json", "members/not-the-id.json", "prompts/frozen.md", "catalog.json", "build.json", "composition.json", "evals/writer/index.json", "evals/writer/cases/z-first.json", "evals/writer/cases/a-second.json"} {
				files[name] = mustPreparationFile(t, p, name)
			}
			tc.change(files)
			got, err := fixtureVerifyFiles(t, files)
			if !errors.Is(err, agentpackage.ErrIntegrity) || got != nil {
				t.Fatalf("unverified inventory escaped: %v", err)
			}
		})
	}
}
