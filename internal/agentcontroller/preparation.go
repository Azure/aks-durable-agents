package agentcontroller

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Azure/aks-durable-agents/internal/agentpackage"
	"github.com/Azure/aks-durable-agents/internal/qualification"
	"github.com/Azure/aks-durable-agents/modeltransport"
	"github.com/agent-primitives/suite/core"
	"github.com/gowebpki/jcs"
)

// NativeBinding is the host's frozen, non-secret native binding JSON shape.
// Field names and encoding are shared with ordinary hosting; they are not a new
// persisted format. The retained manager canonicalizes these JSON bytes with JCS.
type NativeBinding struct {
	Endpoint, Deployment, Scope string
	Policy                      json.RawMessage
	RunnerABI                   string
}

// JSON preserves the host's existing json.Marshal encoding, including RawMessage.
func (b NativeBinding) JSON() ([]byte, error) { return json.Marshal(b) }

// CandidateExpectations contains only host-selected context, never evaluation
// inventory. Manifest/member/composition/platform must match the verified package;
// an optional ProfileDigest must match the exact derived native profile.
type CandidateExpectations struct {
	Workspace, Target, MemberID                      string
	ManifestDigest, CompositionDigest, ProfileDigest string
	Platform                                         core.Platform
	Binding                                          NativeBinding
	ExpiresAt                                        time.Time
}

type PreparedCase struct {
	Ref   core.FileRef
	Bytes []byte
	Input string
}

// PreparationSummary retains verified source bytes and the exact native inputs.
// It is not qualification, eligibility, publisher trust or execution authority.
type PreparationSummary struct {
	ManifestDigest                              string
	SuiteManifest                               []byte
	Member                                      core.ManifestRef
	MemberBytes                                 []byte
	Instructions                                core.FileRef
	InstructionBytes                            []byte
	Composition                                 core.CompositionRef
	CompositionBytes                            []byte
	Index                                       core.FileRef
	IndexBytes                                  []byte
	Cases                                       []PreparedCase
	AuthoredModel, Model                        string
	NativeConfig, BindingJSON, CanonicalBinding []byte
	SourceDigest                                string
}

type PreparedCandidate struct {
	Plan    qualification.Plan
	Summary PreparationSummary
}

// ErrPreparation identifies a whole-candidate refusal. Context is fixed and
// deliberately excludes package contents, host values and filesystem paths.
var ErrPreparation = errors.New("candidate preparation refused")

// PrepareCandidate derives complete inventory from one verified file view. It
// allocates only returned data: no retained manager, store, listener or dispatch.
func PrepareCandidate(p *agentpackage.Package, expected CandidateExpectations) (PreparedCandidate, error) {
	refuse := func(reason string) (PreparedCandidate, error) {
		return PreparedCandidate{}, fmt.Errorf("%w: %s", ErrPreparation, reason)
	}
	if p == nil || p.Report() == nil || p.Digest() != expected.ManifestDigest {
		return refuse("verified manifest expectation")
	}
	// This existing function is pure. Calling it directly keeps candidate and
	// ordinary native validation/rendering identical without another renderer.
	h, err := packagedHarness(p, definition{Spec: Spec{Member: expected.MemberID}, Model: expected.Binding.Deployment})
	if err != nil {
		return refuse("unsupported native profile")
	}
	binding := expected.Binding
	if binding.RunnerABI != RunnerABI || binding.Endpoint == "" || binding.Deployment == "" {
		return refuse("native binding")
	}
	if binding.Scope == "" {
		binding.Scope = modeltransport.DefaultScope
	}
	policy, err := jcs.Transform(binding.Policy)
	if err != nil || len(policy) == 0 || policy[0] != '{' {
		return refuse("native policy")
	}
	bindingJSON, err := binding.JSON()
	if err != nil {
		return refuse("native binding encoding")
	}
	// Identical canonicalization and size bound to openRetained, before hashing.
	canonicalBinding, err := jcs.Transform(bindingJSON)
	if err != nil || len(canonicalBinding) > 64<<10 {
		return refuse("native binding bytes")
	}
	s := PreparationSummary{ManifestDigest: p.Digest(), Model: h.model, NativeConfig: h.config, BindingJSON: bindingJSON, CanonicalBinding: canonicalBinding}
	var suite core.Suite
	s.SuiteManifest, err = preparationDocument(p, "agentsuite.json", &suite)
	if err != nil {
		return refuse("suite document")
	}
	s.Member = suite.Agents[0]
	var agent core.Agent
	s.MemberBytes, err = preparationDocument(p, s.Member.Path, &agent)
	if err != nil {
		return refuse("member document")
	}
	s.Instructions, s.AuthoredModel = agent.Instructions, agent.Model.Model
	s.InstructionBytes, err = p.ReadFile(s.Instructions.Path)
	if err != nil {
		return refuse("instructions")
	}
	selected := 0
	for _, ref := range suite.Compositions {
		if ref.Agent == expected.MemberID && ref.Platform == expected.Platform && ref.RuntimeProfile == "" {
			s.Composition = ref
			selected++
		}
	}
	if selected != 1 || s.Composition.Descriptor.Digest != expected.CompositionDigest {
		return refuse("composition expectation")
	}
	s.CompositionBytes, err = p.ReadFile(s.Composition.Path)
	if err != nil {
		return refuse("composition document")
	}
	if len(agent.Evals) != 1 {
		return refuse("exactly one evaluation index required")
	}
	s.Index = agent.Evals[0]
	var index core.EvaluationIndex
	s.IndexBytes, err = preparationDocument(p, s.Index.Path, &index)
	if err != nil {
		return refuse("evaluation index")
	}
	profileDigest := preparationDigest("candidate-native-profile-v1", struct {
		RunnerABI string
		Config    []byte
	}{binding.RunnerABI, h.config})
	if expected.ProfileDigest != "" && expected.ProfileDigest != profileDigest {
		return refuse("native profile expectation")
	}
	plan := qualification.Plan{
		Subject: qualification.Subject{Workspace: expected.Workspace, Target: expected.Target,
			SuiteDigest: p.Digest(), BindingDigest: retainedHash(canonicalBinding), ProfileDigest: profileDigest,
			PolicyDigest: retainedHash(policy), JudgeDigest: retainedHash([]byte("candidate-no-judge-v1\n")),
			ModelDigest: preparationDigest("candidate-model-v1", struct{ Endpoint, Deployment, Scope string }{binding.Endpoint, binding.Deployment, binding.Scope})},
		Members:  []qualification.Member{{ID: s.Member.ID, Digest: s.Member.Descriptor.Digest}},
		MemberID: s.Member.ID, CompositionDigest: s.Composition.Descriptor.Digest, Platform: s.Composition.Platform.String(), IndexDigest: s.Index.Descriptor.Digest,
		ExpiresAt: expected.ExpiresAt.Round(0).UTC(),
	}
	for _, ref := range index.Cases {
		var c core.EvaluationCase
		data, err := preparationDocument(p, ref.Path, &c)
		if err != nil {
			return refuse("evaluation case")
		}
		q := qualification.Case{ID: c.ID, Digest: ref.Descriptor.Digest, InputDigest: retainedHash([]byte(c.Input)), Runs: 1}
		if c.Runs != nil {
			q.Runs = *c.Runs
		}
		q.MinPasses = q.Runs
		if c.MinPasses != nil {
			q.MinPasses = *c.MinPasses
		}
		for _, a := range c.Assertions {
			if a.Critical != nil && !*a.Critical {
				return refuse("cannot preserve advisory meaning of critical:false assertions")
			}
			qa := qualification.Assertion{ID: a.ID, Kind: a.Type}
			switch a.Type {
			case "contains", "notContains":
				qa.Value = a.Value
			case "regex":
				qa.Value = a.Pattern
			case "toolNotCalled":
				qa.Value = a.Tool
			default:
				// Plan cannot retain a judge's rubric/version, and this native
				// profile cannot support toolCalled or unknown assertion kinds.
				return refuse("unsupported assertion")
			}
			q.Assertions = append(q.Assertions, qa)
		}
		plan.Cases = append(plan.Cases, q)
		s.Cases = append(s.Cases, PreparedCase{Ref: ref, Bytes: data, Input: c.Input})
	}
	if qualification.ValidatePlan(plan) != nil {
		return refuse("qualification bounds")
	}
	// Manifest identity anchors all retained package bytes. Selected references
	// disambiguate inventory without claiming Git provenance or publisher trust.
	s.SourceDigest = preparationDigest("candidate-source-v1", struct{ Manifest, Member, Composition, Index string }{
		p.Digest(), s.Member.Descriptor.Digest, s.Composition.Descriptor.Digest, s.Index.Descriptor.Digest,
	})
	return PreparedCandidate{Plan: plan, Summary: s}, nil
}

func preparationDocument(p *agentpackage.Package, path string, out any) ([]byte, error) {
	b, err := p.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err = core.Unmarshal(b, out); err != nil {
		return nil, err
	}
	return b, nil
}

func preparationDigest(domain string, value any) string {
	return retainedHash(append([]byte(domain+"\n"), retainedJSON(value)...))
}
