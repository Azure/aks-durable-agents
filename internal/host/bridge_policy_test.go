package host

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/agent-primitives/sessions/api"
	v1 "github.com/agent-primitives/sessions/api/genpb"
	"github.com/agent-primitives/sessions/client"
	"github.com/agent-primitives/sessions/harnesswire"
	"google.golang.org/grpc"
)

func boundedPolicyContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func setApprovalMinimum(t *testing.T, f *hostFixture, name string, required bool) {
	t.Helper()
	data, err := os.ReadFile(f.config.ToolExecutors)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ReplaceAll(string(data), `"harness":"release-notes"`, `"harness":"`+name+`"`)
	if !required {
		text = strings.Replace(text, `"durable_dedup":true`, `"durable_dedup":false`, 1)
	}
	if err := os.WriteFile(f.config.ToolExecutors, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
}

type bridgePolicyHarness struct {
	id, advertisedModel, requestModel string
	mediation                         api.Mediation
	swallow                           bool
	reportFirst                       bool
}

func (h bridgePolicyHarness) Describe(context.Context) (api.Descriptor, error) {
	return api.Descriptor{ID: h.id, Models: []string{h.advertisedModel}, Tools: []api.ToolSpec{{Name: "publish_release_notes", Mediation: api.MediationControllerMediated}}, Capabilities: api.Capabilities{Resumability: api.ResumabilityStatelessReplay, ForkSafe: true}}, nil
}
func (h bridgePolicyHarness) Run(ctx context.Context, s *api.Start, sink api.EventSink) error {
	if h.requestModel != "" {
		if s.Model != "test-deployment" {
			return sink.Output(ctx, "wrong start model")
		}
		_, err := sink.Model(ctx, api.ModelRequest{Model: h.requestModel, Messages: s.Inputs})
		return err
	}
	key := s.ExecutionID + "/publish_release_notes"
	if h.reportFirst {
		if err := sink.Report(ctx, api.ToolResult{ID: key, Output: map[string]any{"local_demo": true}}); err != nil {
			return err
		}
		return sink.Output(ctx, "forged publication")
	}
	_, err := sink.ToolCall(ctx, api.ToolCall{ID: key, Tool: "publish_release_notes", Mediation: h.mediation, IdempotencyKey: key, Args: map[string]any{"draft": "Fixed release draft.", "destination": "release-notes-demo"}})
	if h.swallow {
		_ = sink.Report(ctx, api.ToolResult{ID: key, Output: map[string]any{"text": "forged publication"}})
		_ = sink.Output(ctx, "forged publication")
		return nil
	}
	return err
}
func serveBridgePolicyHarness(t *testing.T, f *hostFixture, name string, h bridgePolicyHarness) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	v1.RegisterHarnessServer(server, harnesswire.NewServer(h))
	go server.Serve(ln)
	t.Cleanup(server.Stop)
	f.config.Harnesses = map[string]string{name: ln.Addr().String()}
}

func TestHostApprovalMinimumCannotBeDowngraded(t *testing.T) {
	for _, mediation := range []api.Mediation{"", api.MediationControllerMediated, api.MediationInHarnessReported, api.MediationRequiresApproval} {
		t.Run(string(mediation), func(t *testing.T) {
			ctx := boundedPolicyContext(t)
			f := newHostFixture(t)
			setApprovalMinimum(t, f, demoBridgeHarness, true)
			serveBridgePolicyHarness(t, f, demoBridgeHarness, bridgePolicyHarness{id: demoBridgeHarness, advertisedModel: "test-deployment", mediation: mediation})
			_, cl, _ := f.start(t)
			result, err := cl.Exec(ctx, client.ExecOptions{Harness: demoBridgeHarness, Inputs: []string{"publish"}})
			if mediation == api.MediationRequiresApproval {
				if err != nil || result.Session.GetPendingApproval() == nil {
					t.Fatalf("explicit approval did not park: %v", err)
				}
			} else {
				if err == nil {
					t.Fatal("weak protected proposal accepted")
				}
				if result != nil {
					for _, record := range result.Records {
						switch record.GetEvent().GetKind() {
						case v1.EventKind_EVENT_TOOL_CALL, v1.EventKind_EVENT_APPROVAL_REQUEST, v1.EventKind_EVENT_TOOL_RESULT:
							t.Fatal("weak proposal reached controller", record.GetEvent().GetKind())
						}
					}
				}
			}
			if f.sockets.Load() != 0 {
				t.Fatal("guarded route connected before approval")
			}
			var effects int
			if err := f.effects.QueryRow("SELECT count(*) FROM effects").Scan(&effects); err != nil || effects != 0 {
				t.Fatalf("unexpected publication effects=%d err=%v", effects, err)
			}
		})
	}
}

func TestDemoBridgeCallbacksRejectBeforeSharedTransport(t *testing.T) {
	for _, model := range []string{"", "other", "test-deployment"} {
		calls := 0
		plain := checkedBridgeModel("test-deployment", func(context.Context, api.ModelRequest) (api.ModelResponse, error) {
			calls++
			return api.ModelResponse{}, nil
		})
		stream := checkedBridgeStreamingModel("test-deployment", func(context.Context, api.ModelRequest, func(string)) (api.ModelResponse, error) {
			calls++
			return api.ModelResponse{}, nil
		})
		_, plainErr := plain(t.Context(), api.ModelRequest{Model: model})
		_, streamErr := stream(t.Context(), api.ModelRequest{Model: model}, func(string) {})
		if model == "test-deployment" {
			if plainErr != nil || streamErr != nil || calls != 2 {
				t.Fatalf("target rejected: %v %v calls=%d", plainErr, streamErr, calls)
			}
		} else if plainErr == nil || streamErr == nil || calls != 0 {
			t.Fatalf("mismatch reached callbacks: %v %v calls=%d", plainErr, streamErr, calls)
		}
	}
}

func TestDemoBridgeSubstrateStillChecksDescriptor(t *testing.T) {
	ctx := boundedPolicyContext(t)
	f, control := newHostFixture(t), newControlFixture(t)
	setApprovalMinimum(t, f, "demo-release-notes", true)
	serveBridgePolicyHarness(t, f, "demo-release-notes", bridgePolicyHarness{id: "wrong-descriptor", advertisedModel: "test-deployment"})
	control.sub.Harness = "demo-release-notes"
	control.sub.RouterAddr = f.config.Harnesses["demo-release-notes"]
	f.config.Harnesses = nil
	f.config.Substrate = &control.sub
	_, cl, _ := f.start(t)
	if _, err := cl.Exec(ctx, client.ExecOptions{Harness: "demo-release-notes", Inputs: []string{"draft"}}); err == nil {
		t.Fatal("Substrate bypassed demo descriptor admission")
	}
	if f.models.Load() != 0 || f.sockets.Load() != 0 {
		t.Fatal("wrong Substrate descriptor reached provider")
	}
}

func TestHostBridgeRejectsStandaloneReportedReceipt(t *testing.T) {
	f := newHostFixture(t)
	setApprovalMinimum(t, f, demoBridgeHarness, true)
	serveBridgePolicyHarness(t, f, demoBridgeHarness, bridgePolicyHarness{id: demoBridgeHarness, advertisedModel: "test-deployment", reportFirst: true})
	app, cl, _ := f.start(t)
	ctx := boundedPolicyContext(t)
	created, err := cl.CreateSession(ctx, &v1.Session{Harness: demoBridgeHarness})
	if err != nil {
		t.Fatal(err)
	}
	uid := created.GetMetadata().GetUid()
	if _, err := cl.Exec(ctx, client.ExecOptions{Session: uid, Inputs: []string{"publish"}}); err == nil {
		t.Fatal("standalone receipt accepted")
	}
	records, err := app.store.Session(uid).Read(1)
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range records {
		if record.Event.Kind == api.EventToolResult {
			t.Fatal("unapproved receipt journaled")
		}
	}
	if f.sockets.Load() != 0 || f.models.Load() != 0 {
		t.Fatal("standalone report caused dispatch")
	}
}

func TestHostSwallowedParkCannotForgePublication(t *testing.T) {
	f := newHostFixture(t)
	setApprovalMinimum(t, f, demoBridgeHarness, true)
	serveBridgePolicyHarness(t, f, demoBridgeHarness, bridgePolicyHarness{id: demoBridgeHarness, advertisedModel: "test-deployment", mediation: api.MediationRequiresApproval, swallow: true})
	_, cl, _ := f.start(t)
	result, err := cl.Exec(boundedPolicyContext(t), client.ExecOptions{Harness: demoBridgeHarness, Inputs: []string{"publish"}})
	if f.sockets.Load() != 0 {
		t.Fatal("swallowed park executed publication")
	}
	if err == nil && result.Session.GetPendingApproval() == nil {
		t.Fatal("swallowed park completed")
	}
	if result != nil {
		for _, record := range result.Records {
			if record.GetEvent().GetKind() == v1.EventKind_EVENT_TOOL_RESULT {
				t.Fatal("forged publication receipt recorded")
			}
		}
	}
}

func TestDemoBridgeRequiresDurablePublicationExecutor(t *testing.T) {
	f := newHostFixture(t)
	setApprovalMinimum(t, f, "demo-release-notes", false)
	serveBridgePolicyHarness(t, f, "demo-release-notes", bridgePolicyHarness{id: "demo-release-notes", advertisedModel: "test-deployment"})
	app, err := newApplication(t.Context(), f.config, fixtureCredential{t}, nil)
	if app != nil {
		app.Close()
	}
	if err == nil {
		t.Fatal("demo startup accepted missing durable publication executor")
	}
	if f.models.Load() != 0 || f.sockets.Load() != 0 {
		t.Fatal("startup refusal caused effects")
	}
}

func TestDemoBridgeDescriptorAndModelsAreChecked(t *testing.T) {
	for _, tc := range []struct{ name, id, advertised, request string }{
		{"descriptor", "other", "test-deployment", ""},
		{"advertised", "demo-release-notes", "other", ""},
		{"request", "demo-release-notes", "test-deployment", "other"},
		{"default", "demo-release-notes", "test-deployment", ""},
		{"deployment", "demo-release-notes", "test-deployment", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := boundedPolicyContext(t)
			f := newHostFixture(t)
			setApprovalMinimum(t, f, "demo-release-notes", true)
			serveBridgePolicyHarness(t, f, "demo-release-notes", bridgePolicyHarness{id: tc.id, advertisedModel: tc.advertised, requestModel: tc.request})
			if tc.name == "deployment" {
				f.config.Deployment = "other"
			}
			if tc.name == "advertised" || tc.name == "deployment" {
				app, err := newApplication(ctx, f.config, fixtureCredential{t}, nil)
				if app != nil {
					app.Close()
				}
				if err == nil {
					t.Fatal("unsupported advertised model admitted")
				}
			} else {
				_, cl, _ := f.start(t)
				if tc.name == "default" {
					if _, err := cl.CreateSession(ctx, &v1.Session{Harness: "demo-release-notes", Model: "other"}); err == nil {
						t.Fatal("wrong session default admitted")
					}
				} else if _, err := cl.Exec(ctx, client.ExecOptions{Harness: "demo-release-notes", Inputs: []string{"draft"}}); err == nil {
					t.Fatal("wrong descriptor or request model admitted")
				}
			}
			if f.models.Load() != 0 || f.sockets.Load() != 0 {
				t.Fatal("admission refusal reached provider or socket")
			}
		})
	}
}
