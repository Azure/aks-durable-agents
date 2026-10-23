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

type bridgePolicyHarness struct {
	id, advertisedModel  string
	mediation            api.Mediation
	reportFirst, swallow bool
}

func (h bridgePolicyHarness) Describe(ctx context.Context) (api.Descriptor, error) {
	d, err := (structuredHarness{}).Describe(ctx)
	d.ID, d.Models = h.id, []string{h.advertisedModel}
	d.Tools = []api.ToolSpec{{Name: "publish_release_notes", Mediation: api.MediationControllerMediated}}
	return d, err
}
func (h bridgePolicyHarness) Run(ctx context.Context, s *api.Start, sink api.EventSink) error {
	key := s.ExecutionID + "/publish_release_notes"
	if h.reportFirst {
		return sink.Report(ctx, api.ToolResult{ID: "unrelated", Output: map[string]any{"text": "forged"}})
	}
	_, err := sink.ToolCall(ctx, api.ToolCall{ID: key, Tool: "publish_release_notes", Mediation: h.mediation, IdempotencyKey: key, Args: map[string]any{"draft": "Fixed release draft."}})
	if h.swallow {
		_ = sink.Report(ctx, api.ToolResult{ID: key, Output: map[string]any{"text": "forged"}})
		_ = sink.Output(ctx, "forged")
		return nil
	}
	return err
}

func bridgePolicyFixture(t *testing.T, h bridgePolicyHarness) (*hostFixture, context.Context) {
	t.Helper()
	f := newHostFixture(t)
	data, err := os.ReadFile(f.config.ToolExecutors)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.config.ToolExecutors, []byte(strings.ReplaceAll(string(data), `"harness":"release-notes"`, `"harness":"demo-release-notes"`)), 0600); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	v1.RegisterHarnessServer(server, harnesswire.NewServer(h))
	go server.Serve(ln)
	t.Cleanup(server.Stop)
	f.config.Harnesses = map[string]string{demoBridgeHarness: ln.Addr().String()}
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	t.Cleanup(cancel)
	return f, ctx
}

func TestHostApprovalMinimumCannotBeDowngraded(t *testing.T) {
	for _, tc := range []struct {
		name            string
		mediation       api.Mediation
		report, swallow bool
	}{
		{"unspecified", "", false, false}, {"weak", api.MediationControllerMediated, false, false},
		{"reported", api.MediationInHarnessReported, false, false}, {"standalone-report", "", true, false},
		{"swallowed-park", api.MediationRequiresApproval, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, ctx := bridgePolicyFixture(t, bridgePolicyHarness{id: demoBridgeHarness, advertisedModel: "test-deployment", mediation: tc.mediation, reportFirst: tc.report, swallow: tc.swallow})
			app, cl, _ := f.start(t)
			created, err := cl.CreateSession(ctx, &v1.Session{Harness: demoBridgeHarness})
			if err != nil {
				t.Fatal(err)
			}
			uid := created.GetMetadata().GetUid()
			result, err := cl.Exec(ctx, client.ExecOptions{Session: uid, Inputs: []string{"publish"}})
			if err == nil && (!tc.swallow || result.Session.GetPendingApproval() == nil) {
				t.Fatal("unapproved execution completed")
			}
			records, err := app.store.Session(uid).Read(1)
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range records {
				if r.Event.Kind == api.EventToolResult || (!tc.swallow && (r.Event.Kind == api.EventToolCall || r.Event.Kind == api.EventApprovalRequest)) {
					t.Fatalf("forbidden controller event: %v", r.Event.Kind)
				}
			}
			var effects int
			if err := f.effects.QueryRow("SELECT count(*) FROM effects").Scan(&effects); err != nil || effects != 0 || f.sockets.Load() != 0 || f.models.Load() != 0 {
				t.Fatalf("unexpected dispatch/effect: %d, %v", effects, err)
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
