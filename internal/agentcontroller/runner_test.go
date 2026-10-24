package agentcontroller

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/agent-primitives/sessions/api"
	v1 "github.com/agent-primitives/sessions/api/genpb"
	"github.com/agent-primitives/sessions/harnesswire"
	"github.com/agent-primitives/sessions/runtime/remote"
	"google.golang.org/protobuf/proto"
)

func TestRunnerActualSocketAndExactSpecAdmission(t *testing.T) {
	c, p := retainedConfig(t), retainedFixture(t, nil)
	r := openFixture(t, c)
	d, err := r.remember(t.Context(), fixtureAgent(p), p)
	if err != nil {
		t.Fatal(err)
	}
	spec := r.spec(d)
	addr := spec.GetRemote().GetAddress()
	if !strings.HasPrefix(addr, "unix:///tmp/ada-agent-") {
		t.Fatalf("not a private real Unix address: %q", addr)
	}
	backend := remote.New(addr)
	defer backend.Close()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	desc, err := backend.Describe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if desc.ID != d.Harness || desc.Version != RunnerABI || !reflect.DeepEqual(desc.Models, []string{c.Model}) || !desc.Capabilities.ForkSafe || desc.Capabilities.Resumability != api.ResumabilityStatelessReplay {
		t.Fatalf("wrong frozen descriptor: %#v", desc)
	}
	if !proto.Equal(spec.Capabilities, harnesswire.DescriptorToProto(desc).Capabilities) {
		t.Fatal("stored capabilities differ from actual listener")
	}
	for _, change := range []func(*v1.HarnessSpec){func(s *v1.HarnessSpec) { s.GetRemote().Address = "unix:///tmp/foreign.sock" }, func(s *v1.HarnessSpec) { s.DescriptorId = "foreign" }, func(s *v1.HarnessSpec) { s.Capabilities.ForkSafe = false }} {
		bad := proto.Clone(spec).(*v1.HarnessSpec)
		change(bad)
		if _, release, err := r.factory(d.Harness, bad); err == nil {
			if release != nil {
				release()
			}
			t.Fatal("accepted mismatched spec")
		}
	}
	if _, release, err := r.factory("unknown", spec); err == nil {
		if release != nil {
			release()
		}
		t.Fatal("adopted unknown owner")
	}
	socket := strings.TrimPrefix(addr, "unix://")
	r.close()
	if _, err := os.Lstat(socket); !os.IsNotExist(err) {
		t.Fatal("close leaked owned socket")
	}
}

type captureSink struct {
	api.EventSink
	requests []api.ModelRequest
}

func (s *captureSink) Model(_ context.Context, req api.ModelRequest) (api.ModelResponse, error) {
	s.requests = append(s.requests, req)
	return api.ModelResponse{Message: *api.TextMessage("assistant", "answer")}, nil
}
func TestRunnerFreezesPromptAndModelWithoutDuplicatingConversation(t *testing.T) {
	p := retainedFixture(t, nil)
	h, err := packagedHarness(p, definition{Harness: "test-harness", Model: "operator-model", Spec: Spec{Member: "writer"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, start := range []*api.Start{{Config: []byte(`{"system_prompt":"replace"}`)}, {Config: []byte(`{}`)}, {Model: "author-model-not-host-model"}} {
		if err := h.Run(t.Context(), start, &captureSink{}); err == nil {
			t.Fatal("caller replaced frozen configuration")
		}
	}
	start := &api.Start{History: []api.Event{{Kind: api.EventInput, Message: api.TextMessage("user", "old")}, {Kind: api.EventOutput, Message: api.TextMessage("assistant", "answer")}}, Inputs: []api.Message{*api.TextMessage("user", "new")}}
	sink := &captureSink{}
	if err := h.Run(t.Context(), start, sink); err != nil {
		t.Fatal(err)
	}
	if len(start.Config) != 0 || start.Model != "" {
		t.Fatal("runner mutated caller Start")
	}
	if len(sink.requests) != 1 || sink.requests[0].Model != "operator-model" {
		t.Fatal("did not bind host model")
	}
	var messages []string
	for _, m := range sink.requests[0].Messages {
		messages = append(messages, m.Role+":"+m.Text())
	}
	if !reflect.DeepEqual(messages, []string{"system:Write fictional release notes.\n", "user:old", "assistant:answer", "user:new"}) {
		t.Fatalf("wrong replay context: %v", messages)
	}
}

func TestRunnerRefusesUnsupportedModelRequirements(t *testing.T) {
	for _, kind := range []string{"protocol", "endpoint", "secrets", "capabilities", "invoke"} {
		t.Run(kind, func(t *testing.T) {
			p := retainedFixture(t, func(_ map[string]any, a map[string]any) {
				m := a["model"].(map[string]any)
				switch kind {
				case "protocol":
					m["protocol"] = "other-protocol"
				case "endpoint":
					m["endpointEnv"] = "PACKAGED_ENDPOINT"
				case "secrets":
					m["secretRefs"] = []any{"credential"}
				case "capabilities":
					delete(m, "model")
					m["capabilities"] = map[string]any{"api": "openai-chat-completions-v1", "contextTokens": 1024, "outputTokens": 128, "streaming": false, "toolCalling": false}
				case "invoke":
					a["invokes"] = []any{map[string]any{"agent": "worker", "maxConcurrent": 1, "maxDepth": 1}}
				}
			})
			if _, err := packagedHarness(p, definition{Harness: "test", Model: "host", Spec: Spec{Member: "writer"}}); err == nil {
				t.Fatal("silently ignored execution requirement")
			}
		})
	}
}

func TestRunnerDoesNotUnlinkForeignSocketOrFile(t *testing.T) {
	for _, kind := range []string{"regular", "symlink", "unowned-stale", "live"} {
		t.Run(kind, func(t *testing.T) {
			c, p := retainedConfig(t), retainedFixture(t, nil)
			r := openFixture(t, c)
			d, err := r.remember(t.Context(), fixtureAgent(p), p)
			if err != nil {
				t.Fatal(err)
			}
			socket := strings.TrimPrefix(r.spec(d).GetRemote().Address, "unix://")
			r.close()
			switch kind {
			case "regular":
				err = os.WriteFile(socket, []byte("not a socket"), 0600)
			case "symlink":
				err = os.Symlink(filepath.Join(t.TempDir(), "target"), socket)
			default:
				ln, e := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
				err = e
				if e == nil {
					ln.SetUnlinkOnClose(false)
					if kind == "live" {
						t.Cleanup(func() { _ = ln.Close() })
					} else {
						_ = ln.Close()
					}
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Remove(socket) })
			if reopened, err := openRetained(c, nil, nil); err == nil {
				reopened.close()
				t.Fatal("adopted or removed foreign socket/file")
			}
			if _, err := os.Lstat(socket); err != nil {
				t.Fatal("removed foreign socket/file")
			}
		})
	}
}
