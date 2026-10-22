package sessionfixture

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/agent-primitives/sessions/api"
	v1 "github.com/agent-primitives/sessions/api/genpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestActorPlacementEvidenceReadsOnlyPrivateFixedFile(t *testing.T) {
	data := privateTempDir(t)
	path := filepath.Join(data, "substrate-placement.json")
	want := []byte(`{"version":1,"first":{"actor":"session"},"latest":{"actor":"session"}}`)
	if err := os.WriteFile(path, want, 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := RunCLI(t.Context(), []string{"placement-evidence", "--data", data}, &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out.String()) != string(want) {
		t.Fatal(out.String())
	}
	os.Chmod(path, 0644)
	if err := RunCLI(t.Context(), []string{"placement-evidence", "--data", data}, io.Discard, io.Discard); err == nil {
		t.Fatal("public placement file accepted")
	}
	if err := RunCLI(t.Context(), []string{"placement-evidence", "--data", data, "--file", "/elsewhere"}, io.Discard, io.Discard); err == nil {
		t.Fatal("arbitrary file reader accepted")
	}
}

func TestActorHarnessUsesFrozenStatelessScenario(t *testing.T) {
	got, err := ActorHarness().Describe(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	want, err := newHarnessScenario("v2").Describe(t.Context())
	if err != nil || !reflect.DeepEqual(got, want) || got.Capabilities.Resumability != api.ResumabilityStatelessReplay {
		t.Fatalf("actor changed frozen v2 descriptor: got=%+v want=%+v error=%v", got, want, err)
	}
}

// Removing the actor-only capability command must reject the selected image
// before provisioning, rather than discovering a legacy image in a paid run.
func TestActorHarnessCapabilityCheck(t *testing.T) {
	var out bytes.Buffer
	if err := RunCLI(t.Context(), []string{"actor-harness", "--check"}, &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	desc, _ := newHarnessScenario("v2").Describe(t.Context())
	want := map[string]any{"version": float64(1), "mode": "actor-v2", "harness": "release-notes", "protocol": "harnesswire", "port": float64(80), "resumability": "STATELESS_REPLAY", "descriptor": desc.Version, "readinessPort": float64(8081), "readinessPath": "/readyz"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("capability mismatch: %v", got)
	}
}

func TestActorHarnessReadinessImpliesBoundGRPCAndStopsWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	reader, writer := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- RunCLI(ctx, []string{"actor-harness", "--addr", "127.0.0.1:0"}, writer, io.Discard) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("actor listeners did not stop")
		}
		reader.Close()
		writer.Close()
	})
	var started map[string]string
	if err := json.NewDecoder(reader).Decode(&started); err != nil {
		t.Fatal(err)
	}
	if started["readinessAddr"] == "" {
		t.Fatal("native wakeup readiness listener missing")
	}
	client := &http.Client{Timeout: time.Second}
	response, err := client.Get("http://" + started["readinessAddr"] + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatal(response.StatusCode)
	}
	conn, err := grpc.NewClient(started["addr"], grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := v1.NewHarnessClient(conn).Describe(ctx, &v1.DescribeRequest{}); err != nil {
		t.Fatalf("ready actor could not Describe: %v", err)
	}
}

func TestActorHarnessRejectsHostStateAndNonActorAddresses(t *testing.T) {
	for _, args := range [][]string{
		{"--instructions", "/data/instructions.txt"},
		{"--data", "/data"},
		{"--node-name", "node"},
		{"--pod-uid", "pod"},
		{"--scenario", "v1"},
		{"--addr", "0.0.0.0:9000"},
		{"--addr", "0.0.0.0:0"},
		{"--addr", "fixture.example:80"},
		{"--addr", "[::]:80"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			err := RunCLI(t.Context(), append([]string{"actor-harness"}, args...), io.Discard, io.Discard)
			if err == nil || strings.Contains(err.Error(), "unknown session-fixture command") {
				t.Fatalf("expected actor-specific validation: %v", err)
			}
		})
	}
}
