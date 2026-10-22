package sessionfixture

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/agent-primitives/sessions/api"
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
	want := map[string]any{"version": float64(1), "mode": "actor-v2", "harness": "release-notes", "protocol": "harnesswire", "port": float64(80), "resumability": "STATELESS_REPLAY", "descriptor": desc.Version}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("capability mismatch: %v", got)
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
