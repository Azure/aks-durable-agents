package host

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

// Guard MVS's effective assembly, not just the declared requirements.
func TestSubstrateResolvedModules(t *testing.T) {
	cmd := exec.Command("go", "list", "-m", "-json", "github.com/agent-primitives/sessions", "github.com/agent-primitives/sessions/integrations/substrate", "github.com/agent-substrate/substrate")
	raw, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	for _, want := range []struct{ path, version string }{
		{"github.com/agent-primitives/sessions", "v0.3.0"},
		{"github.com/agent-primitives/sessions/integrations/substrate", "v0.3.0"},
		{"github.com/agent-substrate/substrate", "v0.5.0"},
	} {
		var got struct {
			Path, Version string
			Replace       *struct{ Path, Version string }
		}
		if err := dec.Decode(&got); err != nil {
			t.Fatal(err)
		}
		if got.Path != want.path {
			t.Fatalf("wrong module: %+v", got)
		}
		if got.Replace != nil || got.Version != want.version {
			t.Fatalf("pin changed: %+v", got)
		}
	}
}
