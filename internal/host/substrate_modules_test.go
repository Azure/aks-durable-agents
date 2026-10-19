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
	for _, want := range []struct{ path, version, replacement string }{
		{"github.com/agent-primitives/sessions", "v0.1.3-0.20261018160920-ce018b2daa0f", "github.com/gambtho/agentsessions"},
		{"github.com/agent-primitives/sessions/integrations/substrate", "v0.0.0-20261019014422-ff3da2b33f61", ""},
		{"github.com/agent-substrate/substrate", "v0.4.1-0.20261013053953-96dffb287919", ""},
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
		if want.replacement != "" {
			if got.Replace == nil || got.Replace.Path != want.replacement || got.Replace.Version != want.version {
				t.Fatalf("auth fork changed: %+v", got)
			}
		} else if got.Replace != nil || got.Version != want.version {
			t.Fatalf("pin changed: %+v", got)
		}
	}
}
