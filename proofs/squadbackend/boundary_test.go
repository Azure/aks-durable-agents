package squadbackend_test

import (
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const parentModule = "github.com/Azure/aks-durable-agents"
const proofModule = parentModule + "/proofs/squadbackend"

type modulePin struct{ Path, Version string }
type manifest struct {
	Module        modulePin
	Go, Toolchain string
	Require       []modulePin
	Replace       []struct{ Old, New modulePin }
}

func goOutput(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "go", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go %v in %s: %v\n%s", args, dir, err, out)
	}
	return string(out)
}

func readManifest(t *testing.T, dir string) manifest {
	t.Helper()
	var m manifest
	if err := json.Unmarshal([]byte(goOutput(t, dir, "mod", "edit", "-json")), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func selectedPins(t *testing.T, dir string) map[string]string {
	t.Helper()
	pins := map[string]string{}
	dec := json.NewDecoder(strings.NewReader(goOutput(t, dir, "list", "-m", "-json", "all")))
	for {
		var m modulePin
		err := dec.Decode(&m)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if m.Version != "" {
			pins[m.Path] = m.Version
		}
	}
	return pins
}

func usedPins(t *testing.T) map[string]string {
	t.Helper()
	pins := map[string]string{}
	out := goOutput(t, ".", "list", "-deps", "-test", "-tags", "squadproof", "-f", "{{if .Module}}{{.Module.Path}} {{.Module.Version}}{{end}}", "./...")
	for _, line := range strings.Split(out, "\n") {
		if fields := strings.Fields(line); len(fields) == 2 {
			pins[fields[0]] = fields[1]
		}
	}
	return pins
}

func TestProofModulePins(t *testing.T) {
	root := filepath.Join("..", "..")
	proof, parent := readManifest(t, "."), readManifest(t, root)
	if proof.Module.Path != proofModule || parent.Module.Path != parentModule {
		t.Fatalf("expected separate proof module, got %q / %q", proof.Module.Path, parent.Module.Path)
	}
	if proof.Go != parent.Go || proof.Toolchain != parent.Toolchain {
		t.Fatalf("Go/toolchain drift: proof %s/%s root %s/%s", proof.Go, proof.Toolchain, parent.Go, parent.Toolchain)
	}
	if len(proof.Replace) != 1 || proof.Replace[0].Old.Path != parentModule || proof.Replace[0].New.Path != "../.." || proof.Replace[0].New.Version != "" {
		t.Fatalf("proof must use only the local parent replacement: %+v", proof.Replace)
	}
	declared := map[string]string{}
	for _, p := range parent.Require {
		declared[p.Path] = p.Version
	}
	for _, p := range proof.Require {
		if version, ok := declared[p.Path]; ok && version != p.Version {
			t.Errorf("declared %s drift: proof %s root %s", p.Path, p.Version, version)
		}
	}
	selected := selectedPins(t, root)
	// Lazy module graphs can differ for unused parent dependencies. Compare
	// selected versions for code the proof actually compiles, including tests.
	for path, version := range usedPins(t) {
		if want, ok := selected[path]; ok && want != version {
			t.Errorf("selected %s drift: proof %s root %s", path, version, want)
		}
	}
}

func TestRootExcludesProof(t *testing.T) {
	root := filepath.Join("..", "..")
	for _, dir := range []string{".", root} {
		if _, err := os.Lstat(filepath.Join(dir, "go.work")); !os.IsNotExist(err) {
			t.Fatalf("unexpected workspace file in %s: %v", dir, err)
		}
	}
	for _, p := range readManifest(t, root).Require {
		if strings.HasPrefix(p.Path, proofModule) {
			t.Fatalf("root requires proof module: %+v", p)
		}
	}
	for _, args := range [][]string{{"list", "./..."}, {"list", "-deps", "./cmd/host", "./cmd/demo-host", "./cmd/demo-client", "./cmd/session-fixture"}} {
		for _, path := range strings.Fields(goOutput(t, root, args...)) {
			if path == parentModule+"/internal/squadproof" || path == proofModule || strings.HasPrefix(path, proofModule+"/") {
				t.Fatalf("root reaches non-shipping proof: %s", path)
			}
		}
	}
}
