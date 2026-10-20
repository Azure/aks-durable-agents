package sessionfixture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestV2InitializerRecordsRuntimeSocketAcrossMountNamespaces(t *testing.T) {
	data := privateTempDir(t)
	if err := initDataScenario(data, "/data/publish.sock", "v2"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(data, "tools.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"socket":"/data/publish.sock"`) {
		t.Fatalf("wrong runtime socket: %s", raw)
	}
	if err := initDataScenario(privateTempDir(t), "/arbitrary/publish.sock", "v2"); err == nil {
		t.Fatal("arbitrary remote socket path admitted")
	}
}
