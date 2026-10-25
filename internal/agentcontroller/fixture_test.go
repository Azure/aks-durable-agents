package agentcontroller

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Azure/aks-durable-agents/internal/agentpackage"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func fixtureJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
func fixtureDigest(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

// Hand-built Suite graph: member paths deliberately do not follow a filename convention.
func retainedFixture(t *testing.T, change func(map[string]any, map[string]any)) *agentpackage.Package {
	t.Helper()
	return retainedFixtureInstructions(t, []byte("Write fictional release notes.\n"), change)
}
func retainedFixtureInstructions(t *testing.T, instructions []byte, change func(map[string]any, map[string]any)) *agentpackage.Package {
	t.Helper()
	const manifestType = "application/vnd.oci.image.manifest.v1+json"
	const agentType = "application/vnd.agentsuite.agent.v1+json"
	desc := func(media string, b []byte) map[string]any {
		return map[string]any{"mediaType": media, "digest": fixtureDigest(b), "size": len(b)}
	}
	files := map[string][]byte{"prompts/frozen.md": instructions}
	agent := map[string]any{"schemaVersion": "1.0.0-draft", "mediaType": agentType, "id": "writer", "instructions": map[string]any{"path": "prompts/frozen.md", "descriptor": desc("text/markdown; charset=utf-8", files["prompts/frozen.md"])}, "model": map[string]any{"protocol": "openai-compatible", "model": "author-model-not-host-model"}}
	platform := map[string]any{"os": "linux", "architecture": "amd64"}
	image := map[string]any{"platform": platform, "imageRef": "registry.example/harness@sha256:" + strings.Repeat("a", 64), "image": map[string]any{"mediaType": manifestType, "digest": "sha256:" + strings.Repeat("a", 64), "size": 1}}
	files["catalog.json"] = fixtureJSON(map[string]any{"schemaVersion": "1.0.0-draft", "mediaType": "application/vnd.agentsuite.tool.provider.catalog.v1+json", "toolProviders": []any{}})
	files["build.json"] = fixtureJSON(map[string]any{"schemaVersion": "1.0.0-draft", "mediaType": "application/vnd.agentsuite.build.profile.v1+json", "id": "default", "sourceEpoch": 1, "runtimeBase": []any{image}, "harness": []any{image}})
	files["composition.json"] = fixtureJSON(map[string]any{"schemaVersion": "1.0.0-draft", "mediaType": "application/vnd.agentsuite.composition.v1+json", "agent": "writer", "platform": platform, "buildProfile": "default", "toolProviders": []any{}})
	ref := func(id, path, media string) map[string]any {
		return map[string]any{"id": id, "path": path, "descriptor": desc(media, files[path])}
	}
	suite := map[string]any{"schemaVersion": "1.0.0-draft", "mediaType": "application/vnd.agentsuite.manifest.v1+json", "name": "handmade", "toolProviderCatalog": ref("catalog", "catalog.json", "application/vnd.agentsuite.tool.provider.catalog.v1+json"), "buildProfiles": []any{ref("default", "build.json", "application/vnd.agentsuite.build.profile.v1+json")}, "compositions": []any{map[string]any{"agent": "writer", "platform": platform, "path": "composition.json", "descriptor": desc("application/vnd.agentsuite.composition.v1+json", files["composition.json"])}}}
	if change != nil {
		change(suite, agent)
	}
	files["members/not-the-id.json"] = fixtureJSON(agent)
	suite["agents"] = []any{ref("writer", "members/not-the-id.json", agentType)}
	if _, hasInvokes := agent["invokes"]; hasInvokes {
		var worker map[string]any
		if err := json.Unmarshal(fixtureJSON(agent), &worker); err != nil {
			t.Fatal(err)
		}
		worker["id"] = "worker"
		delete(worker, "invokes")
		files["worker.json"] = fixtureJSON(worker)
		suite["agents"] = append(suite["agents"].([]any), ref("worker", "worker.json", agentType))
		files["worker-composition.json"] = fixtureJSON(map[string]any{"schemaVersion": "1.0.0-draft", "mediaType": "application/vnd.agentsuite.composition.v1+json", "agent": "worker", "platform": platform, "buildProfile": "default", "toolProviders": []any{}})
		suite["compositions"] = append(suite["compositions"].([]any), map[string]any{"agent": "worker", "platform": platform, "path": "worker-composition.json", "descriptor": desc("application/vnd.agentsuite.composition.v1+json", files["worker-composition.json"])})
	}
	files["agentsuite.json"] = fixtureJSON(suite)
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	tw := tar.NewWriter(gz)
	for name, b := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(b)), Format: tar.FormatUSTAR}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	config, layer := []byte("{}"), compressed.Bytes()
	manifest := fixtureJSON(map[string]any{"schemaVersion": 2, "mediaType": manifestType, "artifactType": "application/vnd.agentsuite.suite.v1", "config": desc("application/vnd.oci.empty.v1+json", config), "layers": []any{desc("application/vnd.agentsuite.content.v1.tar+gzip", layer)}})
	p, err := agentpackage.Verify(context.Background(), fixtureDigest(manifest), manifest, config, layer)
	if err != nil {
		t.Fatalf("invalid hand-built fixture: %v", err)
	}
	return p
}

func retainedConfig(t *testing.T) Config {
	t.Helper()
	puller, err := agentpackage.New(agentpackage.Policy{Repositories: []string{"registry.example/suite"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return Config{Namespace: "test", Directory: filepath.Join(t.TempDir(), "state"), Model: "operator-model", Binding: []byte(`{"endpoint":"https://operator.example","policy":{"maxAttempts":3},"runnerABI":"ada-agent-chat-v1"}`), Puller: puller}
}
func fixtureAgent(p *agentpackage.Package) Agent {
	return Agent{ObjectMeta: metav1.ObjectMeta{Namespace: "test", Name: "writer", UID: types.UID("uid-one"), Generation: 1}, Spec: Spec{Package: PackageReference{Reference: "registry.example/suite@" + p.Digest()}, Member: "writer", ModelBindingRef: BindingReference{Name: "default"}}}
}
func openFixture(t *testing.T, c Config) *retained {
	t.Helper()
	r, err := openRetained(c, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.close)
	return r
}
