package sessionfixture

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Init must refuse changed frozen bytes instead of silently accepting a new recovery identity.
func TestInitFrozenInstructionsAndTools(t *testing.T) {
	dir := privateTempDir(t)
	var out bytes.Buffer
	if err := runCLI(t.Context(), []string{"init", "--data", dir}, &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "instructions.txt"))
	if err != nil || string(raw) != frozenInstructions {
		t.Fatalf("instructions: %q %v", raw, err)
	}
	raw, err = os.ReadFile(filepath.Join(dir, "tools.json"))
	if err != nil || !bytes.Contains(raw, []byte(`"durable_dedup":true`)) || !bytes.Contains(raw, []byte(`/run/reference/publish.sock`)) {
		t.Fatalf("route: %s %v", raw, err)
	}
	if err = runCLI(t.Context(), []string{"init", "--data", dir}, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "instructions.txt"), []byte("changed"), 0600)
	if err = runCLI(t.Context(), []string{"init", "--data", dir}, io.Discard, io.Discard); err == nil {
		t.Fatal("frozen instructions overwritten")
	}
}

// The fake must meter exactly accepted requests, persist them across handlers, and never accept credentials.
func TestFakeFrozenDraftAndDurableMeter(t *testing.T) {
	ledger := filepath.Join(privateTempDir(t), "fake-calls.jsonl")
	for i, variant := range []string{"A", "B"} {
		handler, err := newFakeHandler(ledger)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(map[string]any{"model": modelID, "messages": []map[string]string{{"role": "system", "content": frozenInstructions}, {"role": "user", "content": "REFERENCE fictional proposal, variant " + variant}}})
		req := httptest.NewRequest("POST", "http://127.0.0.1/v1/chat/completions", bytes.NewReader(body))
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, req)
		if out.Code != 200 {
			t.Fatalf("fake: %d %s", out.Code, out.Body.String())
		}
		var response struct {
			Choices []struct{ Message struct{ Content string } }
		}
		json.Unmarshal(out.Body.Bytes(), &response)
		want := draftA
		if i == 1 {
			want = draftB
		}
		if len(response.Choices) != 1 || response.Choices[0].Message.Content != want {
			t.Fatalf("draft: %s", out.Body.String())
		}
	}
	n, err := meterCount(ledger)
	if err != nil || n != 2 {
		t.Fatalf("meter: %d %v", n, err)
	}
}
func TestFakeRejectsBoundaryErrorsWithoutMetering(t *testing.T) {
	ledger := filepath.Join(privateTempDir(t), "fake-calls.jsonl")
	handler, err := newFakeHandler(ledger)
	if err != nil {
		t.Fatal(err)
	}
	valid := `{"model":"gpt-6-luna-2026-09-22","messages":[{"role":"system","content":` + string(mustJSON(t, frozenInstructions)) + `},{"role":"user","content":"REFERENCE fictional proposal, variant A"}]}`
	for _, tc := range []struct{ method, path, body, header string }{
		{"GET", "/v1/chat/completions", valid, ""}, {"POST", "/other", valid, ""}, {"POST", "/v1/chat/completions?key=x", valid, ""},
		{"POST", "/v1/chat/completions", valid, "Authorization"}, {"POST", "/v1/chat/completions", valid, "api-key"}, {"POST", "/v1/chat/completions", valid, "X-Api-Key"},
		{"POST", "/v1/chat/completions", `{`, ""}, {"POST", "/v1/chat/completions", strings.Repeat("x", 131073), ""},
		{"POST", "/v1/chat/completions", strings.Replace(valid, "variant A", "variant C", 1), ""},
		{"POST", "/v1/chat/completions", strings.Replace(valid, `"model":`, `"model":"wrong","model":`, 1), ""},
	} {
		req := httptest.NewRequest(tc.method, "http://127.0.0.1"+tc.path, strings.NewReader(tc.body))
		if tc.header != "" {
			req.Header.Set(tc.header, "never-send")
		}
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, req)
		if out.Code < 400 {
			t.Fatalf("accepted: %#v %s", tc, out.Body.String())
		}
	}
	n, err := meterCount(ledger)
	if err != nil || n != 0 {
		t.Fatalf("rejected request spent: %d %v", n, err)
	}
	_ = http.MethodPost
}
func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
