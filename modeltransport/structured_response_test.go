package modeltransport

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

// A syntactically valid change envelope is not evidence of a successful finish.
// Checking only content JSON, or allowing refusal-with-stop, breaks these tests.
func TestStructuredResponseOutcomes(t *testing.T) {
	for _, stream := range []bool{false, true} {
		for _, tc := range []struct {
			name, content, finish, refusal string
			ok                             bool
		}{
			{"success", fmt.Sprintf("%q", structuredOutput), `"stop"`, "null", true},
			{"truncated-valid-envelope", fmt.Sprintf("%q", structuredOutput), `"length"`, "null", false},
			{"filtered", fmt.Sprintf("%q", structuredOutput), `"content_filter"`, "null", false},
			{"missing-finish", fmt.Sprintf("%q", structuredOutput), "null", "null", false},
			{"refusal-with-stop", fmt.Sprintf("%q", structuredOutput), `"stop"`, `"provider-private-refusal"`, false},
			{"null-content", "null", `"stop"`, "null", false},
			{"empty-content", `""`, `"stop"`, "null", false},
		} {
			t.Run(fmt.Sprintf("%t/%s", stream, tc.name), func(t *testing.T) {
				p, _, ledger := openTestPolicy(t)
				var sends atomic.Int32
				body := fmt.Sprintf(`{"choices":[{"index":0,"message":{"role":"assistant","content":%s,"refusal":%s},"finish_reason":%s}],"usage":{"prompt_tokens":12,"completion_tokens":4}}`, tc.content, tc.refusal, tc.finish)
				if stream {
					body = "data: " + strings.Replace(body, `"message":`, `"delta":`, 1) + "\n\ndata: [DONE]\n\n"
				}
				c, target := boundedFixture(t, p, func(w http.ResponseWriter, r *http.Request) { sends.Add(1); io.WriteString(w, body) }, goodCredential())
				err := boundedSend(c, target, structuredChat("first", testFormat, stream))
				if tc.ok != (err == nil) {
					t.Fatalf("completion accepted=%t, error=%v", tc.ok, err)
				}
				n, outcome, in, out, _ := ledgerRows(t, ledger)
				want := "unknown"
				if tc.ok {
					want = "succeeded"
				}
				if n != 1 || outcome != want || !in.Valid || in.Int64 != 12 || !out.Valid || out.Int64 != 4 {
					t.Fatalf("outcome/known usage: %d %s %v %v", n, outcome, in, out)
				}
				if !tc.ok {
					if strings.Contains(err.Error(), "provider-private") {
						t.Fatal("provider refusal leaked")
					}
					if err = boundedSend(c, target, structuredChat("second", testFormat, stream)); err == nil {
						t.Fatal("dispatch after incomplete/refused output")
					}
					if sends.Load() != 1 {
						t.Fatalf("retried: %d", sends.Load())
					}
				}
			})
		}
	}
}

func TestStructuredResponseRejectsAmbiguousMetadata(t *testing.T) {
	text := fmt.Sprintf("%q", structuredOutput)
	for _, stream := range []bool{false, true} {
		for _, tc := range []struct{ name, choice string }{
			{"finish-alias", `"finish_reason":"length","FINISH_REASON":"stop","message":{"content":` + text + `}`},
			{"unicode-finish-alias", `"finish_reason":"length","FINIſH_REASON":"stop","message":{"content":` + text + `}`},
			{"finish-alias-reversed", `"FINISH_REASON":"stop","finish_reason":"length","message":{"content":` + text + `}`},
			{"finish-duplicate", `"finish_reason":"length","finish_reason":"stop","message":{"content":` + text + `}`},
			{"refusal-alias", `"finish_reason":"stop","message":{"content":` + text + `,"refusal":"provider-private","REFUSAL":null}`},
			{"refusal-alias-reversed", `"finish_reason":"stop","message":{"content":` + text + `,"REFUSAL":null,"refusal":"provider-private"}`},
			{"refusal-duplicate", `"finish_reason":"stop","message":{"content":` + text + `,"refusal":"provider-private","refusal":null}`},
			{"content-alias", `"finish_reason":"stop","message":{"content":null,"CONTENT":` + text + `}`},
			{"content-alias-reversed", `"finish_reason":"stop","message":{"CONTENT":` + text + `,"content":null}`},
			{"content-duplicate", `"finish_reason":"stop","message":{"content":null,"content":` + text + `}`},
		} {
			t.Run(fmt.Sprintf("%t/%s", stream, tc.name), func(t *testing.T) {
				body := `{"choices":[{` + tc.choice + `}],"usage":{"prompt_tokens":12,"completion_tokens":4}}`
				if stream {
					body = "data: " + strings.Replace(body, `"message":`, `"delta":`, 1) + "\n\ndata: [DONE]\n\n"
				}
				p, _, ledger := openTestPolicy(t)
				var calls atomic.Int32
				c, target := boundedFixture(t, p, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); io.WriteString(w, body) }, goodCredential())
				err := boundedSend(c, target, structuredChat("first", testFormat, stream))
				if err == nil {
					t.Fatal("ambiguous completion metadata accepted")
				}
				if strings.Contains(err.Error(), "provider-private") {
					t.Fatal("provider payload leaked")
				}
				n, outcome, _, _, _ := ledgerRows(t, ledger)
				if n != 1 || outcome != "unknown" {
					t.Fatalf("ambiguous outcome %d %s", n, outcome)
				}
				if boundedSend(c, target, structuredChat("second", testFormat, stream)) == nil || calls.Load() != 1 {
					t.Fatal("ambiguous completion retried")
				}
			})
		}
	}
}

func TestStructuredResponseUnicodeText(t *testing.T) {
	for _, stream := range []bool{false, true} {
		for _, tc := range []struct {
			name, escape string
			ok           bool
		}{
			{"lone-high", `\ud800`, false},
			{"lone-low", `\udfff`, false},
			{"high-then-text", `\ud800text`, false},
			{"reversed", `\udfff\ud800`, false},
			{"pair", `\uD83D\uDE80`, true},
			{"backslashes", `\\\\ud800`, true},
			{"replacement-escape", `\ufffd`, true},
			{"replacement-rune", "�", true},
		} {
			t.Run(fmt.Sprintf("%t/%s", stream, tc.name), func(t *testing.T) {
				p, _, ledger := openTestPolicy(t)
				content := strings.Replace(fmt.Sprintf("%q", structuredOutput), "Upgrade advice", tc.escape, 1)
				body := fmt.Sprintf(`{"choices":[{"finish_reason":"stop","message":{"content":%s}}],"usage":{"prompt_tokens":12,"completion_tokens":4}}`, content)
				if stream {
					body = "data: " + strings.Replace(body, `"message":`, `"delta":`, 1) + "\n\ndata: [DONE]\n\n"
				}
				var sends atomic.Int32
				c, target := boundedFixture(t, p, func(w http.ResponseWriter, r *http.Request) { sends.Add(1); io.WriteString(w, body) }, goodCredential())
				err := boundedSend(c, target, structuredChat("first", testFormat, stream))
				if tc.ok != (err == nil) {
					t.Fatalf("Unicode completion accepted=%t error=%v", tc.ok, err)
				}
				n, outcome, in, out, _ := ledgerRows(t, ledger)
				if n != 1 || (outcome == "succeeded") != tc.ok || !in.Valid || in.Int64 != 12 || !out.Valid || out.Int64 != 4 {
					t.Fatalf("Unicode outcome/counts %d %s %v %v", n, outcome, in, out)
				}
				if !tc.ok && (boundedSend(c, target, structuredChat("second", testFormat, stream)) == nil || sends.Load() != 1) {
					t.Fatal("Unicode failure retried")
				}
			})
		}
	}
}

func TestStructuredResponseExtensionNumbers(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprint(stream), func(t *testing.T) {
			p, _, _ := openTestPolicy(t)
			body := strings.TrimSuffix(structuredSuccess(), "}") + `,"extension":{"integer":9007199254740993,"exponent":1e400}}`
			if stream {
				body = "data: " + strings.Replace(body, `"message":`, `"delta":`, 1) + "\n\ndata: [DONE]\n\n"
			}
			c, target := boundedFixture(t, p, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body) }, goodCredential())
			if err := boundedSend(c, target, structuredChat("first", testFormat, stream)); err != nil {
				t.Fatalf("opaque provider numbers rejected: %v", err)
			}
		})
	}
}

func TestStructuredResponseStreamBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, frames string
		ok           bool
	}{
		{"normal", "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\",\"content\":null}}]}\n\ndata: {\"choices\":[{\"delta\":{\"content\":\"{}\"}}]}\n\ndata: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n", true},
		{"no-stop", "data: {\"choices\":[{\"delta\":{\"content\":\"{}\"}}]}\n\n", false},
		{"late-content", "data: {\"choices\":[{\"delta\":{\"content\":\"{}\"},\"finish_reason\":\"stop\"}]}\n\ndata: {\"choices\":[{\"delta\":{\"content\":\"late\"}}]}\n\n", false},
		{"partial-refusal", "data: {\"choices\":[{\"delta\":{\"content\":\"{\"}}]}\n\ndata: {\"choices\":[{\"delta\":{\"refusal\":\"private\"},\"finish_reason\":\"stop\"}]}\n\n", false},
		{"usage-only", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _, ledger := openTestPolicy(t)
			body := tc.frames + "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":12,\"completion_tokens\":4}}\n\ndata: [DONE]\n\n"
			c, target := boundedFixture(t, p, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body) }, goodCredential())
			err := boundedSend(c, target, structuredChat("first", testFormat, true))
			if tc.ok != (err == nil) {
				t.Fatalf("SSE completed=%t error=%v", tc.ok, err)
			}
			_, outcome, _, _, _ := ledgerRows(t, ledger)
			if (outcome == "succeeded") != tc.ok {
				t.Fatalf("outcome=%s", outcome)
			}
		})
	}
}
