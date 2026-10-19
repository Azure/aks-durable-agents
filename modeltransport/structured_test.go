package modeltransport

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

const testFormat = `{"type":"json_schema","json_schema":{"name":"document_changes","strict":true,"schema":{"type":"object","additionalProperties":false,"required":["changes"],"properties":{"changes":{"type":"array","minItems":1,"maxItems":32,"items":{"type":"object","additionalProperties":false,"required":["document","operation","content"],"properties":{"document":{"type":"string","maxLength":63},"operation":{"type":"string","enum":["replace"]},"content":{"type":"string","maxLength":65536}}}}}}}}`
const structuredOutput = `{"changes":[{"document":"notes","operation":"replace","content":"Upgrade advice"}]}`

func structuredChat(text, format string, stream bool) string {
	body := map[string]any{"model": "test-deployment", "messages": []map[string]string{{"role": "user", "content": text}}, "stream": stream, "response_format": json.RawMessage(format)}
	b, _ := json.Marshal(body)
	return string(b)
}

func structuredSuccess() string {
	return fmt.Sprintf(`{"choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":%q,"refusal":null}}],"usage":{"prompt_tokens":750,"completion_tokens":120,"completion_tokens_details":{"reasoning_tokens":40}}}`, structuredOutput)
}

// Counting only messages, or dropping the schema before forwarding, breaks this boundary.
func TestStructuredRequestSchemaAccounting(t *testing.T) {
	var canonical any
	if err := json.Unmarshal([]byte(testFormat), &canonical); err != nil {
		t.Fatal(err)
	}
	formatBytes, _ := json.Marshal(canonical)
	limit := 8192 - 256 - 64 - len("user") - len(formatBytes)
	for _, delta := range []int{0, 1} {
		t.Run(fmt.Sprint(delta), func(t *testing.T) {
			p, _, ledger := openTestPolicy(t)
			var sends, creds atomic.Int32
			c, target := boundedFixture(t, p, func(w http.ResponseWriter, r *http.Request) {
				sends.Add(1)
				var body map[string]json.RawMessage
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				var gotFormat any
				json.Unmarshal(body["response_format"], &gotFormat)
				if !reflect.DeepEqual(gotFormat, canonical) || string(body["max_completion_tokens"]) != "4096" {
					t.Errorf("schema/cap not preserved: %s", body)
				}
				io.WriteString(w, structuredSuccess())
			}, func(ctx context.Context, o policy.TokenRequestOptions) (azcore.AccessToken, error) {
				creds.Add(1)
				return goodCredential()(ctx, o)
			})
			err := boundedSend(c, target, structuredChat(strings.Repeat("x", limit+delta), testFormat, false))
			if delta == 0 {
				if err != nil || sends.Load() != 1 {
					t.Fatalf("bounded schema request refused: %v sends%d", err, sends.Load())
				}
			} else {
				n, _, _, _, _ := ledgerRows(t, ledger)
				if err == nil || !strings.Contains(err.Error(), "full context exceeds input bound") || sends.Load() != 0 || creds.Load() != 0 || n != 0 {
					t.Fatalf("schema exceeded context before I/O: %v sends%d creds%d rows%d", err, sends.Load(), creds.Load(), n)
				}
			}
		})
	}
}

func TestStructuredRequestRefusesInvalidFormat(t *testing.T) {
	for _, format := range []string{
		`{"type":"json_object"}`,
		strings.Replace(testFormat, `"strict":true`, `"strict":false`, 1),
		strings.Replace(testFormat, `"strict":true,`, ``, 1),
		strings.Replace(testFormat, `"name":"document_changes"`, `"name":"private/value"`, 1),
		strings.Replace(testFormat, `"type":"json_schema"`, `"type":"json_schema","unknown":true`, 1),
		`{"type":"json_schema","json_schema":{"name":"x","strict":true,"schema":{}}}`,
		strings.Replace(testFormat, `"name":"document_changes"`, `"name":"`+strings.Repeat("x", 16384)+`"`, 1),
	} {
		t.Run(fmt.Sprint(len(format), "-", strings.Contains(format, "false")), func(t *testing.T) {
			p, _, ledger := openTestPolicy(t)
			var sends, creds atomic.Int32
			c, target := boundedFixture(t, p, func(http.ResponseWriter, *http.Request) { sends.Add(1) }, func(ctx context.Context, o policy.TokenRequestOptions) (azcore.AccessToken, error) {
				creds.Add(1)
				return goodCredential()(ctx, o)
			})
			err := boundedSend(c, target, structuredChat("x", format, false))
			n, _, _, _, _ := ledgerRows(t, ledger)
			if err == nil || sends.Load() != 0 || creds.Load() != 0 || n != 0 {
				t.Fatalf("invalid schema reached I/O: %v sends%d creds%d rows%d", err, sends.Load(), creds.Load(), n)
			}
		})
	}
}

func TestStructuredRequestPreservesSchemaNumbers(t *testing.T) {
	for _, number := range []string{"9007199254740993", "1e400"} {
		t.Run(number, func(t *testing.T) {
			p, _, _ := openTestPolicy(t)
			format := fmt.Sprintf(`{"type":"json_schema","json_schema":{"name":"numeric","strict":true,"schema":{"type":"object","additionalProperties":false,"required":["id"],"properties":{"id":{"type":"number","enum":[%s]}}}}}`, number)
			c, target := boundedFixture(t, p, func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
				}
				if !strings.Contains(string(body), number) {
					t.Errorf("schema number changed on wire: %s", body)
				}
				io.WriteString(w, structuredSuccess())
			}, goodCredential())
			if err := boundedSend(c, target, structuredChat("x", format, false)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestStructuredRequestSchemaChangesFingerprint(t *testing.T) {
	p, _, ledger := openTestPolicy(t)
	var sends atomic.Int32
	c, target := boundedFixture(t, p, func(w http.ResponseWriter, r *http.Request) { sends.Add(1); io.WriteString(w, structuredSuccess()) }, goodCredential())
	for _, format := range []string{testFormat, strings.Replace(testFormat, "document_changes", "document_review", 1)} {
		if err := boundedSend(c, target, structuredChat("same message", format, false)); err != nil {
			t.Fatal(err)
		}
	}
	n, outcome, _, _, _ := ledgerRows(t, ledger)
	if n != 2 || sends.Load() != 2 || outcome != "succeeded" {
		t.Fatalf("schema excluded from fingerprint: rows%d sends%d %s", n, sends.Load(), outcome)
	}
}
