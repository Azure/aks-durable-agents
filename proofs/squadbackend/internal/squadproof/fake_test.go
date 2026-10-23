//go:build squadproof

package squadproof

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func fakeRequest(t *testing.T, role, phase string, stream bool) *http.Request {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"model": "proof-model", "max_completion_tokens": 4096, "stream": stream, "messages": []any{
		map[string]string{"role": "system", "content": fmt.Sprintf("squad-proof-v1 role=%s package=%s phase=%s", role, proofDigest(), phase)},
		map[string]string{"role": "user", "content": `{"kind":"start","mode":"double-approval"}`},
	}})
	r := httptest.NewRequest(http.MethodPost, "https://proof-model.invalid/openai/v1/chat/completions", strings.NewReader(string(body)))
	r.Header.Set("Authorization", "Bearer "+proofToken)
	return r
}

func TestProofFakeExplicitScriptModes(t *testing.T) {
	for _, mode := range []string{"double-approval", "wrong-member"} {
		raw, err := json.Marshal(fakePlan("lead", "plan", `{"kind":"start","mode":"`+mode+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		var plan scriptedPlan
		if err = json.Unmarshal(raw, &plan); err != nil {
			t.Fatal(err)
		}
		if mode == "double-approval" {
			if len(plan.Tools) != 3 || plan.Tools[1].Name != "checkpoint" || plan.Tools[2].Name != "checkpoint" {
				t.Fatalf("missing second approval: %+v", plan)
			}
		} else if len(plan.Tools) != 2 || plan.Tools[0].Name != "dispatch_member" || plan.Tools[0].Arguments["member"] != "other" {
			t.Fatalf("wrong-member mode ineffective: %+v", plan)
		}
	}
}

func TestProofFakeStreamAndNonstream(t *testing.T) {
	for _, stream := range []bool{false, true} {
		l, _ := openTestLedger(t)
		f := &fakeModel{ledger: l}
		for _, role := range []string{"lead", "member"} {
			w := httptest.NewRecorder()
			f.ServeHTTP(w, fakeRequest(t, role, "plan", stream))
			if w.Code != 200 || !strings.Contains(w.Body.String(), "checkpoint") && role == "lead" || !strings.Contains(w.Body.String(), "publish") && role == "member" {
				t.Fatalf("model response: %d %s", w.Code, w.Body.String())
			}
			if stream && (!strings.Contains(w.Body.String(), "[DONE]") || w.Header().Get("Content-Type") != "text/event-stream") {
				t.Fatal("stream missing completion")
			}
		}
		if n, err := l.attemptCount(testContext, "model"); err != nil || n != 2 {
			t.Fatalf("durable attempts: %d %v", n, err)
		}
	}
}

func TestProofFakeAttemptCap(t *testing.T) {
	l, _ := openTestLedger(t)
	f := &fakeModel{ledger: l}
	for i := 0; i < 17; i++ {
		w := httptest.NewRecorder()
		f.ServeHTTP(w, fakeRequest(t, "lead", "finish", false))
		expected := 200
		if i == 16 {
			expected = 400
		}
		if w.Code != expected {
			t.Fatalf("request%d status%d", i, w.Code)
		}
	}
	if n, err := l.attemptCount(testContext, "model"); err != nil || n != 17 {
		t.Fatalf("attempts include refused request: %d %v", n, err)
	}
}

func TestProofFakeRejectsWrongPin(t *testing.T) {
	l, _ := openTestLedger(t)
	f := &fakeModel{ledger: l}
	for _, kind := range []string{"token", "path", "role"} {
		r := fakeRequest(t, "lead", "plan", false)
		switch kind {
		case "token":
			r.Header.Set("Authorization", "Bearer other")
		case "path":
			r.URL.Path = "/other"
		case "role":
			r = fakeRequest(t, "unknown", "plan", false)
		}
		w := httptest.NewRecorder()
		f.ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatalf("accepted%s: %d", kind, w.Code)
		}
	}
	if n, err := l.attemptCount(testContext, "model"); err != nil || n != 3 {
		t.Fatalf("rejected calls not counted: %d %v", n, err)
	}
}
