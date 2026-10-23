//go:build squadproof

package squadproof

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const proofToken = "proof-only-not-an-azure-token"
const proofEndpoint = "https://proof-model.invalid/openai/v1/"
const fixturePackage = "squad-proof-v1:lead,member;dispatch_member,read_context,checkpoint,publish;epoch=1"

func proofDigest() string { return fmt.Sprintf("%x", sha256.Sum256([]byte(fixturePackage))) }

func (l *Ledger) attempt(ctx context.Context, kind, id string) (n int, err error) {
	err = l.transaction(ctx, func(c *sql.Conn) error {
		if err := event(ctx, c, "attempt-"+kind, id); err != nil {
			return err
		}
		return c.QueryRowContext(ctx, `SELECT count(*) FROM events WHERE kind=?`, "attempt-"+kind).Scan(&n)
	})
	return
}
func (l *Ledger) attemptCount(ctx context.Context, kind string) (int, error) {
	var n int
	err := l.db.QueryRowContext(ctx, `SELECT count(*) FROM events WHERE kind=?`, "attempt-"+kind).Scan(&n)
	return n, err
}

type fakeModel struct{ ledger *Ledger }

func modelText(raw json.RawMessage) (string, error) {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return text, nil
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &parts) != nil || len(parts) != 1 || parts[0].Type != "text" {
		return "", ErrInvalid
	}
	return parts[0].Text, nil
}
func (f *fakeModel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	n, err := f.ledger.attempt(r.Context(), "model", "provider")
	if err != nil {
		http.Error(w, "proof meter unavailable", 500)
		return
	}
	var body struct {
		Model    string          `json:"model"`
		Max      int             `json:"max_completion_tokens"`
		Legacy   json.RawMessage `json:"max_tokens"`
		Stream   bool            `json:"stream"`
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, (64<<10)+1))
	if err != nil || n > 16 || len(raw) > 64<<10 || json.Unmarshal(raw, &body) != nil || r.Method != "POST" || r.URL.Path != "/openai/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer "+proofToken || r.Header.Get("api-key") != "" || body.Model != "proof-model" || (body.Max != 0 && body.Max != 4096) || body.Legacy != nil || len(body.Messages) != 2 || body.Messages[0].Role != "system" || body.Messages[1].Role != "user" {
		http.Error(w, "invalid proof model request", 400)
		return
	}
	system, err := modelText(body.Messages[0].Content)
	if err != nil {
		http.Error(w, "invalid proof system", 400)
		return
	}
	input, err := modelText(body.Messages[1].Content)
	if err != nil {
		http.Error(w, "invalid proof input", 400)
		return
	}
	role, phase := "", ""
	for _, candidate := range []string{"lead", "member"} {
		for _, stage := range []string{"plan", "finish"} {
			if system == fmt.Sprintf("squad-proof-v1 role=%s package=%s phase=%s", candidate, proofDigest(), stage) {
				role, phase = candidate, stage
			}
		}
	}
	if role == "" {
		http.Error(w, "off-package proof role", 400)
		return
	}
	plan := fakePlan(role, phase, input)
	content, _ := json.Marshal(plan)
	usage := map[string]int{"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150}
	if body.Stream {
		w.Header().Set("Content-Type", "text/event-stream")
		delta, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"delta": map[string]string{"content": string(content)}}}})
		totals, _ := json.Marshal(map[string]any{"choices": []any{}, "usage": usage})
		fmt.Fprintf(w, "data: %s\n\ndata: %s\n\ndata: [DONE]\n\n", delta, totals)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"id": "proof-completion", "object": "chat.completion", "model": "proof-model", "choices": []any{map[string]any{"index": 0, "message": map[string]string{"role": "assistant", "content": string(content)}, "finish_reason": "stop"}}, "usage": usage})
}

func fakePlan(role, phase, input string) map[string]any {
	plan := map[string]any{"tools": []any{}, "reply": "proof " + role + " response recorded"}
	if phase == "finish" {
		return plan
	}
	tool := func(name string, args map[string]any) map[string]any {
		return map[string]any{"name": name, "arguments": args}
	}
	var request struct{ Kind, Mode, Text string }
	_ = json.Unmarshal([]byte(input), &request)
	if role == "member" {
		plan["tools"] = []any{tool("publish", map[string]any{"epoch": 1, "text": "synthetic member result"})}
	} else if request.Kind == "start" || request.Text == "start" {
		member := "member"
		if request.Mode == "wrong-member" {
			member = "other"
		}
		tools := []any{tool("dispatch_member", map[string]any{"epoch": 1, "member": member, "task": "produce a synthetic result"}), tool("checkpoint", map[string]any{"epoch": 1})}
		if strings.Contains(request.Mode, "double") {
			tools = append(tools, tool("checkpoint", map[string]any{"epoch": 1}))
		}
		plan["tools"] = tools
	}
	return plan
}
