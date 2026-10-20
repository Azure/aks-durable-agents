package sessionfixture

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"syscall"
)

const frozenInstructions = "REFERENCE FICTIONAL LOCAL PROTOTYPE. Produce release notes for the fictional Northwind team. Never contact an external service. The local fake supplies deterministic text.\n"

var proposalInput = regexp.MustCompile(`^REFERENCE fictional proposal, variant ([AB])(?:\. Base digest [0-9a-f]{64}\.)?$`)

type meterEntry struct {
	RequestDigest string `json:"requestDigest"`
	Provider      string `json:"provider"`
}

func newFakeHandler(ledger string) (http.Handler, error) {
	if err := privateFile(ledger); err != nil {
		return nil, err
	}
	if _, err := meterCount(ledger); err != nil {
		return nil, err
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		refuse := func(code int) { http.Error(w, "only bounded credential-free fictional completions are accepted", code) }
		if r.Method != "POST" || r.URL.RequestURI() != "/v1/chat/completions" {
			refuse(http.StatusForbidden)
			return
		}
		for _, header := range []string{"Authorization", "Proxy-Authorization", "api-key", "x-api-key", "Cookie"} {
			if len(r.Header.Values(header)) != 0 {
				refuse(http.StatusForbidden)
				return
			}
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, 131073))
		if err != nil {
			refuse(http.StatusBadRequest)
			return
		}
		if len(raw) > 131072 {
			refuse(http.StatusRequestEntityTooLarge)
			return
		}
		var req struct {
			Model         string            `json:"model"`
			Messages      []json.RawMessage `json:"messages"`
			Stream        bool              `json:"stream"`
			StreamOptions json.RawMessage   `json:"stream_options"`
		}
		if err = strictJSON(raw, []string{"model", "messages", "stream", "stream_options"}, &req); err != nil || req.Model != modelID || len(req.Messages) < 2 || len(req.Messages) > 65 || len(req.Messages)%2 != 0 {
			refuse(http.StatusBadRequest)
			return
		}
		if req.Stream {
			var options struct {
				IncludeUsage *bool `json:"include_usage"`
			}
			if strictJSON(req.StreamOptions, []string{"include_usage"}, &options) != nil || options.IncludeUsage == nil || !*options.IncludeUsage {
				refuse(http.StatusBadRequest)
				return
			}
		} else if len(req.StreamOptions) != 0 {
			refuse(http.StatusBadRequest)
			return
		}
		variant := ""
		for i, msg := range req.Messages {
			var m struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			}
			if err = strictJSON(msg, []string{"role", "content"}, &m); err != nil {
				refuse(http.StatusBadRequest)
				return
			}
			switch {
			case i == 0:
				if m.Role != "system" || m.Content != frozenInstructions {
					refuse(http.StatusBadRequest)
					return
				}
			case i%2 == 1:
				match := proposalInput.FindStringSubmatch(m.Content)
				if m.Role != "user" || match == nil {
					refuse(http.StatusBadRequest)
					return
				}
				variant = match[1]
			default:
				if m.Role != "assistant" || (m.Content != draftA && m.Content != draftB) {
					refuse(http.StatusBadRequest)
					return
				}
			}
		}
		hash := sha256.Sum256(raw)
		entry := meterEntry{RequestDigest: hex.EncodeToString(hash[:]), Provider: "deterministic-local-fake"}
		if err = appendMeter(ledger, entry); err != nil {
			refuse(http.StatusInternalServerError)
			return
		}
		draft := draftA
		if variant == "B" {
			draft = draftB
		}
		if req.Stream {
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-store")
			// A finite deterministic stream: one exact text delta, one usage-only
			// frame, then DONE. Metering was synced once before any response bytes.
			for _, frame := range []any{
				map[string]any{"model": modelID, "choices": []any{map[string]any{"index": 0, "delta": map[string]string{"role": "assistant", "content": draft}}}},
				map[string]any{"model": modelID, "choices": []any{}, "usage": map[string]int{"prompt_tokens": 1, "completion_tokens": 1}},
			} {
				payload, err := json.Marshal(frame)
				if err != nil {
					return
				}
				if _, err = io.WriteString(w, "data: "+string(payload)+"\n\n"); err != nil {
					return
				}
			}
			io.WriteString(w, "data: [DONE]\n\n")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"model": modelID, "choices": []any{map[string]any{"message": map[string]string{"role": "assistant", "content": draft}}}, "usage": map[string]int{"prompt_tokens": 1, "completion_tokens": 1}})
	}), nil
}
func appendMeter(path string, entry meterEntry) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size() > 4<<20 {
		return errors.New("meter limit reached")
	}
	raw, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	n, err := f.Write(raw)
	if err != nil {
		return err
	}
	if n != len(raw) {
		return io.ErrShortWrite
	}
	return f.Sync()
}
func meterCount(path string) (int, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return 0, err
	}
	if !info.Mode().IsRegular() || info.Size() > 4<<20 {
		return 0, errors.New("invalid meter")
	}
	scanner := bufio.NewReader(io.LimitReader(f, (4<<20)+1))
	count := 0
	for {
		line, err := scanner.ReadBytes('\n')
		if err == io.EOF && len(line) == 0 {
			return count, nil
		}
		if err != nil {
			return 0, errors.New("truncated meter")
		}
		var entry meterEntry
		if len(line) > 4096 || strictJSON(line, []string{"requestDigest", "provider"}, &entry) != nil || entry.Provider != "deterministic-local-fake" || len(entry.RequestDigest) != 64 {
			return 0, errors.New("corrupt meter")
		}
		if _, err = hex.DecodeString(entry.RequestDigest); err != nil || strings.TrimSpace(string(line)) == "" {
			return 0, errors.New("corrupt meter digest")
		}
		count++
		if count > 10000 {
			return 0, errors.New("meter call bound exceeded")
		}
	}
}
