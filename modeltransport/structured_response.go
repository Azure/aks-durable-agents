package modeltransport

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// This state observes provider outcomes before the sessions Chat adapter loses
// refusal and finish metadata. A streamed prefix is never a completed response.
type structuredCompletion struct {
	text, finished bool
}

type completionMessage struct {
	Role      string          `json:"role"`
	Content   *string         `json:"content"`
	Refusal   json.RawMessage `json:"refusal"`
	ToolCalls json.RawMessage `json:"tool_calls"`
}

func (s *structuredCompletion) observe(data []byte, stream bool) error {
	var response struct {
		Choices []struct {
			Index        int               `json:"index"`
			FinishReason *string           `json:"finish_reason"`
			Message      completionMessage `json:"message"`
			Delta        completionMessage `json:"delta"`
		} `json:"choices"`
	}
	invalid := errors.New("modeltransport: incomplete or refused structured completion")
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if !utf8.Valid(data) || !validResponseEscapes(data) || uniqueResponseValue(d, true) != nil || json.Unmarshal(data, &response) != nil {
		return invalid
	}
	if stream && len(response.Choices) == 0 {
		return nil
	} // usage-only frame
	if len(response.Choices) != 1 || response.Choices[0].Index != 0 || s.finished {
		return invalid
	}
	choice := response.Choices[0]
	message := choice.Message
	if stream {
		message = choice.Delta
	}
	if (message.Role != "" && message.Role != "assistant") || present(message.Refusal) || present(message.ToolCalls) {
		return invalid
	}
	if message.Content != nil && strings.TrimSpace(*message.Content) != "" {
		s.text = true
	}
	if choice.FinishReason != nil {
		if *choice.FinishReason != "stop" {
			return invalid
		}
		s.finished = true
	}
	if !stream && !s.complete() {
		return invalid
	}
	return nil
}

// Match encoding/json's Unicode key folding without changing request-schema keys.
func foldResponseKey(key string) string {
	return strings.Map(func(r rune) rune {
		for {
			next := unicode.SimpleFold(r)
			if next <= r {
				return next
			}
			r = next
		}
	}, key)
}

// encoding/json silently replaces unpaired UTF-16 escapes in the response
// envelope. Reject them before adapter decoding; escaped backslashes (including
// JSON text nested inside model content) remain literal data for the consumer.
func validResponseEscapes(raw []byte) bool {
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		i++
		if i == len(raw) {
			return false
		}
		if raw[i] != 'u' {
			continue
		}
		if i+4 >= len(raw) {
			return false
		}
		unit, err := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		if err != nil || unit >= 0xdc00 && unit <= 0xdfff {
			return false
		}
		i += 4
		if unit < 0xd800 || unit > 0xdbff {
			continue
		}
		if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
			return false
		}
		low, err := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
		if err != nil || low < 0xdc00 || low > 0xdfff {
			return false
		}
		i += 6
	}
	return true
}

func present(v json.RawMessage) bool           { return len(v) > 0 && !bytes.Equal(v, []byte("null")) }
func (s *structuredCompletion) complete() bool { return s.text && s.finished }
