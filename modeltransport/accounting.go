package modeltransport

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
)

// Reasoning tokens are a subset of completion tokens, not an extra billable
// category. Missing details remain NULL; known input/output counts are required
// for success and are compared against the reservation independently.
type tokenUsage struct {
	Input     *int64 `json:"prompt_tokens"`
	Output    *int64 `json:"completion_tokens"`
	Reasoning *int64 `json:"-"`
}

func responseUsage(data []byte) (tokenUsage, error) {
	var wire struct {
		Choices []struct {
			FinishReason *string `json:"finish_reason"`
		} `json:"choices"`
		Usage *struct {
			Input   *int64 `json:"prompt_tokens"`
			Output  *int64 `json:"completion_tokens"`
			Details *struct {
				Reasoning *int64 `json:"reasoning_tokens"`
			} `json:"completion_tokens_details"`
		} `json:"usage"`
	}
	// Refuse duplicate fields without treating provider nulls as schema errors.
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := uniqueResponseValue(d, false); err != nil {
		return tokenUsage{}, errors.New("modeltransport: invalid response JSON")
	}
	if _, err := d.Token(); err != io.EOF {
		return tokenUsage{}, errors.New("modeltransport: trailing response JSON")
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return tokenUsage{}, errors.New("modeltransport: invalid response usage")
	}
	var u tokenUsage
	if wire.Usage != nil {
		u.Input, u.Output = wire.Usage.Input, wire.Usage.Output
		if wire.Usage.Details != nil {
			u.Reasoning = wire.Usage.Details.Reasoning
		}
	}
	for _, choice := range wire.Choices {
		if choice.FinishReason != nil && *choice.FinishReason != "stop" {
			return u, errors.New("modeltransport: non-success generation finish")
		}
	}
	return u, nil
}

// Match the adapter's typed completion fields before recording success. Usage
// frames may have no choices, while a plain Chat response must have a choice.
// Keep this separate from usage decoding so malformed text never erases known
// provider counts or earns a succeeded ledger row before the adapter rejects it.
func validCompletion(data []byte, stream bool) bool {
	var response struct {
		Choices []struct {
			Message struct {
				Content   string `json:"content"`
				Reasoning string `json:"reasoning_content"`
			} `json:"message"`
			Delta struct {
				Content   string `json:"content"`
				Reasoning string `json:"reasoning_content"`
			} `json:"delta"`
		} `json:"choices"`
	}
	return json.Unmarshal(data, &response) == nil && (stream || len(response.Choices) > 0)
}

func uniqueResponseValue(d *json.Decoder, foldKeys bool) error {
	tok, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			k, e := d.Token()
			if e != nil {
				return e
			}
			key, ok := k.(string)
			if foldKeys {
				key = foldResponseKey(key)
			}
			if !ok || seen[key] {
				return errors.New("duplicate response member")
			}
			seen[key] = true
			if e = uniqueResponseValue(d, foldKeys); e != nil {
				return e
			}
		}
	case '[':
		for d.More() {
			if err = uniqueResponseValue(d, foldKeys); err != nil {
				return err
			}
		}
	default:
		return errors.New("bad JSON delimiter")
	}
	_, err = d.Token()
	return err
}
func (u tokenUsage) valid(inputLimit int) bool {
	return u.Input != nil && u.Output != nil && *u.Input >= 0 && *u.Input <= int64(inputLimit) && *u.Output >= 0 && *u.Output <= maxOutputTokens && (u.Reasoning == nil || (*u.Reasoning >= 0 && *u.Reasoning <= *u.Output))
}

// accountingBody observes, but does not delay, the streaming bytes consumed by
// the adapter. Closing before a complete plain document / SSE [DONE] is unknown.
// Its context callback closes abandoned bodies and durably stops the run.
type accountingBody struct {
	body       io.ReadCloser
	ctx        context.Context
	cancel     context.CancelFunc
	policy     *Policy
	id         int64
	stream     bool
	structured *structuredCompletion
	mu         sync.Mutex
	buffer     []byte
	total      int
	usage      tokenUsage
	sawUsage   bool
	complete   bool
	doneLine   bool
	final      bool
	result     error
	stop       func() bool
	closeOnce  sync.Once
	closeErr   error
}

func newAccountingBody(body io.ReadCloser, ctx context.Context, cancel context.CancelFunc, p *Policy, id int64, stream, structured bool) *accountingBody {
	if stream {
		body = &eventBody{ReadCloser: body, reader: bufio.NewReader(body)}
	}
	b := &accountingBody{body: body, ctx: ctx, cancel: cancel, policy: p, id: id, stream: stream}
	if structured {
		b.structured = &structuredCompletion{}
	}
	b.stop = context.AfterFunc(ctx, func() {
		// Finalize before closing network resources; callers observing cancellation
		// must never race a subsequent reservation past an unrecorded error.
		b.mu.Lock()
		b.finishLocked(false)
		b.mu.Unlock()
		b.closeNetwork()
	})
	return b
}
func (b *accountingBody) closeNetwork() { b.closeOnce.Do(func() { b.closeErr = b.body.Close() }) }
func (b *accountingBody) finishLocked(success bool) {
	if b.final {
		return
	}
	b.final = true
	outcome := "unknown"
	if success && b.usage.valid(b.policy.InputLimit()) && b.ctx.Err() == nil {
		outcome = "succeeded"
	} else {
		b.result = safeError(b.ctx, "modeltransport: response usage or completion unknown")
	}
	if err := b.policy.change(b.id, outcome, b.usage); err != nil {
		b.result = err
	}
}
func (b *accountingBody) Read(dst []byte) (int, error) {
	b.mu.Lock()
	if b.final {
		err := b.result
		b.mu.Unlock()
		if err != nil {
			return 0, err
		}
		return 0, io.EOF
	}
	b.mu.Unlock()
	n, err := b.body.Read(dst)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.final && b.result != nil {
		return 0, b.result
	}
	b.total += n
	if b.total > maxResponseBytes {
		b.finishLocked(false)
		b.cancel()
		return 0, b.result
	}
	if !b.final {
		b.buffer = append(b.buffer, dst[:n]...)
		if b.stream {
			if parseErr := b.consumeEvents(); parseErr != nil {
				b.finishLocked(false)
				b.cancel()
				return 0, b.result
			}
			if b.complete {
				b.finishLocked(true)
			}
		}
	}
	if err != nil {
		if err == io.EOF {
			if !b.stream {
				u, e := responseUsage(b.buffer)
				b.usage = u
				if e == nil && b.structured != nil {
					e = b.structured.observe(b.buffer, false)
				}
				b.finishLocked(e == nil && validCompletion(b.buffer, false))
			} else {
				b.finishLocked(b.complete)
			}
		} else {
			b.finishLocked(false)
		}
		b.cancel()
	}
	if b.result != nil {
		return 0, b.result
	}
	return n, err
}
func (b *accountingBody) consumeEvents() error {
	// SSE permits CRLF. Normalize only complete lines, retaining an incomplete
	// trailing line across reads. Blank-line-delimited events may contain comments.
	for {
		end := bytes.IndexByte(b.buffer, '\n')
		if end < 0 {
			return nil
		}
		line := bytes.TrimSuffix(b.buffer[:end], []byte{'\r'})
		// Chat events are single data lines. Refuse multi-line JSON rather than
		// guessing concatenation semantics; this is intentionally a closed subset.
		if bytes.HasPrefix(line, []byte("data:")) {
			payload := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
			if bytes.Equal(payload, []byte("[DONE]")) {
				if b.doneLine {
					return errors.New("duplicate DONE")
				}
				if b.structured != nil && !b.structured.complete() {
					return errors.New("incomplete structured stream")
				}
				b.doneLine = true
			} else {
				if b.doneLine {
					return errors.New("data after DONE")
				}
				u, err := responseUsage(payload)
				if err == nil && !validCompletion(payload, true) {
					err = errors.New("invalid streamed completion")
				}
				if u.Input != nil || u.Output != nil || u.Reasoning != nil {
					if b.sawUsage {
						return errors.New("duplicate usage")
					}
					b.sawUsage = true
					b.usage = u
				}
				if err == nil && b.structured != nil {
					err = b.structured.observe(payload, true)
				}
				if err != nil {
					return err
				}
			}
		} else if len(line) == 0 {
			if b.doneLine {
				b.complete = true
			}
		} else if len(line) > 0 && !bytes.HasPrefix(line, []byte(":")) {
			return errors.New("unsupported SSE field")
		}
		b.buffer = b.buffer[end+1:]
	}
}
func (b *accountingBody) Close() error {
	b.mu.Lock()
	b.finishLocked(b.complete)
	result := b.result
	b.mu.Unlock()
	if b.stop != nil {
		b.stop()
	}
	b.closeNetwork()
	b.cancel()
	if result != nil {
		return result
	}
	if b.closeErr != nil {
		return safeError(b.ctx, "modeltransport: response close failed")
	}
	return nil
}
