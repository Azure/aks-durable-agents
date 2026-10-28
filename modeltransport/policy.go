package modeltransport

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	maxInputTokens   = 8192
	maxOutputTokens  = 4096
	modelTimeout     = 25 * time.Second
	maxRequestBytes  = 64 * 1024
	maxResponseBytes = 4 * 1024 * 1024
)

type policySnapshot struct {
	Version          int      `json:"version"`
	PlannedCallSlots []string `json:"plannedCallSlots,omitempty"`
	MaxAttempts      *int     `json:"maxAttempts,omitempty"`
	MaxInputTokens   *int     `json:"maxInputTokens,omitempty"`
	RunID            string   `json:"runID"`
	LedgerPath       string   `json:"ledgerPath"`
	Deployment       string   `json:"deployment"`
	Pricing          pricing  `json:"pricing"`
}
type pricing struct {
	Input  int64  `json:"inputMicroUSDPerMillionTokens"`
	Output int64  `json:"outputMicroUSDPerMillionTokens"`
	Extra  *int64 `json:"extraMicroUSDPerCall"`
	Source string `json:"source"`
	AsOf   string `json:"asOf"`
}

func validatePricing(p pricing) error {
	if p.Input <= 0 || p.Output <= 0 || p.Extra == nil || *p.Extra != 0 {
		return errors.New("modeltransport: invalid policy values or pricing")
	}
	u, err := url.Parse(p.Source)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return errors.New("modeltransport: pricing requires an HTTPS source")
	}
	date, err := time.Parse("2006-01-02", p.AsOf)
	if err != nil || date.Format("2006-01-02") != p.AsOf {
		return errors.New("modeltransport: pricing requires a valid asOf date")
	}
	return nil
}

func priceReservation(p pricing, inputLimit int) *big.Int {
	input := new(big.Int).Mul(big.NewInt(p.Input), big.NewInt(int64(inputLimit)))
	output := new(big.Int).Mul(big.NewInt(p.Output), big.NewInt(maxOutputTokens))
	return new(big.Int).Add(input, output)
}

// Policy owns a private SQLite ledger for one immutable run. It may be shared by
// transports, but must remain open until all their response bodies are closed.
// A zero Policy is not usable. A nil Config.Policy preserves the legacy API.
type Policy struct {
	config policySnapshot
	run    *runSnapshot
	ledger *budgetLedger
	mu     sync.Mutex
	closed bool
}

// OpenPolicyFile validates a closed, versioned USD pricing snapshot and reserves
// the entire versioned run budget before a transport can acquire any credential.
// It does not invent rates, dates, deployment names, or extra-charge assumptions.
func OpenPolicyFile(path string) (*Policy, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("modeltransport: policy unavailable")
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 64*1024+1))
	if err != nil || len(data) > 64*1024 {
		return nil, errors.New("modeltransport: invalid policy file")
	}
	var c policySnapshot
	if err = decodeClosed(data, &c); err != nil {
		return nil, errors.New("modeltransport: invalid policy schema")
	}
	validVersion := ((c.Version == 1 && c.MaxAttempts == nil) || (c.Version == 2 && c.MaxAttempts != nil && *c.MaxAttempts == 3)) && c.PlannedCallSlots == nil
	validVersion = validVersion || (c.Version == 3 && c.MaxAttempts != nil && *c.MaxAttempts == 3 && validCallSlots(c.PlannedCallSlots))
	validInput := c.MaxInputTokens == nil || *c.MaxInputTokens == 32768
	if !validVersion || !validInput || strings.TrimSpace(c.RunID) == "" || len(c.RunID) > 256 || strings.TrimSpace(c.RunID) != c.RunID || strings.TrimSpace(c.Deployment) == "" || len(c.Deployment) > 256 || strings.TrimSpace(c.Deployment) != c.Deployment || !filepath.IsAbs(c.LedgerPath) || filepath.Clean(c.LedgerPath) != c.LedgerPath {
		return nil, errors.New("modeltransport: invalid policy values or pricing")
	}
	if err = validatePricing(c.Pricing); err != nil {
		return nil, err
	}
	limit := 2
	if c.MaxAttempts != nil {
		limit = *c.MaxAttempts
	}
	inputLimit := maxInputTokens
	if c.MaxInputTokens != nil {
		inputLimit = *c.MaxInputTokens
	}
	// Reserve every attempt at the selected input bound and 4096 output tokens.
	// Compare rational microUSD against USD2 without rounding or int64 overflow.
	reservation := new(big.Int).Mul(priceReservation(c.Pricing, inputLimit), big.NewInt(int64(limit)))
	if reservation.Cmp(big.NewInt(2000000000000)) > 0 {
		return nil, errors.New("modeltransport: full run reservation exceeds USD 2")
	}
	snapshot, _ := json.Marshal(c)
	ledger, err := openBudgetLedger(c.LedgerPath, string(snapshot), limit, inputLimit, c.PlannedCallSlots)
	if err != nil {
		return nil, err
	}
	return &Policy{config: c, ledger: ledger}, nil
}

// Snapshot returns fresh JSON bytes of the entire immutable policy.
func (p *Policy) Snapshot() []byte {
	if p.run != nil {
		data, _ := json.Marshal(p.run)
		return data
	}
	data, _ := json.Marshal(p.config)
	return data
}

// InputLimit reports the immutable input bound; omission preserves the legacy bound.
func (p *Policy) InputLimit() int {
	if p.run != nil {
		return runInputLimit(p.run.RunConfig)
	}
	if p.config.MaxInputTokens != nil {
		return *p.config.MaxInputTokens
	}
	return maxInputTokens
}

// AttemptLimit reports the immutable policy's total dispatch-attempt ceiling.
func (p *Policy) AttemptLimit() int {
	if p.run != nil {
		return len(p.run.Slots)
	}
	if p.config.MaxAttempts != nil {
		return *p.config.MaxAttempts
	}
	return 2
}

// Close closes the ledger. Closing before response completion prevents success
// accounting and is a lifecycle error; the durable dispatch row remains a stop.
func (p *Policy) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	if p.ledger == nil {
		return nil
	}
	return p.ledger.db.Close()
}

// decodeClosed rejects duplicate object members, unknown fields, nulls, invalid
// UTF-8 and trailing JSON. Null is not an explicit value in our request/config
// schemas. Provider responses use a separate decoder because null usage is valid
// evidence of unknown counts, never zero.
func decodeClosed(data []byte, dst any) error {
	if !utf8.Valid(data) {
		return errors.New("invalid UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := uniqueValue(d); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	if err := exactSchemaKeys(data, reflect.TypeOf(dst)); err != nil {
		return err
	}
	d = json.NewDecoder(bytes.NewReader(data))
	// Schemas contain arbitrary JSON numbers; never round their constraints
	// through float64 before encoding the provider request/fingerprint.
	d.UseNumber()
	d.DisallowUnknownFields()
	return d.Decode(dst)
}
func uniqueValue(d *json.Decoder) error {
	tok, err := d.Token()
	if err != nil {
		return err
	}
	if tok == nil {
		return errors.New("null value")
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			k, err := d.Token()
			if err != nil {
				return err
			}
			key, ok := k.(string)
			if !ok || seen[key] {
				return errors.New("duplicate member")
			}
			seen[key] = true
			if err = uniqueValue(d); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err = uniqueValue(d); err != nil {
				return err
			}
		}
	default:
		return errors.New("invalid delimiter")
	}
	_, err = d.Token()
	return err
}

type boundedChat struct {
	Model               string             `json:"model"`
	Messages            []textMessage      `json:"messages"`
	Stream              bool               `json:"stream,omitempty"`
	StreamOptions       *chatStreamOptions `json:"stream_options,omitempty"`
	MaxCompletionTokens *int               `json:"max_completion_tokens"`
	ResponseFormat      *responseFormat    `json:"response_format,omitempty"`
}
type textMessage struct {
	Role    string  `json:"role"`
	Content *string `json:"content"`
}
type chatStreamOptions struct {
	IncludeUsage bool `json:"include_usage"`
}

func (p *Policy) prepare(req *http.Request, slot string) ([]byte, string, bool, bool, error) {
	deployment := p.config.Deployment
	if p.run != nil {
		binding, ok := p.runBinding(slot)
		if !ok {
			return nil, "", false, false, errors.New("modeltransport: policy slot mismatch")
		}
		deployment = binding.Deployment
	}
	if req.Method != http.MethodPost || req.URL.Path != "/openai/v1/chat/completions" || req.URL.RawQuery != "" || req.URL.ForceQuery || req.Body == nil || req.Header.Get("Content-Encoding") != "" {
		return nil, "", false, false, errors.New("modeltransport: policy requires plain Chat POST")
	}
	data, err := io.ReadAll(io.LimitReader(req.Body, maxRequestBytes+1))
	if err != nil || len(data) > maxRequestBytes {
		return nil, "", false, false, errors.New("modeltransport: request too large or unreadable")
	}
	var c boundedChat
	if err = decodeClosed(data, &c); err != nil || c.Model != deployment || len(c.Messages) == 0 || (c.MaxCompletionTokens != nil && *c.MaxCompletionTokens != maxOutputTokens) {
		return nil, "", false, false, errors.New("modeltransport: unsupported Chat request")
	}
	// One token per UTF-8 byte of every role/content string and the encoded
	// response format, plus 64 per message and 256 for conversation framing.
	// Tools, multimodal content and arbitrary request fields remain unsupported.
	tokens := 256
	if c.ResponseFormat != nil {
		size, err := c.ResponseFormat.inputBytes()
		if err != nil {
			return nil, "", false, false, err
		}
		tokens += size
	}
	for _, m := range c.Messages {
		switch m.Role {
		case "system", "developer", "user", "assistant":
		default:
			return nil, "", false, false, errors.New("modeltransport: unsupported message role")
		}
		if m.Content == nil {
			return nil, "", false, false, errors.New("modeltransport: message content required")
		}
		tokens += 64 + len(m.Role) + len(*m.Content)
		if tokens > p.InputLimit() {
			return nil, "", false, false, errors.New("modeltransport: full context exceeds input bound")
		}
	}
	cap := maxOutputTokens
	c.MaxCompletionTokens = &cap
	if c.Stream {
		c.StreamOptions = &chatStreamOptions{IncludeUsage: true}
	} else if c.StreamOptions != nil {
		return nil, "", false, false, errors.New("modeltransport: stream options without streaming")
	}
	body, _ := json.Marshal(c)
	hash := sha256.Sum256(body)
	return body, hex.EncodeToString(hash[:]), c.Stream, c.ResponseFormat != nil, nil
}

func (p *Policy) reserve(hash, slot string) (int64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.ledger == nil {
		return 0, errors.New("modeltransport: policy closed or uninitialized")
	}
	if !p.acceptsCallSlot(slot) {
		return 0, ledgerError()
	}
	return p.ledger.reserve(hash, slot)
}
func (p *Policy) dispatch(id int64) error { return p.change(id, "dispatching", tokenUsage{}) }
func (p *Policy) change(id int64, outcome string, usage tokenUsage) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.ledger == nil {
		return errors.New("modeltransport: policy closed")
	}
	return p.ledger.change(id, outcome, usage)
}
func ledgerError() error {
	return errors.New("modeltransport: ledger unavailable, inconsistent, or policy stop")
}
