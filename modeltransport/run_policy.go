package modeltransport

import (
	"encoding/json"
	"errors"
	"math/big"
	"path/filepath"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// RunPricing freezes explicit USD rates and their provenance for one binding.
type RunPricing struct {
	Input  int64  `json:"inputMicroUSDPerMillionTokens"`
	Output int64  `json:"outputMicroUSDPerMillionTokens"`
	Extra  *int64 `json:"extraMicroUSDPerCall"`
	Source string `json:"source"`
	AsOf   string `json:"asOf"`
}

// RunBinding pins a destination, audience, model and explicit prices together.
type RunBinding struct {
	ID         string     `json:"id"`
	Endpoint   string     `json:"endpoint"`
	Scope      string     `json:"scope"`
	Deployment string     `json:"deployment"`
	Pricing    RunPricing `json:"pricing"`
}

// RunSlot declares one call at its immutable binding.
type RunSlot struct {
	ID        string `json:"id"`
	BindingID string `json:"bindingID"`
}

// RunConfig is a complete, library-only inventory sharing one budget and lifecycle.
type RunConfig struct {
	RunID          string       `json:"runID"`
	LedgerPath     string       `json:"ledgerPath"`
	PlanDigest     string       `json:"planDigest"`
	MaxInputTokens *int         `json:"maxInputTokens,omitempty"`
	Bindings       []RunBinding `json:"bindings"`
	Slots          []RunSlot    `json:"slots"`
}

// runSnapshot is deliberately separate from the unchanged file-policy profiles.
type runSnapshot struct {
	Version int `json:"version"`
	RunConfig
}

// ValidateRunConfig checks a complete worst-case reservation without I/O.
func ValidateRunConfig(c RunConfig) error {
	invalid := errors.New("modeltransport: invalid run policy")
	if !validRunLabel(c.RunID) || !utf8.ValidString(c.LedgerPath) || !filepath.IsAbs(c.LedgerPath) || filepath.Clean(c.LedgerPath) != c.LedgerPath ||
		(c.MaxInputTokens != nil && *c.MaxInputTokens != 32768) || len(c.Bindings) < 1 || len(c.Bindings) > 64 || len(c.Slots) < 1 || len(c.Slots) > 64 {
		return invalid
	}
	if len(c.PlanDigest) != 71 || !strings.HasPrefix(c.PlanDigest, "sha256:") {
		return invalid
	}
	for _, ch := range c.PlanDigest[7:] {
		if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f') {
			return invalid
		}
	}
	bindings := make(map[string]RunBinding, len(c.Bindings))
	for _, b := range c.Bindings {
		if _, exists := bindings[b.ID]; exists || !validCallID(b.ID) || !validRunLabel(b.Deployment) || b.Scope == "" || !utf8.ValidString(b.Scope) || strings.IndexFunc(b.Scope, unicode.IsSpace) >= 0 ||
			!utf8.ValidString(b.Endpoint) || !utf8.ValidString(b.Pricing.Source) {
			return invalid
		}
		if _, err := parseEndpoint(b.Endpoint); err != nil {
			return err
		}
		if err := validatePricing(pricing(b.Pricing)); err != nil {
			return err
		}
		bindings[b.ID] = b
	}
	seen, used := map[string]bool{}, map[string]bool{}
	total := new(big.Int)
	for _, slot := range c.Slots {
		b, ok := bindings[slot.BindingID]
		if !ok || !validCallID(slot.ID) || seen[slot.ID] {
			return invalid
		}
		seen[slot.ID], used[slot.BindingID] = true, true
		total.Add(total, priceReservation(pricing(b.Pricing), runInputLimit(c)))
	}
	if len(used) != len(bindings) {
		return invalid
	}
	if total.Cmp(big.NewInt(2000000000000)) > 0 {
		return errors.New("modeltransport: full run reservation exceeds USD 2")
	}
	data, err := json.Marshal(runSnapshot{Version: 4, RunConfig: c})
	if err != nil || len(data) > maxRequestBytes {
		return errors.New("modeltransport: run snapshot exceeds 64 KiB")
	}
	return nil
}

func validRunLabel(label string) bool {
	return utf8.ValidString(label) && len(label) > 0 && len(label) <= 256 && strings.TrimSpace(label) == label
}

func runInputLimit(c RunConfig) int {
	if c.MaxInputTokens != nil {
		return *c.MaxInputTokens
	}
	return maxInputTokens
}

// OpenRunPolicy freezes all input before validation, then opens one shared ledger.
// It adds no file profile: version 4 snapshots cannot be opened by OpenPolicyFile.
func OpenRunPolicy(c RunConfig) (*Policy, error) {
	c.Bindings = slices.Clone(c.Bindings)
	c.Slots = slices.Clone(c.Slots)
	if c.MaxInputTokens != nil {
		v := *c.MaxInputTokens
		c.MaxInputTokens = &v
	}
	for i := range c.Bindings {
		if c.Bindings[i].Pricing.Extra != nil {
			v := *c.Bindings[i].Pricing.Extra
			c.Bindings[i].Pricing.Extra = &v
		}
	}
	if err := ValidateRunConfig(c); err != nil {
		return nil, err
	}
	snapshot := &runSnapshot{Version: 4, RunConfig: c}
	data, _ := json.Marshal(snapshot)
	slots := make([]string, len(c.Slots))
	for i, slot := range c.Slots {
		slots[i] = slot.ID
	}
	ledger, err := openBudgetLedger(c.LedgerPath, string(data), len(slots), runInputLimit(c), slots)
	if err != nil {
		return nil, err
	}
	return &Policy{run: snapshot, ledger: ledger}, nil
}

// The inventory is bounded to 64; direct lookup avoids a second mutable index.
func (p *Policy) runBinding(slot string) (RunBinding, bool) {
	for _, call := range p.run.Slots {
		if call.ID == slot {
			for _, b := range p.run.Bindings {
				if b.ID == call.BindingID {
					return b, true
				}
			}
		}
	}
	return RunBinding{}, false
}

func (p *Policy) matchesBinding(c Config) bool {
	if p.run == nil {
		return p.config.Deployment == c.Deployment && p.acceptsCallSlot(c.CallSlot)
	}
	b, ok := p.runBinding(c.CallSlot)
	return ok && b.Endpoint == c.Endpoint && b.Scope == c.Scope && b.Deployment == c.Deployment
}
