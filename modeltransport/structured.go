package modeltransport

import (
	"encoding/json"
	"errors"
	"regexp"
)

// Schema mode is an explicit text-only Chat extension, not arbitrary request
// parameters. The caller still validates the returned document contents and scopes.
type responseFormat struct {
	Type       string          `json:"type"`
	JSONSchema *responseSchema `json:"json_schema"`
}
type responseSchema struct {
	Name   string         `json:"name"`
	Strict *bool          `json:"strict"`
	Schema map[string]any `json:"schema"`
}

var schemaName = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func (f *responseFormat) inputBytes() (int, error) {
	if f.Type != "json_schema" || f.JSONSchema == nil || !schemaName.MatchString(f.JSONSchema.Name) || f.JSONSchema.Strict == nil || !*f.JSONSchema.Strict || f.JSONSchema.Schema["type"] != "object" {
		return 0, errors.New("modeltransport: unsupported response format")
	}
	b, err := json.Marshal(f)
	if err != nil || len(b) > 16384 {
		return 0, errors.New("modeltransport: response format exceeds bound")
	}
	return len(b), nil
}
