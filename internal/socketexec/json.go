package socketexec

import (
	"bytes"
	"encoding/json"
	"io"
	"slices"
	"strings"
	"unicode/utf8"
)

// The standard decoder accepts duplicate and case-folded members and repairs
// invalid UTF-8. Validate those properties before decoding any typed object.
func strictJSON(data []byte) error {
	if !utf8.Valid(data) {
		return errInvalidJSON
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := walkJSON(dec, 0); err != nil {
		return errInvalidJSON
	}
	if _, err := dec.Token(); err != io.EOF {
		return errInvalidJSON
	}
	return nil
}

func walkJSON(dec *json.Decoder, depth int) error {
	token, err := dec.Token()
	if err != nil {
		return errInvalidJSON
	}
	delim, container := token.(json.Delim)
	if !container {
		return nil
	}
	if depth >= 100 || (delim != '{' && delim != '[') {
		return errInvalidJSON
	}
	seen := make(map[string]bool)
	for dec.More() {
		if delim == '{' {
			key, err := dec.Token()
			name, ok := key.(string)
			if err != nil || !ok || seen[name] {
				return errInvalidJSON
			}
			seen[name] = true
		}
		if err := walkJSON(dec, depth+1); err != nil {
			return err
		}
	}
	end, err := dec.Token()
	if err != nil || (delim == '{' && end != json.Delim('}')) || (delim == '[' && end != json.Delim(']')) {
		return errInvalidJSON
	}
	return nil
}

// Reject strings that Marshal would silently repair in the public JSON-shaped
// argument domain. The depth bound also stops cycles before recursive traversal.
func validStrings(value any, depth int) bool {
	if depth > 100 {
		return false
	}
	switch value := value.(type) {
	case string:
		return utf8.ValidString(value)
	case map[string]any:
		for key, child := range value {
			if !utf8.ValidString(key) || !validStrings(child, depth+1) {
				return false
			}
		}
	case []any:
		for _, child := range value {
			if !validStrings(child, depth+1) {
				return false
			}
		}
	}
	return true
}

func object(data []byte, dst any, fields, nullable string) error {
	if strictJSON(data) != nil {
		return errInvalidJSON
	}
	var members map[string]json.RawMessage
	if json.Unmarshal(data, &members) != nil || members == nil {
		return errInvalidJSON
	}
	allowed, nulls := strings.Fields(fields), strings.Fields(nullable)
	for name, raw := range members {
		if !slices.Contains(allowed, name) || (bytes.Equal(raw, []byte("null")) && !slices.Contains(nulls, name)) {
			return errInvalidJSON
		}
	}
	if json.Unmarshal(data, dst) != nil {
		return errInvalidJSON
	}
	return nil
}
