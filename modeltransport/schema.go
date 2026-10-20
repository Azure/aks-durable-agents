package modeltransport

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
)

// encoding/json otherwise accepts case-insensitive aliases even with
// DisallowUnknownFields. Only the documented exact spellings belong to this
// closed configuration/request schema.
func exactSchemaKeys(raw []byte, t reflect.Type) error {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Struct:
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil {
			return err
		}
		fields := make(map[string]reflect.Type, t.NumField())
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			fields[name] = f.Type
		}
		for key, value := range object {
			field, ok := fields[key]
			if !ok {
				return errors.New("non-schema member")
			}
			if err := exactSchemaKeys(value, field); err != nil {
				return err
			}
		}
	case reflect.Slice:
		var values []json.RawMessage
		if err := json.Unmarshal(raw, &values); err != nil {
			return err
		}
		for _, value := range values {
			if err := exactSchemaKeys(value, t.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}
