package main

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// omap is a JSON object that marshals its keys in insertion order.
// encoding/json sorts map keys alphabetically, which would scatter
// "openapi"/"info"/"paths" and every schema's properties; insertion
// order keeps the generated document readable and diff-stable in the
// order the source declares things (route table order, struct field
// order).
type omap struct {
	keys   []string
	values map[string]any
}

func newOmap() *omap {
	return &omap{values: map[string]any{}}
}

// set inserts or replaces a key, preserving the position of an
// existing key. It returns the map for chained construction.
func (m *omap) set(key string, value any) *omap {
	if _, exists := m.values[key]; !exists {
		m.keys = append(m.keys, key)
	}
	m.values[key] = value
	return m
}

func (m *omap) get(key string) (any, bool) {
	v, ok := m.values[key]
	return v, ok
}

// MarshalJSON emits the object with keys in insertion order.
func (m *omap) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range m.keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		kb, err := marshalNoEscape(k)
		if err != nil {
			return nil, fmt.Errorf("marshal key %q: %w", k, err)
		}
		buf.Write(kb)
		buf.WriteByte(':')
		vb, err := marshalNoEscape(m.values[k])
		if err != nil {
			return nil, fmt.Errorf("marshal value of %q: %w", k, err)
		}
		buf.Write(vb)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// marshalNoEscape is json.Marshal without HTML escaping, so prose
// like "Authorization: Macaroon <token>" stays readable instead of
// becoming <token>.
func marshalNoEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
