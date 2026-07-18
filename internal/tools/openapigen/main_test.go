package main

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func emptyDocs() *docIndex {
	return &docIndex{types: map[string]string{}, fields: map[string]string{}}
}

type sampleEmbedded struct {
	Kind string `json:"kind"`
}

type sampleContract struct {
	sampleEmbedded
	ID        string          `json:"id"`
	Count     int             `json:"count,omitempty"`
	When      time.Time       `json:"when"`
	Blob      []byte          `json:"blob"`
	Payload   json.RawMessage `json:"payload"`
	Notes     []string        `json:"notes,omitempty"`
	Hidden    string          `json:"-"`
	unexpored string          //nolint:unused // proves unexported fields are skipped
	Flag      string          `json:"flag" openapi:"enum=on|off,readOnly"`
}

func TestSchemaBuilderReflectsJSONShape(t *testing.T) {
	b := newSchemaBuilder(emptyDocs())
	ref, err := b.refFor(reflect.TypeOf(sampleContract{}))
	if err != nil {
		t.Fatalf("refFor: %v", err)
	}
	if got, _ := ref.get("$ref"); got != "#/components/schemas/sampleContract" {
		t.Fatalf("$ref = %v", got)
	}

	raw, err := json.Marshal(b.schemas)
	if err != nil {
		t.Fatalf("marshal schemas: %v", err)
	}
	var schemas map[string]struct {
		Properties map[string]map[string]any `json:"properties"`
		Required   []string                  `json:"required"`
	}
	if err := json.Unmarshal(raw, &schemas); err != nil {
		t.Fatalf("unmarshal schemas: %v", err)
	}
	schema, ok := schemas["sampleContract"]
	if !ok {
		t.Fatalf("sampleContract not registered; got %v", schemas)
	}

	tests := []struct {
		property string
		key      string
		want     any
	}{
		{"kind", "type", "string"}, // promoted from the embedded struct
		{"id", "type", "string"},
		{"count", "type", "integer"},
		{"when", "format", "date-time"},
		{"blob", "format", "byte"},
		{"payload", "description", "Arbitrary JSON value."},
		{"notes", "type", "array"},
		{"flag", "readOnly", true},
	}
	for _, tt := range tests {
		prop, ok := schema.Properties[tt.property]
		if !ok {
			t.Errorf("property %q missing", tt.property)
			continue
		}
		if got := prop[tt.key]; !reflect.DeepEqual(got, tt.want) {
			t.Errorf("property %q %s = %v, want %v", tt.property, tt.key, got, tt.want)
		}
	}
	if _, ok := schema.Properties["Hidden"]; ok {
		t.Error(`json:"-" field leaked into schema`)
	}
	if _, ok := schema.Properties["unexpored"]; ok {
		t.Error("unexported field leaked into schema")
	}

	wantRequired := []string{"kind", "id", "when", "blob", "payload", "flag"}
	if !reflect.DeepEqual(schema.Required, wantRequired) {
		t.Errorf("required = %v, want %v", schema.Required, wantRequired)
	}

	enum, _ := schema.Properties["flag"]["enum"].([]any)
	if !reflect.DeepEqual(enum, []any{"on", "off"}) {
		t.Errorf("flag enum = %v", enum)
	}
}

func TestApplyOpenAPITagRejectsUnknownDirective(t *testing.T) {
	err := applyOpenAPITag(newOmap(), "readonly")
	if err == nil || !strings.Contains(err.Error(), "unknown openapi tag directive") {
		t.Fatalf("err = %v, want unknown-directive error", err)
	}
}

func TestOmapPreservesInsertionOrder(t *testing.T) {
	m := newOmap().set("zebra", 1).set("alpha", 2).set("zebra", 3)
	got, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"zebra":3,"alpha":2}` {
		t.Fatalf("marshal = %s", got)
	}
}

func TestYAMLFromJSONPreservesOrder(t *testing.T) {
	in := []byte(`{"zebra":{"b":1,"a":"x <y>"},"alpha":[true,null,2.5]}`)
	out, err := yamlFromJSON(in)
	if err != nil {
		t.Fatal(err)
	}
	want := "zebra:\n  b: 1\n  a: x <y>\nalpha:\n  - true\n  - null\n  - 2.5\n"
	if string(out) != want {
		t.Fatalf("yaml = %q, want %q", out, want)
	}
}

// TestGenerateEndToEnd runs the full projection against the real
// route table and contract structs — the same code path `just
// generate` runs. Catching a generator failure here means a broken
// table or an unsupported contract type can never reach the commit
// stage with stale artifacts.
func TestGenerateEndToEnd(t *testing.T) {
	jsonBytes, yamlBytes, err := generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	var doc struct {
		OpenAPI    string         `json:"openapi"`
		Paths      map[string]any `json:"paths"`
		Components struct {
			Schemas map[string]any `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(jsonBytes, &doc); err != nil {
		t.Fatalf("generated JSON does not parse: %v", err)
	}
	if doc.OpenAPI != "3.1.0" {
		t.Errorf("openapi = %q", doc.OpenAPI)
	}
	if len(doc.Paths) == 0 || len(doc.Components.Schemas) == 0 {
		t.Errorf("empty paths (%d) or schemas (%d)", len(doc.Paths), len(doc.Components.Schemas))
	}
	if !strings.HasPrefix(string(yamlBytes), "# Code generated") {
		t.Error("yaml missing generated-code header")
	}
}
