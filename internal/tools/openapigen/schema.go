package main

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"
)

var (
	timeType       = reflect.TypeOf(time.Time{})
	rawMessageType = reflect.TypeOf(json.RawMessage{})
)

// schemaBuilder walks contract types with reflection and accumulates
// named struct types as components/schemas entries. Reflection gives
// the truthful serialized shape (json tags, embedding, omitempty);
// the docIndex overlays GoDoc comments as descriptions. Component
// names are the Go type names; a name collision across packages is a
// hard error so two different shapes can never silently share a
// schema.
type schemaBuilder struct {
	docs    *docIndex
	schemas *omap                   // components/schemas, first-encounter order
	names   map[reflect.Type]string // assigned component names
	byName  map[string]reflect.Type // collision detection
}

func newSchemaBuilder(docs *docIndex) *schemaBuilder {
	return &schemaBuilder{
		docs:    docs,
		schemas: newOmap(),
		names:   map[reflect.Type]string{},
		byName:  map[string]reflect.Type{},
	}
}

// refFor registers t (a named struct type) as a component and
// returns a $ref to it. Registration happens before the schema body
// is built so self-referential types terminate at the ref.
func (b *schemaBuilder) refFor(t reflect.Type) (*omap, error) {
	name, ok := b.names[t]
	if !ok {
		name = t.Name()
		if prior, taken := b.byName[name]; taken {
			return nil, fmt.Errorf("component name %q claimed by both %s.%s and %s.%s; rename one contract type",
				name, prior.PkgPath(), prior.Name(), t.PkgPath(), t.Name())
		}
		b.names[t] = name
		b.byName[name] = t
		// Reserve the slot in encounter order, then fill it: schemaForStruct
		// can recurse back into refFor for nested contract types.
		b.schemas.set(name, nil)
		schema, err := b.schemaForStruct(t)
		if err != nil {
			return nil, fmt.Errorf("schema for %s.%s: %w", t.PkgPath(), t.Name(), err)
		}
		b.schemas.set(name, schema)
	}
	ref := newOmap()
	ref.set("$ref", "#/components/schemas/"+name)
	return ref, nil
}

// schemaFor returns the schema (possibly a $ref) for an arbitrary
// reflect type.
func (b *schemaBuilder) schemaFor(t reflect.Type) (*omap, error) {
	switch t {
	case timeType:
		return newOmap().set("type", "string").set("format", "date-time"), nil
	case rawMessageType:
		return newOmap().set("description", "Arbitrary JSON value."), nil
	}

	switch t.Kind() {
	case reflect.Pointer:
		elem, err := b.schemaFor(t.Elem())
		if err != nil {
			return nil, err
		}
		return nullable(elem), nil
	case reflect.Struct:
		if t.Name() != "" {
			return b.refFor(t)
		}
		return b.schemaForStruct(t)
	case reflect.String:
		return newOmap().set("type", "string"), nil
	case reflect.Bool:
		return newOmap().set("type", "boolean"), nil
	case reflect.Int, reflect.Int64, reflect.Uint, reflect.Uint64:
		return newOmap().set("type", "integer").set("format", "int64"), nil
	case reflect.Int8, reflect.Int16, reflect.Int32, reflect.Uint8, reflect.Uint16, reflect.Uint32:
		return newOmap().set("type", "integer"), nil
	case reflect.Float32, reflect.Float64:
		return newOmap().set("type", "number"), nil
	case reflect.Slice, reflect.Array:
		if t.Elem().Kind() == reflect.Uint8 {
			// []byte marshals as base64.
			return newOmap().set("type", "string").set("format", "byte"), nil
		}
		items, err := b.schemaFor(t.Elem())
		if err != nil {
			return nil, err
		}
		return newOmap().set("type", "array").set("items", items), nil
	case reflect.Map:
		if t.Key().Kind() != reflect.String {
			return nil, fmt.Errorf("map key kind %s is not representable in JSON", t.Key().Kind())
		}
		values, err := b.schemaFor(t.Elem())
		if err != nil {
			return nil, err
		}
		return newOmap().set("type", "object").set("additionalProperties", values), nil
	case reflect.Interface:
		return newOmap().set("description", "Arbitrary JSON value."), nil
	default:
		return nil, fmt.Errorf("unsupported kind %s", t.Kind())
	}
}

// nullable widens a schema to admit JSON null, the wire value a nil
// pointer decodes from (and, without omitempty, encodes to). Typed
// schemas grow "null" in their type; $refs wrap in anyOf because a
// $ref cannot carry sibling keys; schemas with no type constraint
// (RawMessage, interface) already admit null.
func nullable(schema *omap) *omap {
	if _, isRef := schema.get("$ref"); isRef {
		return newOmap().set("anyOf", []any{schema, newOmap().set("type", "null")})
	}
	if typ, ok := schema.get("type"); ok {
		schema.set("type", []any{typ, "null"})
	}
	return schema
}

// schemaForStruct builds the object schema for a struct type,
// following encoding/json semantics: tag-renamed fields, skipped "-"
// fields, promoted embedded fields, and omitempty/omitzero optionality.
func (b *schemaBuilder) schemaForStruct(t reflect.Type) (*omap, error) {
	properties := newOmap()
	var required []string
	if err := b.collectStructFields(t, properties, &required); err != nil {
		return nil, err
	}
	schema := newOmap()
	if t.Name() != "" {
		if doc := b.docs.typeDoc(t.PkgPath(), t.Name()); doc != "" {
			schema.set("description", doc)
		}
	}
	schema.set("type", "object")
	schema.set("properties", properties)
	if len(required) > 0 {
		schema.set("required", required)
	}
	return schema, nil
}

// collectStructFields appends t's serialized fields to properties,
// recursing into promoted (anonymous, untagged) embedded structs the
// way encoding/json does.
func (b *schemaBuilder) collectStructFields(t reflect.Type, properties *omap, required *[]string) error {
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		tagName, tagOpts, _ := strings.Cut(field.Tag.Get("json"), ",")
		// Go 1.26's encoder ignores a field whose tag name is "-"
		// whether or not options follow ("-", "-,omitempty"), so the
		// schema must too (verified empirically against this
		// module's toolchain).
		if tagName == "-" {
			continue
		}

		if field.Anonymous && tagName == "" {
			embedded := field.Type
			if embedded.Kind() == reflect.Pointer {
				embedded = embedded.Elem()
			}
			if embedded.Kind() == reflect.Struct {
				if err := b.collectStructFields(embedded, properties, required); err != nil {
					return err
				}
				continue
			}
		}
		if !field.IsExported() {
			continue
		}

		name := tagName
		if name == "" {
			name = field.Name
		}
		fieldSchema, err := b.schemaFor(field.Type)
		if err != nil {
			return fmt.Errorf("field %s: %w", field.Name, err)
		}
		if doc := b.docs.fieldDoc(t.PkgPath(), t.Name(), field.Name); doc != "" {
			// A $ref must not carry siblings in every renderer;
			// wrap documented refs so the description survives.
			if _, isRef := fieldSchema.get("$ref"); isRef {
				fieldSchema = newOmap().
					set("description", doc).
					set("allOf", []any{fieldSchema})
			} else {
				// The author's doc comment always wins over a
				// type-derived description (json.RawMessage and
				// interface schemas carry a generic one).
				withDoc := newOmap().set("description", doc)
				for _, k := range fieldSchema.keys {
					if k == "description" {
						continue
					}
					withDoc.set(k, fieldSchema.values[k])
				}
				fieldSchema = withDoc
			}
		}
		if err := applyOpenAPITag(fieldSchema, field.Tag.Get("openapi")); err != nil {
			return fmt.Errorf("field %s: %w", field.Name, err)
		}
		if _, exists := properties.get(name); exists {
			// encoding/json resolves same-name collisions with
			// depth/tag shadowing rules this generator does not
			// implement; refuse to guess which field wins rather
			// than document the wrong shape.
			return fmt.Errorf("duplicate property %q (embedded-field shadowing is not supported)", name)
		}
		properties.set(name, fieldSchema)

		optional := hasOption(tagOpts, "omitempty") || hasOption(tagOpts, "omitzero")
		if !optional {
			*required = append(*required, name)
		}
	}
	return nil
}

func hasOption(opts, want string) bool {
	for opts != "" {
		var opt string
		opt, opts, _ = strings.Cut(opts, ",")
		if opt == want {
			return true
		}
	}
	return false
}

// applyOpenAPITag overlays the field's `openapi:"…"` struct tag onto
// its schema. Supported directives: format=<v>, enum=a|b|c,
// example=<v>, readOnly, writeOnly, deprecated. Unknown directives
// are a hard error so a typo (readonly, fromat) cannot silently ship
// an undocumented contract.
func applyOpenAPITag(schema *omap, tag string) error {
	if tag == "" {
		return nil
	}
	if _, isRef := schema.get("$ref"); isRef {
		return fmt.Errorf("openapi tag cannot apply to a $ref field; document the referenced type instead")
	}
	for _, directive := range strings.Split(tag, ",") {
		directive = strings.TrimSpace(directive)
		key, value, hasValue := strings.Cut(directive, "=")
		switch key {
		case "format":
			if !hasValue || value == "" {
				return fmt.Errorf("openapi tag format= needs a value")
			}
			schema.set("format", value)
		case "enum":
			if !hasValue || value == "" {
				return fmt.Errorf("openapi tag enum= needs |-separated values")
			}
			var enum []any
			for _, v := range strings.Split(value, "|") {
				enum = append(enum, v)
			}
			schema.set("enum", enum)
		case "example":
			if !hasValue {
				return fmt.Errorf("openapi tag example= needs a value")
			}
			schema.set("example", exampleValue(value))
		case "readOnly":
			schema.set("readOnly", true)
		case "writeOnly":
			schema.set("writeOnly", true)
		case "deprecated":
			schema.set("deprecated", true)
		default:
			return fmt.Errorf("unknown openapi tag directive %q", directive)
		}
	}
	return nil
}

// exampleValue types an example= tag value: numbers and booleans
// become JSON numbers and booleans, everything else stays a string.
func exampleValue(raw string) any {
	if n, err := strconv.ParseInt(raw, 10, 64); err == nil {
		return n
	}
	if f, err := strconv.ParseFloat(raw, 64); err == nil {
		return f
	}
	if b, err := strconv.ParseBool(raw); err == nil {
		return b
	}
	return raw
}

// collectPackagePaths walks the reachable type graph from the given
// roots and returns every package that declares a named struct type
// in it — the packages whose source the docIndex must parse.
func collectPackagePaths(roots []reflect.Type) []string {
	seen := map[reflect.Type]bool{}
	pkgs := map[string]bool{}
	var walk func(t reflect.Type)
	walk = func(t reflect.Type) {
		if t == nil || seen[t] {
			return
		}
		seen[t] = true
		switch t.Kind() {
		case reflect.Pointer, reflect.Slice, reflect.Array:
			walk(t.Elem())
		case reflect.Map:
			walk(t.Key())
			walk(t.Elem())
		case reflect.Struct:
			if t.PkgPath() != "" {
				pkgs[t.PkgPath()] = true
			}
			for i := 0; i < t.NumField(); i++ {
				walk(t.Field(i).Type)
			}
		}
	}
	for _, t := range roots {
		walk(t)
	}
	var out []string
	for pkg := range pkgs {
		out = append(out, pkg)
	}
	return out
}
