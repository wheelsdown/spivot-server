// Package spec carries the generated OpenAPI contract artifacts for
// the native HTTP API.
//
// openapi.json and openapi.yaml are GENERATED files — do not edit
// them by hand. They are projected from the api package's route table
// ([api.Routes]) and contract structs by internal/tools/openapigen;
// regenerate with `just generate` after any change to routes or
// contract types. The artifacts are committed so the server binary
// can embed and serve them without running the generator at build
// time.
package spec

import _ "embed"

// JSON is the generated OpenAPI document in JSON form, served at
// GET /openapi.json.
//
//go:embed openapi.json
var JSON []byte

// YAML is the generated OpenAPI document in YAML form, served at
// GET /openapi.yaml.
//
//go:embed openapi.yaml
var YAML []byte
