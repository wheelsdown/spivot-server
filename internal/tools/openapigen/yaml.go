package main

import (
	"bytes"
	"fmt"

	"gopkg.in/yaml.v3"
)

// yamlFromJSON re-emits a JSON document as YAML, preserving object
// key order. YAML is a superset of JSON, so yaml.v3 parses the JSON
// bytes directly into a node tree that keeps key order and resolves
// scalar tags (!!str/!!int/!!float/!!bool/!!null) with its own
// resolver — the same resolver a consumer of the artifact will use.
// The only post-processing needed is clearing the style flags so the
// encoder emits idiomatic block YAML instead of echoing JSON's
// flow/quoted style.
func yamlFromJSON(data []byte) ([]byte, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("parse JSON as YAML: %w", err)
	}
	clearStyle(&root)
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(root.Content[0]); err != nil {
		return nil, fmt.Errorf("encode yaml: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("close yaml encoder: %w", err)
	}
	return buf.Bytes(), nil
}

// clearStyle resets every node's style so the encoder chooses block
// layout and minimal quoting itself (re-quoting only where YAML
// requires it), instead of preserving the JSON input's flow style.
func clearStyle(node *yaml.Node) {
	node.Style = 0
	for _, child := range node.Content {
		clearStyle(child)
	}
}
