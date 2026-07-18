package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// yamlFromJSON re-emits a JSON document as YAML, preserving object
// key order. It builds a yaml.Node tree from the JSON token stream
// rather than round-tripping through map[string]any, which would
// alphabetize every object and destroy the deliberate ordering the
// generator produces.
func yamlFromJSON(data []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	root, err := yamlNodeFromJSON(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing content after JSON document")
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(root); err != nil {
		return nil, fmt.Errorf("encode yaml: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("close yaml encoder: %w", err)
	}
	return buf.Bytes(), nil
}

func yamlNodeFromJSON(dec *json.Decoder) (*yaml.Node, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("read JSON token: %w", err)
	}
	return yamlNodeFromToken(dec, tok)
}

func yamlNodeFromToken(dec *json.Decoder, tok json.Token) (*yaml.Node, error) {
	switch v := tok.(type) {
	case json.Delim:
		switch v {
		case '{':
			node := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					return nil, fmt.Errorf("read object key: %w", err)
				}
				key, ok := keyTok.(string)
				if !ok {
					return nil, fmt.Errorf("object key %v is not a string", keyTok)
				}
				value, err := yamlNodeFromJSON(dec)
				if err != nil {
					return nil, err
				}
				node.Content = append(node.Content,
					&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
					value,
				)
			}
			if _, err := dec.Token(); err != nil { // consume '}'
				return nil, fmt.Errorf("read object end: %w", err)
			}
			return node, nil
		case '[':
			node := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
			for dec.More() {
				value, err := yamlNodeFromJSON(dec)
				if err != nil {
					return nil, err
				}
				node.Content = append(node.Content, value)
			}
			if _, err := dec.Token(); err != nil { // consume ']'
				return nil, fmt.Errorf("read array end: %w", err)
			}
			return node, nil
		default:
			return nil, fmt.Errorf("unexpected delimiter %q", v)
		}
	case string:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v}, nil
	case json.Number:
		tag := "!!int"
		if _, err := v.Int64(); err != nil {
			tag = "!!float"
		}
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: v.String()}, nil
	case bool:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: fmt.Sprintf("%t", v)}, nil
	case nil:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null", Value: "null"}, nil
	default:
		return nil, fmt.Errorf("unexpected JSON token %T", tok)
	}
}
