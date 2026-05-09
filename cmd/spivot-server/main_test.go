package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRunVersionJSON(t *testing.T) {
	var stdout bytes.Buffer

	if err := run(context.Background(), &stdout, &bytes.Buffer{}, []string{"-o", "json", "version"}); err != nil {
		t.Fatalf("run version: %v", err)
	}

	var got map[string]string
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode version JSON: %v", err)
	}
	if got["version"] == "" {
		t.Fatal("version is empty")
	}
}

func TestRunVersionJSONFlagForms(t *testing.T) {
	tests := [][]string{
		{"-o=json", "version"},
		{"--output", "json", "version"},
		{"--output=json", "version"},
	}

	for _, args := range tests {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			var stdout bytes.Buffer

			if err := run(context.Background(), &stdout, &bytes.Buffer{}, args); err != nil {
				t.Fatalf("run version: %v", err)
			}

			var got map[string]string
			if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
				t.Fatalf("decode version JSON: %v", err)
			}
			if got["version"] == "" {
				t.Fatal("version is empty")
			}
		})
	}
}

func TestRunPrintsUsageWithoutArgs(t *testing.T) {
	var stdout bytes.Buffer

	if err := run(context.Background(), &stdout, &bytes.Buffer{}, nil); err != nil {
		t.Fatalf("run usage: %v", err)
	}
	if !strings.Contains(stdout.String(), "spivot-server [flags] <command>") {
		t.Fatalf("usage output missing command synopsis:\n%s", stdout.String())
	}
}

func TestRunRejectsUnknownGlobalFlag(t *testing.T) {
	err := run(context.Background(), &bytes.Buffer{}, &bytes.Buffer{}, []string{"--bogus", "version"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "unknown flag") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunRejectsUnknownCommand(t *testing.T) {
	err := run(context.Background(), &bytes.Buffer{}, &bytes.Buffer{}, []string{"bogus"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHealthcheck(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	err := runHealthcheck(context.Background(), []string{"-url", server.URL})
	if err != nil {
		t.Fatalf("healthcheck: %v", err)
	}
}
