package api

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRouteTableIntegrity is the fail-closed guard on the route
// table: every entry must carry complete, coherent metadata, because
// both Handler registration and the generated OpenAPI contract are
// projected from it. A malformed entry caught here never reaches a
// running mux or a published spec.
func TestRouteTableIntegrity(t *testing.T) {
	routes := Routes()
	if len(routes) == 0 {
		t.Fatal("route table is empty")
	}

	validAuth := map[AuthPosture]bool{AuthPublic: true, AuthIdentity: true, AuthSession: true}
	seenPatterns := map[string]bool{}
	seenOps := map[string]bool{}

	for _, rt := range routes {
		id := rt.Method + " " + rt.Path
		t.Run(id, func(t *testing.T) {
			if rt.Method != http.MethodGet && rt.Method != http.MethodPost &&
				rt.Method != http.MethodPut && rt.Method != http.MethodPatch && rt.Method != http.MethodDelete {
				t.Errorf("unexpected method %q", rt.Method)
			}
			if !strings.HasPrefix(rt.Path, "/") {
				t.Errorf("path %q does not start with /", rt.Path)
			}
			if rt.OperationID == "" {
				t.Error("missing OperationID")
			}
			if rt.Summary == "" {
				t.Error("missing Summary")
			}
			if len(rt.Tags) == 0 {
				t.Error("missing Tags")
			}
			if rt.handler == nil {
				t.Error("missing handler binding")
			}
			if len(rt.SuccessStatuses) == 0 {
				t.Error("missing SuccessStatuses")
			}
			if !validAuth[rt.Auth] {
				t.Errorf("unknown auth posture %q", rt.Auth)
			}

			if seenPatterns[id] {
				t.Errorf("duplicate registration %q", id)
			}
			seenPatterns[id] = true
			if seenOps[rt.OperationID] {
				t.Errorf("duplicate OperationID %q", rt.OperationID)
			}
			seenOps[rt.OperationID] = true

			if rt.Auth == AuthSession {
				if rt.SessionAction == "" {
					t.Error("AuthSession route missing SessionAction")
				}
				if rt.JourneyPathParam == "" {
					t.Error("AuthSession route missing JourneyPathParam")
				} else if !strings.Contains(rt.Path, "{"+rt.JourneyPathParam+"}") {
					t.Errorf("JourneyPathParam %q not a wildcard in path %q", rt.JourneyPathParam, rt.Path)
				}
			} else {
				if rt.SessionAction != "" || rt.JourneyPathParam != "" {
					t.Error("session metadata set on non-session route")
				}
			}

			if rt.Response == nil {
				if len(rt.SuccessStatuses) != 1 || rt.SuccessStatuses[0] != http.StatusNoContent {
					t.Error("nil Response requires exactly one 204 success status")
				}
			}
		})
	}
}

// TestContractMetaSurface verifies the generated spec and the
// embedded explorer are served by the handler.
func TestContractMetaSurface(t *testing.T) {
	server := NewServer(Config{Address: "127.0.0.1", Port: 8080}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	handler := server.Handler()

	tests := []struct {
		path        string
		contentType string
		wantBody    string
	}{
		{"/openapi.json", "application/json", `"openapi"`},
		{"/openapi.yaml", "application/yaml", "openapi:"},
		{"/docs/", "text/html; charset=utf-8", "Scalar.createApiReference"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
			}
			if got := rec.Header().Get("Content-Type"); got != tt.contentType {
				t.Errorf("Content-Type = %q, want %q", got, tt.contentType)
			}
			if !strings.Contains(rec.Body.String(), tt.wantBody) {
				t.Errorf("body does not contain %q", tt.wantBody)
			}
		})
	}
}
