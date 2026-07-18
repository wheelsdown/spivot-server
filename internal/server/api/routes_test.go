package api

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wheelsdown/spivot-server/internal/platform/auth/macaroon"
)

// TestRouteTableIntegrity is the CI hook for the fail-closed guard on
// the route table: [ValidateRoutes] holds the invariants, and both
// [Server.Handler] (panic at startup) and the openapigen generator
// (refuse to emit) enforce it. This test keeps the shipping table
// green so neither ever fires in anger.
func TestRouteTableIntegrity(t *testing.T) {
	if err := ValidateRoutes(Routes()); err != nil {
		t.Fatalf("route table invalid: %v", err)
	}
}

// TestValidateRoutesRejectsMalformedEntries proves the guard actually
// bites on each invariant it claims to hold.
func TestValidateRoutesRejectsMalformedEntries(t *testing.T) {
	// valid returns a minimal well-formed entry tests then break in
	// exactly one way.
	valid := func() Route {
		return Route{
			Method:          http.MethodGet,
			Path:            "/v1/widgets/{id}",
			OperationID:     "widgetGet",
			Summary:         "Fetch a widget",
			Tags:            []string{tagSystem},
			Auth:            AuthIdentity,
			Response:        RootResponse{},
			SuccessStatuses: []int{http.StatusOK},
			handler:         bindHandler((*Server).handleRoot),
		}
	}

	tests := []struct {
		name    string
		mutate  func(*Route)
		wantErr string
	}{
		{"unknown method", func(r *Route) { r.Method = "FETCH" }, "unexpected method"},
		{"relative path", func(r *Route) { r.Path = "v1/widgets" }, "does not start with /"},
		{"missing operation id", func(r *Route) { r.OperationID = "" }, "missing OperationID"},
		{"missing summary", func(r *Route) { r.Summary = "" }, "missing Summary"},
		{"missing tags", func(r *Route) { r.Tags = nil }, "missing Tags"},
		{"unknown tag", func(r *Route) { r.Tags = []string{"Widgets"} }, "no RouteTags entry"},
		{"missing statuses", func(r *Route) { r.SuccessStatuses = nil }, "missing SuccessStatuses"},
		{"missing handler", func(r *Route) { r.handler = nil }, "missing handler binding"},
		{"unknown posture", func(r *Route) { r.Auth = AuthPosture("token") }, "unknown auth posture"},
		{"session metadata on identity route", func(r *Route) { r.JourneyPathParam = "id" }, "session metadata"},
		{"session without action", func(r *Route) { r.Auth = AuthSession; r.JourneyPathParam = "id" }, "without SessionAction"},
		{"session param not in path", func(r *Route) {
			r.Auth = AuthSession
			r.SessionAction = "journey.read"
			r.JourneyPathParam = "journeyId"
		}, "not present in path"},
		{"nil response without 204", func(r *Route) { r.Response = nil }, "204"},
		{"request optional without request", func(r *Route) { r.RequestOptional = true }, "RequestOptional without Request"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := valid()
			tt.mutate(&rt)
			err := ValidateRoutes([]Route{rt})
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
			}
		})
	}

	t.Run("duplicate operation id", func(t *testing.T) {
		a, b := valid(), valid()
		b.Path = "/v1/widgets"
		b.JourneyPathParam = ""
		err := ValidateRoutes([]Route{a, b})
		if err == nil || !strings.Contains(err.Error(), "duplicate OperationID") {
			t.Fatalf("err = %v, want duplicate OperationID", err)
		}
	})
	t.Run("duplicate registration", func(t *testing.T) {
		a, b := valid(), valid()
		b.OperationID = "widgetGetAgain"
		err := ValidateRoutes([]Route{a, b})
		if err == nil || !strings.Contains(err.Error(), "duplicate registration") {
			t.Fatalf("err = %v, want duplicate registration", err)
		}
	})
	t.Run("valid entry passes", func(t *testing.T) {
		rt := valid()
		if err := ValidateRoutes([]Route{rt}); err != nil {
			t.Fatalf("valid route rejected: %v", err)
		}
	})
}

// concretePath fills a pattern's {wildcard} segments with a literal
// so a request for it can be routed ("/v1/journeys/{id}" →
// "/v1/journeys/x").
func concretePath(pattern string) string {
	segs := strings.Split(pattern, "/")
	for i, seg := range segs {
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
			segs[i] = "x"
		}
	}
	return strings.Join(segs, "/")
}

// coverageVerifier builds a minimal macaroon verifier so AuthSession
// routes register; the coverage tests never present a macaroon, they
// only ask the mux which pattern would serve a request.
func coverageVerifier(t *testing.T) *macaroon.Verifier {
	t.Helper()
	verifier, err := macaroon.NewVerifier(func(context.Context, string) ([]byte, error) {
		return nil, macaroon.ErrUnknownRoot
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return verifier
}

// TestRouteCoverageMuxMatchesTable is the route-coverage assertion
// from issue #43 phase 2: with the session stack wired, a request for
// every table route must resolve to exactly that route's pattern —
// not the GET / catch-all, not a sibling wildcard. Registration is
// table-driven so the mux cannot normally drift, but this pins the
// seam against a future hand-registered route shadowing a table
// entry (or a registration-loop regression dropping one).
func TestRouteCoverageMuxMatchesTable(t *testing.T) {
	server := NewServer(Config{
		Address:          "127.0.0.1",
		Port:             8080,
		MacaroonVerifier: coverageVerifier(t),
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	mux := server.buildMux()

	for _, rt := range Routes() {
		want := rt.Method + " " + rt.Path
		t.Run(want, func(t *testing.T) {
			req := httptest.NewRequest(rt.Method, concretePath(rt.Path), nil)
			_, pattern := mux.Handler(req)
			if pattern != want {
				t.Errorf("mux resolves to %q, want %q", pattern, want)
			}
		})
	}
}

// TestSessionRoutesAbsentWithoutVerifier pins the other half of the
// registration contract: without a MacaroonVerifier the AuthSession
// routes must not be registered at all (RequireSession would 401
// unconditionally — dead code behind an auth wall).
func TestSessionRoutesAbsentWithoutVerifier(t *testing.T) {
	server := NewServer(Config{Address: "127.0.0.1", Port: 8080}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	mux := server.buildMux()

	for _, rt := range Routes() {
		if rt.Auth != AuthSession {
			continue
		}
		want := rt.Method + " " + rt.Path
		t.Run(want, func(t *testing.T) {
			req := httptest.NewRequest(rt.Method, concretePath(rt.Path), nil)
			_, pattern := mux.Handler(req)
			if pattern == want {
				t.Errorf("session route registered without a verifier")
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
