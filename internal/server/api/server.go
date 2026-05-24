// Package api implements the Spivot HTTP API.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/wheelsdown/spivot-server/internal/platform/buildinfo"
	"github.com/wheelsdown/spivot-server/internal/platform/logging"
	"github.com/wheelsdown/spivot-server/internal/platform/proxy"
)

// Store is the database behavior the API server needs for readiness checks.
type Store interface {
	// Ping verifies that the backing store is reachable.
	Ping(context.Context) error
}

// Config describes the HTTP API server's listen and deployment metadata.
type Config struct {
	// Address is the local TCP address to bind.
	Address string
	// Port is the local TCP port to bind.
	Port int
	// PublicURL is the canonical URL served by the edge proxy.
	PublicURL *url.URL
	// Proxy controls whether forwarded request metadata is trusted.
	Proxy proxy.Config
	// Store is the runtime database dependency.
	Store Store
}

// ListenAddr returns the TCP address used by the HTTP server.
func (c Config) ListenAddr() string {
	return net.JoinHostPort(c.Address, strconv.Itoa(c.Port))
}

// Server is the HTTP API server.
type Server struct {
	cfg    Config
	logger *slog.Logger
	server *http.Server
}

// NewServer creates a Spivot API server with the provided configuration.
func NewServer(cfg Config, logger *slog.Logger) *Server {
	return &Server{
		cfg:    cfg,
		logger: logger,
	}
}

// Handler returns the API HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.handleRoot)
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleReady)
	mux.HandleFunc("GET /v1/version", s.handleVersion)
	return s.withLogging(mux)
}

// Start begins serving HTTP requests until the server shuts down.
func (s *Server) Start(ctx context.Context) error {
	s.server = &http.Server{
		Addr:              s.cfg.ListenAddr(),
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		BaseContext: func(net.Listener) context.Context {
			return ctx
		},
	}

	displayAddress := s.cfg.Address
	if displayAddress == "" || displayAddress == "0.0.0.0" {
		displayAddress = "0.0.0.0"
	}
	s.logger.Info("starting API server",
		"address", displayAddress,
		"port", s.cfg.Port,
		"public_url", s.publicURLString(),
		"trust_proxy", s.cfg.Proxy.TrustForwardedHeaders,
		"trusted_proxy_networks", len(s.cfg.Proxy.TrustedNetworks),
	)
	err := s.server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.server == nil {
		return nil
	}
	return s.server.Shutdown(ctx)
}

func (s *Server) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := logging.NewAccessResponseWriter(w)
		next.ServeHTTP(rw, r)
		reqInfo := proxy.RequestInfoFrom(r, s.cfg.Proxy)
		s.logger.Info("request handled",
			"kind", "http_access",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.StatusCode(),
			"response_bytes", rw.BytesWritten(),
			"duration_ms", time.Since(start).Milliseconds(),
			"client_ip", reqInfo.ClientIP,
			"scheme", reqInfo.Scheme,
			"host", reqInfo.Host,
			"trusted_proxy", reqInfo.TrustedProxy,
		)
	})
}

func (s *Server) handleRoot(w http.ResponseWriter, _ *http.Request) {
	response := map[string]string{
		"name":    "Spivot Server",
		"version": buildinfo.Version,
		"status":  "ok",
	}
	if publicURL := s.publicURLString(); publicURL != "" {
		response["public_url"] = publicURL
	}
	writeJSON(w, response, s.logger)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]string{
		"status":  "healthy",
		"version": buildinfo.Version,
		"uptime":  buildinfo.Uptime().String(),
	}, s.logger)
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Store != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := s.cfg.Store.Ping(ctx); err != nil {
			s.logger.Warn("readiness check failed", "error", err)
			writeJSONStatus(w, http.StatusServiceUnavailable, map[string]string{
				"status":  "unready",
				"version": buildinfo.Version,
			}, s.logger)
			return
		}
	}

	writeJSON(w, map[string]string{
		"status":  "ready",
		"version": buildinfo.Version,
	}, s.logger)
}

func (s *Server) handleVersion(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, buildinfo.RuntimeInfo(), s.logger)
}

func writeJSON(w http.ResponseWriter, v any, logger *slog.Logger) {
	writeJSONStatus(w, http.StatusOK, v, logger)
}

func writeJSONStatus(w http.ResponseWriter, status int, v any, logger *slog.Logger) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		logger.Debug("failed to write JSON response", "error", err)
	}
}

// URL returns the public URL when configured, otherwise the local listen URL.
func (s *Server) URL() string {
	if publicURL := s.publicURLString(); publicURL != "" {
		return publicURL
	}
	return fmt.Sprintf("http://%s", s.cfg.ListenAddr())
}

func (s *Server) publicURLString() string {
	if s.cfg.PublicURL == nil {
		return ""
	}
	return s.cfg.PublicURL.String()
}
