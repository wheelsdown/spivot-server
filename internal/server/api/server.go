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
	"strconv"
	"time"

	"github.com/wheelsdown/spivot-server/internal/platform/buildinfo"
	"github.com/wheelsdown/spivot-server/internal/platform/logging"
)

type Server struct {
	address string
	port    int
	logger  *slog.Logger
	server  *http.Server
}

func NewServer(address string, port int, logger *slog.Logger) *Server {
	return &Server{
		address: address,
		port:    port,
		logger:  logger,
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.handleRoot)
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleHealth)
	mux.HandleFunc("GET /v1/version", s.handleVersion)
	return s.withLogging(mux)
}

func (s *Server) Start(ctx context.Context) error {
	addr := net.JoinHostPort(s.address, strconv.Itoa(s.port))
	s.server = &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		BaseContext: func(net.Listener) context.Context {
			return ctx
		},
	}

	displayAddress := s.address
	if displayAddress == "" || displayAddress == "0.0.0.0" {
		displayAddress = "0.0.0.0"
	}
	s.logger.Info("starting API server", "address", displayAddress, "port", s.port)
	err := s.server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

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
		s.logger.Info("request handled",
			"kind", "http_access",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.StatusCode(),
			"response_bytes", rw.BytesWritten(),
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
}

func (s *Server) handleRoot(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]string{
		"name":    "Spivot Server",
		"version": buildinfo.Version,
		"status":  "ok",
	}, s.logger)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]string{
		"status":  "healthy",
		"version": buildinfo.Version,
		"uptime":  buildinfo.Uptime().String(),
	}, s.logger)
}

func (s *Server) handleVersion(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, buildinfo.RuntimeInfo(), s.logger)
}

func writeJSON(w http.ResponseWriter, v any, logger *slog.Logger) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		logger.Debug("failed to write JSON response", "error", err)
	}
}

func (s *Server) URL() string {
	return fmt.Sprintf("http://%s", net.JoinHostPort(s.address, strconv.Itoa(s.port)))
}
