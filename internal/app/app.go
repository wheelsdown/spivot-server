// Package app wires the process lifecycle around the HTTP API server.
package app

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"
)

// Server is the lifecycle contract the app runs: start serving until
// the context ends, then shut down gracefully. Satisfied by
// [api.Server]; defined here so the lifecycle wiring does not depend
// on the HTTP package.
type Server interface {
	// Start begins serving and blocks until the server stops.
	Start(context.Context) error
	// Shutdown gracefully stops the server, honoring the context
	// deadline.
	Shutdown(context.Context) error
}

// App runs a [Server] through a signal-aware serve/shutdown cycle.
type App struct {
	server Server
	logger *slog.Logger
}

// New creates an App around the supplied server and logger.
func New(server Server, logger *slog.Logger) *App {
	return &App{
		server: server,
		logger: logger,
	}
}

// Serve runs the server until ctx is canceled, then performs a
// graceful shutdown bounded at 30 seconds. It returns nil on a clean
// stop and the server's error otherwise.
func (a *App) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		a.logger.Info("shutdown signal received")

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := a.server.Shutdown(shutdownCtx); err != nil {
			a.logger.Error("server shutdown failed", "error", err)
		}
		if shutdownCtx.Err() == context.DeadlineExceeded {
			a.logger.Warn("server shutdown timed out; some connections may have been forcefully terminated")
		}
	}()

	if err := a.server.Start(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}

	a.logger.Info("Spivot Server stopped")
	return nil
}
