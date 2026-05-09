// Package app wires the process lifecycle around the HTTP API server.
package app

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"
)

type Server interface {
	Start(context.Context) error
	Shutdown(context.Context) error
}

type App struct {
	server Server
	logger *slog.Logger
}

func New(server Server, logger *slog.Logger) *App {
	return &App{
		server: server,
		logger: logger,
	}
}

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
