// Package server provides a base HTTP server that satisfies Step 1.3 invariants:
// - /healthz (liveness)
// - /readyz  (readiness)
// - /metrics (Prometheus)
// - structured JSON logs with request IDs
// - graceful shutdown on SIGTERM
// - timeouts on every inbound connection
package server

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"

	aitcMiddleware "github.com/ethicaltomas/aitc/internal/http/middleware"
)

// ReadyFunc is called by /readyz; return nil when ready to serve traffic.
type ReadyFunc func(ctx context.Context) error

// Base is a pre-configured chi router that satisfies the Step 1.3 service invariants.
type Base struct {
	Router *chi.Mux
	logger *zap.Logger
	ready  atomic.Bool
}

// New creates a Base server with all Step 1.3 endpoints and middleware wired in.
func New(logger *zap.Logger) *Base {
	b := &Base{logger: logger}
	b.ready.Store(false)

	r := chi.NewRouter()

	// ── Middleware (Step 1.3: structured JSON logs, request IDs) ──
	r.Use(aitcMiddleware.RequestID)
	r.Use(chiMiddleware.RealIP)
	r.Use(aitcMiddleware.Logger(logger))
	r.Use(chiMiddleware.Recoverer)

	// ── Step 1.3: /healthz liveness ──
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	// ── Step 1.3: /readyz readiness ──
	r.Get("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if !b.ready.Load() {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"status":"not_ready"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ready"}`))
	})

	// ── Step 1.3: /metrics Prometheus ──
	r.Handle("/metrics", promhttp.Handler())

	b.Router = r
	return b
}

// SetReady marks the service as ready to accept traffic.
func (b *Base) SetReady(ready bool) {
	b.ready.Store(ready)
}

// ListenAndServe starts the HTTP server and blocks until SIGTERM/SIGINT.
// Graceful shutdown is performed with a 15-second drain window (Step 1.3).
func (b *Base) ListenAndServe(addr string) error {
	srv := &http.Server{
		Addr:         addr,
		Handler:      b.Router,
		ReadTimeout:  30 * time.Second, // Step 1.3: timeouts on every connection
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// ── Step 1.3: graceful shutdown on SIGTERM ──
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)

	errCh := make(chan error, 1)
	go func() {
		b.logger.Info("http server starting", zap.String("addr", addr))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case sig := <-quit:
		b.logger.Info("shutdown signal received", zap.String("signal", sig.String()))
	}

	b.SetReady(false)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		return err
	}

	b.logger.Info("http server stopped")
	return nil
}
