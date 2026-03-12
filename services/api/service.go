// Package api provides the public REST API for the AITC platform.
// The cmd/api binary calls Run() to start the service.
//
// Service flow:
//  1. HTTP server exposes v1 REST endpoints for cases, recommendations, autopilot, reports.
//  2. Auth middleware validates Okta OIDC tokens (dev stub mode available).
//  3. RBAC middleware enforces role-based access per endpoint.
//  4. Handlers query Postgres with tenant RLS and write audit log entries.
package api

import (
	"context"
	"fmt"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	globalaudit "github.com/ethicaltomas/aitc/internal/audit"
	"github.com/ethicaltomas/aitc/internal/config"
	"github.com/ethicaltomas/aitc/internal/db/postgres"
	httpserver "github.com/ethicaltomas/aitc/internal/http/server"
	"github.com/ethicaltomas/aitc/internal/logging"
	"github.com/ethicaltomas/aitc/internal/tracing"
	"github.com/ethicaltomas/aitc/services/api/internal/auth"
	"github.com/ethicaltomas/aitc/services/api/internal/handlers"
	"github.com/ethicaltomas/aitc/services/api/internal/rbac"
)

// Run starts the API service and blocks until SIGTERM/SIGINT or a fatal error.
func Run(cfg *config.Config) error {
	// ── 1. Structured JSON logger ───────────────────────────────────────────
	logger, err := logging.NewLogger(cfg.ServiceName)
	if err != nil {
		return fmt.Errorf("init logger: %w", err)
	}
	defer logger.Sync() //nolint:errcheck

	logger.Info("api service starting", zap.String("service", cfg.ServiceName))

	// ── 2. OpenTelemetry tracing ────────────────────────────────────────────
	shutdownTracing, err := tracing.Init(cfg.ServiceName)
	if err != nil {
		return fmt.Errorf("init tracing: %w", err)
	}

	// ── 3. Postgres connection pool (graceful degradation if unavailable) ───
	initCtx, initCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer initCancel()

	dbPool, err := postgres.NewPool(initCtx, cfg.Postgres.DSN, cfg.Postgres.MaxConns, cfg.Postgres.MinConns)
	if err != nil {
		logger.Warn("postgres unavailable; starting without DB", zap.Error(err))
		dbPool = nil
	}
	if dbPool != nil {
		defer dbPool.Close()
	}

	// ── 4. Audit writer ─────────────────────────────────────────────────────
	var auditWriter *globalaudit.Writer
	if dbPool != nil {
		auditWriter = globalaudit.NewWriter(dbPool)
	}

	// ── 5. Handlers ─────────────────────────────────────────────────────────
	h := handlers.New(dbPool, auditWriter, logger)

	// ── 6. Auth middleware config ────────────────────────────────────────────
	oktaCfg := auth.OktaConfig{
		BaseURL: cfg.Okta.BaseURL,
		DevMode: cfg.Okta.BaseURL == "",
	}

	// ── 7. HTTP server (health/ready/metrics + v1 routes) ───────────────────
	srv := httpserver.New(logger)

	srv.Router.Route("/v1", func(r chi.Router) {
		r.Use(auth.Middleware(oktaCfg))

		// Cases
		r.With(rbac.Require(rbac.RoleReadOnly, rbac.RoleAnalyst, rbac.RoleAuditor, rbac.RoleAdmin)).
			Get("/cases", h.ListCases)
		r.With(rbac.Require(rbac.RoleReadOnly, rbac.RoleAnalyst, rbac.RoleAuditor, rbac.RoleAdmin)).
			Get("/cases/{id}", h.GetCase)

		// Recommendations
		r.With(rbac.Require(rbac.RoleReadOnly, rbac.RoleAnalyst, rbac.RoleAuditor, rbac.RoleAdmin)).
			Get("/recommendations", h.ListRecommendations)
		r.With(rbac.Require(rbac.RoleAnalyst, rbac.RoleAdmin)).
			Post("/recommendations/{id}/execute", h.ExecuteRecommendation)

		// Autopilot
		r.With(rbac.Require(rbac.RoleAdmin)).
			Post("/autopilot/enable", h.EnableAutopilot)

		// Reports
		r.With(rbac.Require(rbac.RoleAnalyst, rbac.RoleAdmin)).
			Post("/reports", h.CreateReport)
		r.With(rbac.Require(rbac.RoleAuditor, rbac.RoleAnalyst, rbac.RoleAdmin)).
			Get("/reports/{id}/download", h.DownloadReport)
	})

	// ── 8. Graceful shutdown context ─────────────────────────────────────────
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	g, gCtx := errgroup.WithContext(ctx)

	// HTTP server goroutine
	g.Go(func() error {
		srv.SetReady(true)
		return srv.ListenAndServe(cfg.HTTP.ListenAddr)
	})

	// Shutdown watcher
	g.Go(func() error {
		<-gCtx.Done()
		srv.SetReady(false)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return shutdownTracing(shutdownCtx)
	})

	if err := g.Wait(); err != nil && err != context.Canceled {
		return err
	}
	logger.Info("api service stopped")
	return nil
}
