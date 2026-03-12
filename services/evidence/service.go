// Package evidence provides the public API for the evidence service.
// The cmd/evidence binary calls Run() to start the service.
//
// Evidence service flow:
//  1. On startup, wire DB, S3 uploader, and generator.
//  2. In scheduled mode: start a cron-style scheduler that polls for pending
//     evidence_reports rows and generates each one.
//  3. In on-demand mode: generate a single report by ID, then exit.
//  4. In both modes: expose /healthz, /readyz, /metrics via the shared HTTP server.
package evidence

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/ethicaltomas/aitc/internal/config"
	"github.com/ethicaltomas/aitc/internal/db/postgres"
	httpserver "github.com/ethicaltomas/aitc/internal/http/server"
	"github.com/ethicaltomas/aitc/internal/logging"
	"github.com/ethicaltomas/aitc/internal/tracing"
	"github.com/ethicaltomas/aitc/services/evidence/internal/archive"
	"github.com/ethicaltomas/aitc/services/evidence/internal/generator"
	"github.com/ethicaltomas/aitc/services/evidence/internal/scheduler"
)

// Options configures runtime behaviour of the evidence service.
type Options struct {
	// OnDemandTenantID + OnDemandReportID trigger single-report generation mode.
	OnDemandTenantID string
	OnDemandReportID string
	// ScheduleInterval is how often the scheduler polls for pending reports.
	// Defaults to 5 minutes.
	ScheduleInterval time.Duration
}

// Run starts the evidence service with the given config and options.
// It blocks until SIGTERM/SIGINT is received or a fatal error occurs.
func Run(cfg *config.Config, opts Options) error {
	// ── 1. Structured JSON logger ───────────────────────────────────────────────
	logger, err := logging.NewLogger(cfg.ServiceName)
	if err != nil {
		return fmt.Errorf("init logger: %w", err)
	}
	defer logger.Sync() //nolint:errcheck

	logger.Info("evidence service starting", zap.String("service", cfg.ServiceName))

	// ── 2. OpenTelemetry tracing ────────────────────────────────────────────────
	shutdownTracing, err := tracing.Init(cfg.ServiceName)
	if err != nil {
		return fmt.Errorf("init tracing: %w", err)
	}

	// ── 3. Postgres connection pool ─────────────────────────────────────────────
	initCtx, initCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer initCancel()

	dbPool, dbErr := postgres.NewPool(initCtx, cfg.Postgres.DSN, cfg.Postgres.MaxConns, cfg.Postgres.MinConns)
	if dbErr != nil {
		logger.Warn("postgres unavailable; evidence generation will fail",
			zap.Error(dbErr))
	} else {
		defer dbPool.Close()
	}

	// ── 4. S3 uploader ──────────────────────────────────────────────────────────
	// SECURITY: credentials are loaded from environment variables; never from
	// the config file to avoid accidental secret leakage into logs/git.
	accessKey := os.Getenv("AWS_ACCESS_KEY_ID")
	secretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	uploader := archive.NewUploader(
		cfg.S3.Endpoint,
		cfg.S3.ReportsBucket,
		cfg.S3.Region,
		accessKey,
		secretKey,
		dbPool,
	)

	// ── 5. Generator ────────────────────────────────────────────────────────────
	gen := generator.New(dbPool, uploader, logger)

	// ── 6. On-demand mode: generate one report and exit ─────────────────────────
	if opts.OnDemandTenantID != "" && opts.OnDemandReportID != "" {
		logger.Info("on-demand mode",
			zap.String("tenant_id", opts.OnDemandTenantID),
			zap.String("report_id", opts.OnDemandReportID),
		)
		onDemandCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		if err := gen.ProcessByID(onDemandCtx, opts.OnDemandTenantID, opts.OnDemandReportID); err != nil {
			shutdownTracing(context.Background()) //nolint:errcheck
			return fmt.Errorf("on-demand generation: %w", err)
		}
		shutdownTracing(context.Background()) //nolint:errcheck
		return nil
	}

	// ── 7. HTTP server (health + metrics) ───────────────────────────────────────
	srv := httpserver.New(logger)

	interval := opts.ScheduleInterval
	if interval == 0 {
		interval = 5 * time.Minute
	}

	sched := scheduler.New(interval, func(ctx context.Context) error {
		return gen.ProcessPending(ctx)
	}, logger)

	// Signal handling.
	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		logger.Info("shutdown signal received")
		cancel()
	}()

	g, gctx := errgroup.WithContext(ctx)

	// HTTP server goroutine.
	g.Go(func() error {
		srv.SetReady(true)
		return srv.ListenAndServe(cfg.HTTP.ListenAddr)
	})

	// Scheduler goroutine.
	g.Go(func() error {
		sched.Run(gctx)
		return nil
	})

	// Shutdown tracer when done.
	g.Go(func() error {
		<-gctx.Done()
		tctx, tcancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer tcancel()
		return shutdownTracing(tctx)
	})

	if err := g.Wait(); err != nil {
		logger.Error("evidence service error", zap.Error(err))
		return err
	}
	return nil
}
