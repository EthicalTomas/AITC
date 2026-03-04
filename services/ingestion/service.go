// Package ingestion provides the public API for the ingestion service,
// wiring together pollers, archiver, publisher, and HTTP server.
// The cmd/ingestion binary calls Run() to start the service.
package ingestion

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
	ingestionm365 "github.com/ethicaltomas/aitc/services/ingestion/internal/m365"
	ingestionokta "github.com/ethicaltomas/aitc/services/ingestion/internal/okta"
	"github.com/ethicaltomas/aitc/services/ingestion/internal/publisher"
	"github.com/ethicaltomas/aitc/services/ingestion/internal/rawarchive"
)

// Run starts the ingestion service with the given config.
// It blocks until SIGTERM/SIGINT is received or a fatal error occurs.
func Run(cfg *config.Config) error {
	// ── 1. Structured JSON logger ───────────────────────────────────────────────
	logger, err := logging.NewLogger(cfg.ServiceName)
	if err != nil {
		return fmt.Errorf("init logger: %w", err)
	}
	defer logger.Sync() //nolint:errcheck

	logger.Info("ingestion service starting",
		zap.String("service", cfg.ServiceName),
		zap.Bool("mock", cfg.Ingestion.Mock),
	)

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
		logger.Warn("postgres unavailable; running without DB (archive/refs will not persist)",
			zap.Error(dbErr),
		)
	} else {
		defer dbPool.Close()
	}

	// ── 4. Kafka publisher ──────────────────────────────────────────────────────
	kafkaPublisher := publisher.NewKafkaPublisher(cfg.Kafka.Brokers)
	defer kafkaPublisher.Close() //nolint:errcheck

	// ── 5. S3/MinIO archiver ────────────────────────────────────────────────────
	// In dev/mock mode with no S3 endpoint configured, use a no-op archiver so the
	// service still starts.  raw_event_refs rows are persisted; the S3 key remains
	// predictable even though no object is written.
	//
	// SSE note: for production, configure SSE at the S3 bucket level (SSE-S3 or
	// SSE-KMS) to ensure all objects are encrypted at rest without per-request headers.
	var archiver rawarchive.Archiver
	if cfg.S3.Endpoint != "" || (!cfg.Ingestion.Mock && cfg.S3.RawBucket != "") {
		// SECURITY: credentials are loaded from environment (never from config file).
		accessKey := os.Getenv("AWS_ACCESS_KEY_ID")
		secretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
		archiver = rawarchive.NewS3Writer(
			cfg.S3.Endpoint,
			cfg.S3.RawBucket,
			cfg.S3.Region,
			accessKey,
			secretKey,
			cfg.S3.ForcePathStyle,
		)
		logger.Info("using S3/MinIO archiver",
			zap.String("endpoint", cfg.S3.Endpoint),
			zap.String("bucket", cfg.S3.RawBucket),
		)
	} else {
		archiver = rawarchive.NoopArchiver{}
		logger.Warn("S3 not configured; raw events will not be archived to object storage")
	}

	// ── 6. HTTP server (/healthz / /readyz / /metrics) ─────────────────────────
	srv := httpserver.New(logger)

	// ── 7. Wire pollers ────────────────────────────────────────────────────────
	backfillDur := time.Duration(cfg.Ingestion.BackfillHours) * time.Hour
	pollInterval := time.Duration(cfg.Ingestion.PollIntervalSeconds) * time.Second

	var oktaPoller *ingestionokta.Poller
	var m365Poller *ingestionm365.Poller

	if dbPool != nil {
		oktaPoller = ingestionokta.NewPoller(
			ingestionokta.PollerConfig{
				TenantIDs:        cfg.Ingestion.TenantIDs,
				OktaBaseURL:      cfg.Okta.BaseURL,
				OktaToken:        cfg.Okta.Token,
				BackfillDuration: backfillDur,
				PollInterval:     pollInterval,
				Mock:             cfg.Ingestion.Mock,
			},
			dbPool,
			archiver,
			kafkaPublisher,
			logger,
		)

		m365Poller = ingestionm365.NewPoller(
			ingestionm365.PollerConfig{
				TenantIDs:        cfg.Ingestion.TenantIDs,
				M365TenantID:     cfg.M365.TenantID,
				ClientID:         cfg.M365.ClientID,
				ClientSecret:     cfg.M365.ClientSecret,
				BackfillDuration: backfillDur,
				PollInterval:     pollInterval,
				Mock:             cfg.Ingestion.Mock,
			},
			dbPool,
			archiver,
			kafkaPublisher,
			logger,
		)
	} else {
		logger.Warn("DB unavailable — pollers will not start; only HTTP endpoints active")
	}

	// ── 8. Run everything in an errgroup with cancellation ──────────────────────
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	g, gCtx := errgroup.WithContext(ctx)

	// HTTP server — marks ready once all init completes.
	g.Go(func() error {
		srv.SetReady(true)
		return srv.ListenAndServe(cfg.HTTP.ListenAddr)
	})

	// Okta poller worker.
	if oktaPoller != nil {
		g.Go(func() error {
			return oktaPoller.Run(gCtx)
		})
	}

	// M365 poller worker.
	if m365Poller != nil {
		g.Go(func() error {
			return m365Poller.Run(gCtx)
		})
	}

	// Block until shutdown or fatal error.
	if err := g.Wait(); err != nil {
		logger.Error("ingestion service exiting with error", zap.Error(err))
		return err
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = shutdownTracing(shutdownCtx)

	logger.Info("ingestion service stopped")
	return nil
}
