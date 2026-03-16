// Package controlplane provides the public API for the controlplane service.
// The cmd/controlplane binary calls Run() to start the service.
//
// Service flow:
//  1. Kafka consumer reads risk-signals EnvelopeV1 messages.
//  2. Payload is decoded as RiskSignalV1 protobuf.
//  3. Autonomy state is loaded for the tenant (learning mode, autopilot flag).
//  4. Policy validator enforces disallowed list, learning mode gate, autopilot gate.
//  5. Recommendations are published to action-recommendations topic.
//  6. If autopilot is enabled and circuit is closed, validated requests are
//     published to action-requests topic for enforcement-okta consumption.
//  7. All policy decisions are written to the audit log (Step 0.4).
package controlplane

import (
	"context"
	"fmt"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"

	commonpb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/common"
	riskpb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/risk"
	globalaudit "github.com/ethicaltomas/aitc/internal/audit"
	"github.com/ethicaltomas/aitc/internal/config"
	"github.com/ethicaltomas/aitc/internal/db/postgres"
	httpserver "github.com/ethicaltomas/aitc/internal/http/server"
	"github.com/ethicaltomas/aitc/internal/logging"
	"github.com/ethicaltomas/aitc/internal/policy"
	"github.com/ethicaltomas/aitc/internal/stream/kafka"
	"github.com/ethicaltomas/aitc/internal/tracing"
	ctraudit "github.com/ethicaltomas/aitc/services/controlplane/internal/audit"
	"github.com/ethicaltomas/aitc/services/controlplane/internal/autonomy"
	ctrpolicy "github.com/ethicaltomas/aitc/services/controlplane/internal/policy"
	"github.com/ethicaltomas/aitc/services/controlplane/internal/recommendations"
)

// Run starts the controlplane service and blocks until SIGTERM/SIGINT or a fatal error.
func Run(cfg *config.Config) error {
	// ── 1. Structured JSON logger ───────────────────────────────────────────
	logger, err := logging.NewLogger(cfg.ServiceName)
	if err != nil {
		return fmt.Errorf("init logger: %w", err)
	}
	defer logger.Sync() //nolint:errcheck

	logger.Info("controlplane service starting", zap.String("service", cfg.ServiceName))

	// ── 2. OpenTelemetry tracing ────────────────────────────────────────────
	shutdownTracing, err := tracing.Init(cfg.ServiceName)
	if err != nil {
		return fmt.Errorf("init tracing: %w", err)
	}

	// ── 3. Postgres connection pool ─────────────────────────────────────────
	initCtx, initCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer initCancel()

	dbPool, err := postgres.NewPool(initCtx, cfg.Postgres.DSN, cfg.Postgres.MaxConns, cfg.Postgres.MinConns)
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	defer dbPool.Close()

	// ── 4. Policy loader ────────────────────────────────────────────────────
	pol, err := policy.LoadPolicies(cfg.Policy.AllowlistPath, cfg.Policy.DisallowedPath)
	if err != nil {
		return fmt.Errorf("load policies: %w", err)
	}

	// ── 5. Audit writer ─────────────────────────────────────────────────────
	auditWriter := globalaudit.NewWriter(dbPool)
	recorder := ctraudit.NewRecorder(auditWriter)

	// ── 6. Autonomy state repo ──────────────────────────────────────────────
	stateRepo := autonomy.NewTenantStateRepo(dbPool)

	// ── 7. Circuit breaker (autopilot safety net) ───────────────────────────
	// Trip after 5 failures in a 5-minute window; reset after 10 minutes.
	cb := autonomy.NewCircuitBreaker(5, 5*time.Minute, 10*time.Minute)

	// ── 8. Policy validator ─────────────────────────────────────────────────
	validator := ctrpolicy.NewValidator(pol)

	// ── 9. Kafka producers ──────────────────────────────────────────────────
	recTopic := cfg.Kafka.TopicActionRecs
	if recTopic == "" {
		recTopic = kafka.TopicActionRecommendations
	}
	reqTopic := cfg.Kafka.TopicActionRequests
	if reqTopic == "" {
		reqTopic = kafka.TopicActionRequests
	}

	recProducer := kafka.NewProducer(cfg.Kafka.Brokers, recTopic)
	defer recProducer.Close() //nolint:errcheck

	reqProducer := kafka.NewProducer(cfg.Kafka.Brokers, reqTopic)
	defer reqProducer.Close() //nolint:errcheck

	// ── 10. Recommendation generator ────────────────────────────────────────
	gen := recommendations.NewGenerator(validator, recProducer, reqProducer, stateRepo, cb, logger)

	// ── 11. HTTP server (healthz, readyz, metrics) ───────────────────────────
	srv := httpserver.New(logger)

	// ── 12. Kafka consumer (risk-signals) ───────────────────────────────────
	riskTopic := cfg.Kafka.TopicRiskSignals
	if riskTopic == "" {
		riskTopic = kafka.TopicRiskSignals
	}
	groupID := cfg.Kafka.ConsumerGroupID
	if groupID == "" {
		groupID = "controlplane"
	}
	consumer := kafka.NewConsumer(cfg.Kafka.Brokers, riskTopic, groupID)
	defer consumer.Close() //nolint:errcheck

	// ── 13. Graceful shutdown context ───────────────────────────────────────
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	g, gCtx := errgroup.WithContext(ctx)

	// HTTP server goroutine
	g.Go(func() error {
		srv.SetReady(true)
		return srv.ListenAndServe(cfg.HTTP.ListenAddr)
	})

	// Kafka consumer goroutine
	g.Go(func() error {
		logger.Info("kafka consumer starting",
			zap.String("topic", riskTopic),
			zap.String("group_id", groupID),
		)
		return consumer.Consume(gCtx, func(msgCtx context.Context, env *commonpb.EnvelopeV1) error {
			return handleEnvelope(msgCtx, gen, recorder, logger, env)
		})
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
	logger.Info("controlplane service stopped")
	return nil
}

// handleEnvelope decodes a RiskSignalV1 from an EnvelopeV1 and drives recommendation generation.
func handleEnvelope(
	ctx context.Context,
	gen *recommendations.Generator,
	recorder *ctraudit.Recorder,
	logger *zap.Logger,
	env *commonpb.EnvelopeV1,
) error {
	signal := &riskpb.RiskSignalV1{}
	if err := proto.Unmarshal(env.GetPayload(), signal); err != nil {
		return fmt.Errorf("unmarshal RiskSignalV1: %w", err)
	}

	// Propagate envelope metadata if not set on the signal.
	if signal.GetTraceId() == "" {
		signal.TraceId = env.GetTraceId()
	}
	if signal.GetRequestId() == "" {
		signal.RequestId = env.GetRequestId()
	}
	if signal.GetTenantId() == "" {
		signal.TenantId = env.GetTenantId()
	}

	if err := gen.Generate(ctx, signal); err != nil {
		logger.Error("recommendation generation failed",
			zap.Error(err),
			zap.String("signal_id", signal.GetSignalId()),
			zap.String("tenant_id", signal.GetTenantId()),
		)
		// Record audit event for the failure
		_ = recorder.RecordAutonomyStateChange(ctx, signal.GetTenantId(), "controlplane",
			fmt.Sprintf("recommendation generation failed for signal %s: %v", signal.GetSignalId(), err),
			nil, nil,
		)
		return err
	}
	return nil
}
