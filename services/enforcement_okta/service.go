// Package enforcementokta provides the public API for the enforcement-okta service.
// The cmd/enforcement-okta binary calls Run() to start the service.
//
// Service flow:
//  1. Kafka consumer reads action-requests EnvelopeV1 messages.
//  2. Payload is decoded as ResponseActionV1 protobuf.
//  3. Allowlist check: disallowed actions are hard-blocked.
//  4. Idempotency check: response_actions table prevents double-execution.
//  5. Audit entry written for proposed/validated/executed/failed states.
//  6. Action dispatched to: revoke_sessions | mfa_stepup | signon_policy_adjust.
//  7. Before/after state recorded in response_actions table.
//  8. Failures routed to action-requests.dlq Kafka topic.
package enforcementokta

import (
	"context"
	"fmt"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"

	casespb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/cases"
	commonpb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/common"
	globalaudit "github.com/ethicaltomas/aitc/internal/audit"
	"github.com/ethicaltomas/aitc/internal/config"
	"github.com/ethicaltomas/aitc/internal/db/postgres"
	httpserver "github.com/ethicaltomas/aitc/internal/http/server"
	"github.com/ethicaltomas/aitc/internal/logging"
	oktaclient "github.com/ethicaltomas/aitc/internal/okta"
	"github.com/ethicaltomas/aitc/internal/policy"
	"github.com/ethicaltomas/aitc/internal/stream/kafka"
	"github.com/ethicaltomas/aitc/internal/tracing"
	"github.com/ethicaltomas/aitc/services/enforcement_okta/internal/executor"
)

// Run starts the enforcement-okta service and blocks until SIGTERM/SIGINT or a fatal error.
func Run(cfg *config.Config) error {
	// ── 1. Structured JSON logger ───────────────────────────────────────────
	logger, err := logging.NewLogger(cfg.ServiceName)
	if err != nil {
		return fmt.Errorf("init logger: %w", err)
	}
	defer logger.Sync() //nolint:errcheck

	logger.Info("enforcement-okta service starting", zap.String("service", cfg.ServiceName))

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

	// ── 6. Okta client ──────────────────────────────────────────────────────
	okta := oktaclient.NewClient(cfg.Okta.BaseURL, cfg.Okta.Token)

	// ── 7. Executor ─────────────────────────────────────────────────────────
	exec := executor.NewExecutor(dbPool, okta, pol, auditWriter, logger)

	// ── 8. HTTP server (health/ready/metrics) ───────────────────────────────
	srv := httpserver.New(logger)

	// ── 9. Kafka consumer (action-requests) ─────────────────────────────────
	topic := cfg.Kafka.TopicActionRequests
	if topic == "" {
		topic = kafka.TopicActionRequests
	}
	groupID := cfg.Kafka.ConsumerGroupID
	if groupID == "" {
		groupID = "enforcement-okta"
	}
	consumer := kafka.NewConsumer(cfg.Kafka.Brokers, topic, groupID)
	defer consumer.Close() //nolint:errcheck

	// ── 10. Graceful shutdown context ───────────────────────────────────────
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
			zap.String("topic", topic),
			zap.String("group_id", groupID),
		)
		return consumer.Consume(gCtx, func(msgCtx context.Context, env *commonpb.EnvelopeV1) error {
			return handleEnvelope(msgCtx, exec, logger, env)
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
	logger.Info("enforcement-okta service stopped")
	return nil
}

// handleEnvelope decodes an EnvelopeV1, extracts ResponseActionV1, and dispatches it.
func handleEnvelope(ctx context.Context, exec *executor.Executor, logger *zap.Logger, env *commonpb.EnvelopeV1) error {
	action := &casespb.ResponseActionV1{}
	if err := proto.Unmarshal(env.GetPayload(), action); err != nil {
		return fmt.Errorf("unmarshal ResponseActionV1: %w", err)
	}

	// Propagate envelope metadata into the action if not already set
	if action.GetTraceId() == "" {
		action.TraceId = env.GetTraceId()
	}
	if action.GetRequestId() == "" {
		action.RequestId = env.GetRequestId()
	}
	if action.GetTenantId() == "" {
		action.TenantId = env.GetTenantId()
	}

	if err := exec.Dispatch(ctx, action); err != nil {
		logger.Error("action dispatch failed",
			zap.Error(err),
			zap.String("action_id", action.GetActionId()),
			zap.String("action_type", action.GetActionType()),
			zap.String("tenant_id", action.GetTenantId()),
		)
		return err
	}
	return nil
}
