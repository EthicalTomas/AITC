// Package pipeline provides the public API for the pipeline service.
// The cmd/pipeline binary calls Run() to start the service.
//
// Pipeline flow:
//  1. Kafka consumer reads raw-events EnvelopeV1 messages.
//  2. Normalizer parses the payload into NormalizedEventV1.
//  3. PII minimizer redacts sensitive fields for persistence.
//  4. NormalizedStore persists the event to Postgres (normalized_events table).
//  5. FeatureExtractor updates Redis counters and geo checkpoints.
//  6. CAS Engine evaluates detection rules and produces RiskSignalV1 messages.
//  7. RiskSignalStore persists each signal to Postgres (risk_signals table).
//  8. Kafka producer emits each signal to the risk-signals topic.
//  9. CaseCreator groups signals into cases (cases table).
package pipeline

import (
"context"
"fmt"
"os/signal"
"syscall"
"time"

"go.uber.org/zap"
"golang.org/x/sync/errgroup"
"google.golang.org/protobuf/proto"
"google.golang.org/protobuf/types/known/timestamppb"

commonpb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/common"
riskpb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/risk"
"github.com/ethicaltomas/aitc/internal/config"
"github.com/ethicaltomas/aitc/internal/db/postgres"
httpserver "github.com/ethicaltomas/aitc/internal/http/server"
"github.com/ethicaltomas/aitc/internal/logging"
"github.com/ethicaltomas/aitc/internal/stream/kafka"
"github.com/ethicaltomas/aitc/internal/tracing"
"github.com/ethicaltomas/aitc/services/pipeline/internal/cas"
"github.com/ethicaltomas/aitc/services/pipeline/internal/cases"
"github.com/ethicaltomas/aitc/services/pipeline/internal/consumers"
"github.com/ethicaltomas/aitc/services/pipeline/internal/features"
"github.com/ethicaltomas/aitc/services/pipeline/internal/normalizer"
"github.com/ethicaltomas/aitc/services/pipeline/internal/persistence"

"github.com/google/uuid"
)

// Run starts the pipeline service and blocks until SIGTERM/SIGINT or a fatal error.
func Run(cfg *config.Config) error {
// ── 1. Structured JSON logger ───────────────────────────────────────────────
logger, err := logging.NewLogger(cfg.ServiceName)
if err != nil {
return fmt.Errorf("init logger: %w", err)
}
defer logger.Sync() //nolint:errcheck

logger.Info("pipeline service starting", zap.String("service", cfg.ServiceName))

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
logger.Warn("postgres unavailable; running in degraded mode (no DB persistence)",
zap.Error(dbErr))
} else {
defer dbPool.Close()
}

// ── 4. Redis feature store ──────────────────────────────────────────────────
var featureStore *persistence.FeatureStore
if cfg.Redis.Addr != "" {
featureStore = persistence.NewFeatureStore(cfg.Redis.Addr, cfg.Redis.Password, cfg.Redis.DB)
defer featureStore.Close() //nolint:errcheck
logger.Info("redis feature store connected", zap.String("addr", cfg.Redis.Addr))
} else {
logger.Warn("redis not configured; feature extraction will run in degraded mode")
}

// ── 5. Persistence stores ───────────────────────────────────────────────────
var normalizedStore *persistence.NormalizedStore
var signalStore *persistence.RiskSignalStore
var caseCreator *cases.Creator
if dbPool != nil {
normalizedStore = persistence.NewNormalizedStore(dbPool)
signalStore = persistence.NewRiskSignalStore(dbPool)
caseCreator = cases.NewCreator(dbPool)
}

// ── 6. CAS engine ──────────────────────────────────────────────────────────
casEngine := cas.NewEngine(logger)

// ── 7. Kafka risk-signals producer ─────────────────────────────────────────
riskTopic := cfg.Kafka.TopicRiskSignals
if riskTopic == "" {
riskTopic = kafka.TopicRiskSignals
}
riskProducer := kafka.NewProducer(cfg.Kafka.Brokers, riskTopic)
defer riskProducer.Close() //nolint:errcheck

// ── 8. Kafka raw-events consumer ───────────────────────────────────────────
rawTopic := cfg.Kafka.TopicRawEvents
if rawTopic == "" {
rawTopic = kafka.TopicRawEvents
}
groupID := cfg.Kafka.ConsumerGroupID
if groupID == "" {
groupID = "pipeline"
}
consumer := consumers.NewKafkaConsumer(cfg.Kafka.Brokers, rawTopic, groupID)
defer consumer.Close() //nolint:errcheck

// ── 9. HTTP server (/healthz / /readyz / /metrics) ─────────────────────────
srv := httpserver.New(logger)

// ── 10. Signal handling + errgroup ─────────────────────────────────────────
ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
defer stop()

g, gctx := errgroup.WithContext(ctx)

// HTTP server goroutine
g.Go(func() error {
srv.SetReady(true)
return srv.ListenAndServe(cfg.HTTP.ListenAddr)
})

// Consumer goroutine
g.Go(func() error {
return consumer.Run(gctx, func(ctx context.Context, env *commonpb.EnvelopeV1) error {
return handleEnvelope(
ctx, logger, env,
normalizedStore, featureStore, signalStore, caseCreator,
casEngine, riskProducer,
)
})
})

// Context cancellation goroutine
g.Go(func() error {
<-gctx.Done()
srv.SetReady(false)
return nil
})

if err := g.Wait(); err != nil {
logger.Error("pipeline exiting with error", zap.Error(err))
}

// Shutdown tracing
shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
_ = shutdownTracing(shutdownCtx)

logger.Info("pipeline service stopped")
return nil
}

// handleEnvelope processes a single EnvelopeV1 through the full pipeline.
func handleEnvelope(
ctx context.Context,
logger *zap.Logger,
env *commonpb.EnvelopeV1,
normalizedStore *persistence.NormalizedStore,
featureStore *persistence.FeatureStore,
signalStore *persistence.RiskSignalStore,
caseCreator *cases.Creator,
casEngine *cas.Engine,
riskProducer *kafka.Producer,
) error {
// 1. Normalize
ev, err := normalizer.Normalize(env)
if err != nil {
logger.Warn("normalize: skipping unsupported envelope",
zap.String("source", env.GetSource().String()),
zap.Error(err))
return nil // not a retryable error; skip to avoid DLQ spam
}

// 2. PII minimize before persistence
evMinimized := normalizer.MinimizePII(ev)

// 3. Persist normalized event
if normalizedStore != nil {
if err := normalizedStore.Insert(ctx, evMinimized); err != nil {
logger.Error("persist normalized event failed", zap.Error(err),
zap.String("event_id", evMinimized.GetEventId()))
// Non-fatal: continue pipeline even if DB is unavailable.
}
}

// 4. Extract features (Redis)
feats, featErr := features.Extract(ctx, featureStore, ev)
if featErr != nil {
logger.Warn("feature extraction degraded", zap.Error(featErr))
}

// 5. CAS scoring
signals, err := casEngine.Score(ctx, ev, feats)
if err != nil {
logger.Error("CAS scoring failed", zap.Error(err))
return err
}

// 6. Persist signals + emit Kafka messages + create cases
for _, signal := range signals {
// 6a. Persist risk signal
if signalStore != nil {
if err := signalStore.Insert(ctx, signal); err != nil {
logger.Error("persist risk signal failed", zap.Error(err),
zap.String("signal_id", signal.GetSignalId()))
}
}

// 6b. Emit to risk-signals Kafka topic
if err := emitRiskSignal(ctx, riskProducer, env, signal); err != nil {
logger.Error("emit risk signal failed", zap.Error(err),
zap.String("signal_id", signal.GetSignalId()))
}

// 6c. Create/attach case
if caseCreator != nil {
caseID, err := caseCreator.GetOrCreateCase(ctx, signal)
if err != nil {
logger.Error("case creation failed", zap.Error(err),
zap.String("signal_id", signal.GetSignalId()))
} else {
logger.Info("case linked",
zap.String("case_id", caseID),
zap.String("signal_id", signal.GetSignalId()))
}
}

logger.Info("risk signal emitted",
zap.String("signal_id", signal.GetSignalId()),
zap.String("rule_id", signal.GetRuleId()),
zap.Float64("cas_score", signal.GetCasScore()),
)
}

return nil
}

// emitRiskSignal wraps a RiskSignalV1 in an EnvelopeV1 and publishes it to Kafka.
func emitRiskSignal(ctx context.Context, producer *kafka.Producer, srcEnv *commonpb.EnvelopeV1, signal *riskpb.RiskSignalV1) error {
payload, err := proto.Marshal(signal)
if err != nil {
return fmt.Errorf("marshal risk signal: %w", err)
}
env := &commonpb.EnvelopeV1{
TenantId:      signal.GetTenantId(),
MessageId:     uuid.New().String(),
SchemaVersion: "v1",
Source:        commonpb.Source_INTERNAL,
OccurredAt:    signal.GetDetectedAt(),
IngestedAt:    timestamppb.Now(),
PayloadType:   "aitc.risk.RiskSignalV1",
Payload:       payload,
TraceId:       signal.GetTraceId(),
RequestId:     srcEnv.GetRequestId(),
}
return producer.Publish(ctx, env)
}
