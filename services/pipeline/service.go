// Package pipeline provides the Run() entry point for the pipeline service.
// Wiring: Kafka consumer (raw-events) → normalizer → feature extractor → CAS engine
// → case creator/correlator → Kafka producer (risk-signals).
package pipeline

import (
"context"
"fmt"
"os"
	"os/signal"
	"strings"
"syscall"
"time"

"github.com/google/uuid"
"github.com/redis/go-redis/v9"
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
kafkastream "github.com/ethicaltomas/aitc/internal/stream/kafka"
"github.com/ethicaltomas/aitc/internal/tracing"
"github.com/ethicaltomas/aitc/services/pipeline/internal/cas"
"github.com/ethicaltomas/aitc/services/pipeline/internal/cases"
"github.com/ethicaltomas/aitc/services/pipeline/internal/consumers"
"github.com/ethicaltomas/aitc/services/pipeline/internal/features"
"github.com/ethicaltomas/aitc/services/pipeline/internal/normalizer"
"github.com/ethicaltomas/aitc/services/pipeline/internal/persistence"
)

// Run starts the pipeline service. Blocks until SIGTERM/SIGINT or a fatal error.
func Run(cfg *config.Config) error {
// ── 1. Logger ─────────────────────────────────────────────────────────────
logger, err := logging.NewLogger(cfg.ServiceName)
if err != nil {
return fmt.Errorf("pipeline: init logger: %w", err)
}
defer logger.Sync() //nolint:errcheck

logger.Info("pipeline service starting",
zap.String("service", cfg.ServiceName),
zap.String("listen", cfg.HTTP.ListenAddr),
)

// ── 2. Tracing ────────────────────────────────────────────────────────────
shutdownTracing, err := tracing.Init(cfg.ServiceName)
if err != nil {
return fmt.Errorf("pipeline: init tracing: %w", err)
}

// ── 3. Postgres ───────────────────────────────────────────────────────────
initCtx, initCancel := context.WithTimeout(context.Background(), 30*time.Second)
defer initCancel()

dbPool, dbErr := postgres.NewPool(initCtx, cfg.Postgres.DSN, cfg.Postgres.MaxConns, cfg.Postgres.MinConns)
if dbErr != nil {
logger.Warn("postgres unavailable; running without persistence",
zap.Error(dbErr),
)
} else {
defer dbPool.Close()
}

// ── 4. Redis ──────────────────────────────────────────────────────────────
var rdb *redis.Client
if cfg.Redis.Addr != "" {
rdb = redis.NewClient(&redis.Options{
Addr:     cfg.Redis.Addr,
Password: cfg.Redis.Password,
DB:       cfg.Redis.DB,
})
pingCtx, pingCancel := context.WithTimeout(context.Background(), 5*time.Second)
if err := rdb.Ping(pingCtx).Err(); err != nil {
logger.Warn("redis unavailable; feature extraction disabled", zap.Error(err))
rdb.Close()
rdb = nil
}
pingCancel()
if rdb != nil {
defer rdb.Close()
}
}

// ── 5. Kafka producer (risk-signals) ──────────────────────────────────────
riskTopic := cfg.Kafka.TopicRiskSignals
if riskTopic == "" {
riskTopic = kafkastream.TopicRiskSignals
}
producer := kafkastream.NewProducer(cfg.Kafka.Brokers, riskTopic)
defer producer.Close()

// ── 6. Kafka consumer (raw-events) ────────────────────────────────────────
rawTopic := cfg.Kafka.TopicRawEvents
if rawTopic == "" {
rawTopic = kafkastream.TopicRawEvents
}
groupID := cfg.Kafka.ConsumerGroupID
if groupID == "" {
groupID = "pipeline-svc"
}
consumer := consumers.NewKafkaConsumer(cfg.Kafka.Brokers, rawTopic, groupID)
defer consumer.Close()

// ── 7. Service layer ──────────────────────────────────────────────────────
var normStore *persistence.NormalizedStore
var featStore *persistence.FeatureStore
var caseCreator *cases.Creator
var caseCorrelator *cases.Correlator

if dbPool != nil {
normStore = persistence.NewNormalizedStore(dbPool)
featStore = persistence.NewFeatureStore(dbPool)
caseCreator = cases.NewCreator(dbPool, logger)
caseCorrelator = cases.NewCorrelator(dbPool, logger)
}

var extractor *features.Extractor
if rdb != nil {
extractor = features.NewExtractor(rdb)
}

casEngine := cas.New(logger)

// ── 8. HTTP server (healthz / readyz / metrics) ───────────────────────────
srv := httpserver.New(logger)
srv.SetReady(true)

// ── 9. Signal handling + goroutines ──────────────────────────────────────
ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
defer cancel()

g, gCtx := errgroup.WithContext(ctx)

// HTTP server
g.Go(func() error {
go func() {
<-gCtx.Done()
srv.SetReady(false)
}()
return srv.ListenAndServe(cfg.HTTP.ListenAddr)
})

// Kafka consumer
g.Go(func() error {
return consumer.Run(gCtx, func(ctx context.Context, env *commonpb.EnvelopeV1) error {
return processEvent(
ctx, env, logger,
normStore, extractor, featStore,
casEngine, caseCreator, caseCorrelator,
producer,
)
})
})

<-gCtx.Done()
logger.Info("pipeline service shutting down")
cancel()

shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
defer shutdownCancel()
_ = shutdownTracing(shutdownCtx)

if err := g.Wait(); err != nil && err != context.Canceled {
return err
}
return nil
}

// processEvent runs a single raw event through the full pipeline.
func processEvent(
ctx context.Context,
env *commonpb.EnvelopeV1,
logger *zap.Logger,
normStore *persistence.NormalizedStore,
extractor *features.Extractor,
featStore *persistence.FeatureStore,
casEngine *cas.Engine,
caseCreator *cases.Creator,
caseCorrelator *cases.Correlator,
producer *kafkastream.Producer,
) error {
// 1. Normalize
ev, err := normalizer.Normalize(env)
if err != nil {
logger.Warn("pipeline: normalize failed",
zap.String("payload_type", env.GetPayloadType()),
zap.Error(err),
)
return err
}

// 2. Persist normalized event (best-effort: don't fail pipeline on DB error)
if normStore != nil {
if err := normStore.Insert(ctx, ev); err != nil {
logger.Warn("pipeline: persist normalized event failed", zap.Error(err))
}
}

// 3. Extract features from Redis
feats := &features.Features{AdminActionCount: -1}
if extractor != nil {
if f, err := extractor.Extract(ctx, ev); err != nil {
logger.Warn("pipeline: feature extraction failed", zap.Error(err))
} else {
feats = f
}
}

// Load admin action count from Postgres baseline.
if featStore != nil && feats.AdminActionCount < 0 {
count, err := featStore.GetAdminActionCount(ctx, ev.GetTenantId(), ev.GetActorId())
if err != nil {
logger.Warn("pipeline: get admin action count failed", zap.Error(err))
} else {
feats.AdminActionCount = int(count)
}
}

// 4. CAS scoring
signals, err := casEngine.Score(ctx, ev, feats)
if err != nil {
logger.Warn("pipeline: CAS scoring failed", zap.Error(err))
}

// 5. Update admin action baseline (after scoring so it doesn't affect current event)
if featStore != nil && isAdminAction(ev.GetAction()) {
if err := featStore.IncrementAdminActionCount(ctx, ev.GetTenantId(), ev.GetActorId()); err != nil {
logger.Warn("pipeline: increment admin action count failed", zap.Error(err))
}
}

// 6. Create/attach case and persist signals
if len(signals) > 0 && caseCreator != nil {
caseID, err := caseCreator.EnsureCase(ctx, ev.GetTenantId(), signals)
if err != nil {
logger.Warn("pipeline: case creation failed", zap.Error(err))
} else {
for _, sig := range signals {
sig.CaseId = caseID
}
if caseCorrelator != nil {
if err := caseCorrelator.LinkSignals(ctx, ev.GetTenantId(), caseID, signals); err != nil {
logger.Warn("pipeline: link signals failed", zap.Error(err))
}
}
}
}

// 7. Emit risk signals to Kafka
for _, sig := range signals {
if err := emitSignal(ctx, producer, sig); err != nil {
logger.Warn("pipeline: emit signal failed",
zap.String("rule_id", sig.GetRuleId()),
zap.Error(err),
)
}
}

return nil
}

// emitSignal wraps a RiskSignalV1 in an EnvelopeV1 and publishes to Kafka.
func emitSignal(ctx context.Context, producer *kafkastream.Producer, sig *riskpb.RiskSignalV1) error {
payload, err := proto.Marshal(sig)
if err != nil {
return fmt.Errorf("emitSignal: marshal risk signal: %w", err)
}

env := &commonpb.EnvelopeV1{
TenantId:      sig.GetTenantId(),
MessageId:     uuid.NewString(),
SchemaVersion: "v1",
Source:        commonpb.Source_INTERNAL,
OccurredAt:    sig.GetDetectedAt(),
IngestedAt:    timestamppb.New(time.Now().UTC()),
PayloadType:   "aitc.risk.RiskSignalV1",
Payload:       payload,
TraceId:       sig.GetTraceId(),
RequestId:     sig.GetRequestId(),
}

return producer.Publish(ctx, env)
}

func isAdminAction(action string) bool {
return strings.HasPrefix(action, "admin.")
}
