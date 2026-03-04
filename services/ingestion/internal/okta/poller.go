// Package okta implements the Okta System Log polling worker for the ingestion service.
// It supports live polling, per-tenant checkpoints, backfill, and a mock mode for
// development that reads from tools/data/sample_okta_events.json.
package okta

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	commonpb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/common"
	"github.com/ethicaltomas/aitc/internal/audit"
	oktaclient "github.com/ethicaltomas/aitc/internal/okta"
	"github.com/ethicaltomas/aitc/services/ingestion/internal/rawarchive"
)

// Publisher sends an EnvelopeV1 to a message broker.
type Publisher interface {
	Publish(ctx context.Context, env *commonpb.EnvelopeV1) error
}

// PollerConfig configures the Okta poller.
type PollerConfig struct {
	// TenantIDs is the list of tenants this poller processes.
	TenantIDs []string
	// OktaBaseURL and OktaToken identify the Okta org.
	// SECURITY: OktaToken must never be logged.
	OktaBaseURL string
	OktaToken   string
	// BackfillDuration is how far back to look when no checkpoint exists.
	BackfillDuration time.Duration
	// PollInterval is the time to wait between poll cycles.
	PollInterval time.Duration
	// Mock skips real Okta API calls and reads from SampleFilePath instead.
	Mock           bool
	SampleFilePath string // default: tools/data/sample_okta_events.json
}

// Poller polls the Okta System Log API per tenant, archives raw events to S3,
// persists raw_event_refs rows, publishes EnvelopeV1 messages to Kafka,
// and checkpoints progress in Postgres.
type Poller struct {
	cfg        PollerConfig
	client     *oktaclient.Client
	checkpts   *CheckpointStore
	archiver   rawarchive.Archiver
	publisher  Publisher
	pool       *pgxpool.Pool
	auditLog   *audit.Writer
	logger     *zap.Logger
}

// NewPoller creates a ready-to-run Okta poller.
func NewPoller(
	cfg PollerConfig,
	pool *pgxpool.Pool,
	archiver rawarchive.Archiver,
	publisher Publisher,
	logger *zap.Logger,
) *Poller {
	var client *oktaclient.Client
	if !cfg.Mock {
		client = oktaclient.NewClient(cfg.OktaBaseURL, cfg.OktaToken)
	}
	if cfg.SampleFilePath == "" {
		cfg.SampleFilePath = "tools/data/sample_okta_events.json"
	}
	if cfg.BackfillDuration == 0 {
		cfg.BackfillDuration = 24 * time.Hour
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 60 * time.Second
	}

	var checkpts *CheckpointStore
	var auditWriter *audit.Writer
	if pool != nil {
		checkpts = NewCheckpointStore(pool)
		auditWriter = audit.NewWriter(pool)
	}

	return &Poller{
		cfg:       cfg,
		client:    client,
		checkpts:  checkpts,
		archiver:  archiver,
		publisher: publisher,
		pool:      pool,
		auditLog:  auditWriter,
		logger:    logger,
	}
}

// Run starts the polling loop. It returns when ctx is cancelled.
func (p *Poller) Run(ctx context.Context) error {
	p.logger.Info("okta poller starting",
		zap.Bool("mock", p.cfg.Mock),
		zap.Strings("tenants", p.cfg.TenantIDs),
	)

	ticker := time.NewTicker(p.cfg.PollInterval)
	defer ticker.Stop()

	// Poll once immediately, then on tick.
	if err := p.pollAllTenants(ctx); err != nil && ctx.Err() == nil {
		p.logger.Error("okta poll cycle failed", zap.Error(err))
	}

	for {
		select {
		case <-ctx.Done():
			p.logger.Info("okta poller stopping")
			return nil
		case <-ticker.C:
			if err := p.pollAllTenants(ctx); err != nil && ctx.Err() == nil {
				p.logger.Error("okta poll cycle failed", zap.Error(err))
			}
		}
	}
}

func (p *Poller) pollAllTenants(ctx context.Context) error {
	for _, tenantID := range p.cfg.TenantIDs {
		if err := p.pollTenant(ctx, tenantID); err != nil {
			p.logger.Error("okta poll tenant failed",
				zap.String("tenant_id", tenantID),
				zap.Error(err),
			)
		}
	}
	return nil
}

func (p *Poller) pollTenant(ctx context.Context, tenantID string) error {
	var events []oktaclient.SystemLogEvent
	var err error

	if p.cfg.Mock {
		events, err = p.loadMockEvents()
	} else {
		events, err = p.fetchLiveEvents(ctx, tenantID)
	}
	if err != nil {
		return err
	}

	processed := 0
	for _, ev := range events {
		if err := p.processEvent(ctx, tenantID, ev); err != nil {
			p.logger.Error("okta process event failed",
				zap.String("tenant_id", tenantID),
				zap.String("event_id", ev.UUID),
				zap.Error(err),
			)
			continue
		}
		processed++
	}

	if processed > 0 {
		p.logger.Info("okta poll cycle complete",
			zap.String("tenant_id", tenantID),
			zap.Int("processed", processed),
			zap.Bool("mock", p.cfg.Mock),
		)
	}
	return nil
}

// fetchLiveEvents polls the Okta System Log API using the stored checkpoint.
func (p *Poller) fetchLiveEvents(ctx context.Context, tenantID string) ([]oktaclient.SystemLogEvent, error) {
	var watermark time.Time
	var nextLink string

	if p.checkpts != nil {
		var err error
		watermark, nextLink, err = p.checkpts.Get(ctx, tenantID)
		if err != nil {
			return nil, fmt.Errorf("okta fetch checkpoint: %w", err)
		}
	}

	var (
		events      []oktaclient.SystemLogEvent
		newNextLink string
		err         error
	)

	if nextLink != "" {
		// Resume pagination from where we left off.
		events, newNextLink, err = p.client.FetchPage(ctx, nextLink)
	} else {
		since := watermark
		if since.IsZero() {
			// Backfill: start from BackfillDuration ago.
			since = time.Now().UTC().Add(-p.cfg.BackfillDuration)
		}
		events, newNextLink, err = p.client.PollSystemLog(ctx, since, 100)
	}
	if err != nil {
		return nil, fmt.Errorf("okta poll: %w", err)
	}

	// Advance the checkpoint to the timestamp of the last received event.
	if len(events) > 0 && p.checkpts != nil {
		newWatermark := events[len(events)-1].Published
		if saveErr := p.checkpts.Save(ctx, tenantID, newWatermark, newNextLink); saveErr != nil {
			p.logger.Error("okta checkpoint save failed", zap.Error(saveErr))
		}
	}

	return events, nil
}

// loadMockEvents reads sample events from the configured sample file.
func (p *Poller) loadMockEvents() ([]oktaclient.SystemLogEvent, error) {
	data, err := os.ReadFile(p.cfg.SampleFilePath) // #nosec G304 - path from trusted config
	if err != nil {
		return nil, fmt.Errorf("okta mock: read sample file %q: %w", p.cfg.SampleFilePath, err)
	}
	var events []oktaclient.SystemLogEvent
	if err := json.Unmarshal(data, &events); err != nil {
		return nil, fmt.Errorf("okta mock: parse sample file: %w", err)
	}
	return events, nil
}

// processEvent archives the raw event, persists a raw_event_refs row, and publishes to Kafka.
// Deduplicated by (tenant_id, source, provider_event_id) via UNIQUE constraint in Postgres.
func (p *Poller) processEvent(ctx context.Context, tenantID string, ev oktaclient.SystemLogEvent) error {
	rawJSON, err := marshalEvent(ev)
	if err != nil {
		return err
	}

	// 1. Archive raw payload to S3/MinIO.
	s3Key, hashHex, err := p.archiver.Archive(ctx, tenantID, "okta", ev.UUID, ev.Published, rawJSON)
	if err != nil {
		return fmt.Errorf("okta archive event %s: %w", ev.UUID, err)
	}

	// 2. Persist raw_event_refs row (ON CONFLICT DO NOTHING for idempotency).
	// SECURITY: Row-level security is enforced by setting app.tenant_id.
	if p.pool != nil {
		_, dbErr := p.pool.Exec(ctx, `
			INSERT INTO raw_event_refs
				(tenant_id, source, provider_event_id, s3_key, s3_bucket, hash_sha256, occurred_at)
			VALUES ($1, 'okta', $2, $3, $4, $5, $6)
			ON CONFLICT (tenant_id, source, provider_event_id) DO NOTHING`,
			tenantID, ev.UUID, s3Key, "", hashHex, ev.Published,
		)
		if dbErr != nil {
			return fmt.Errorf("okta insert raw_event_ref: %w", dbErr)
		}
	}

	// 3. Build and publish EnvelopeV1 to Kafka.
	env, err := toEnvelope(tenantID, ev, rawJSON)
	if err != nil {
		return err
	}
	if err := p.publisher.Publish(ctx, env); err != nil {
		return fmt.Errorf("okta publish envelope: %w", err)
	}

	p.logger.Debug("okta event processed",
		zap.String("tenant_id", tenantID),
		zap.String("event_id", ev.UUID),
		zap.String("event_type", ev.EventType),
		zap.String("s3_key", s3Key),
	)
	return nil
}

