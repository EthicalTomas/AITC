// Package m365 implements the Microsoft 365 Unified Audit Log polling worker.
// It supports live polling with watermark-based backfill, and a mock mode for
// development that reads from tools/data/sample_m365_ual_events.json.
package m365

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
	m365client "github.com/ethicaltomas/aitc/internal/m365"
	"github.com/ethicaltomas/aitc/services/ingestion/internal/rawarchive"
)

// Publisher sends an EnvelopeV1 to a message broker.
type Publisher interface {
	Publish(ctx context.Context, env *commonpb.EnvelopeV1) error
}

// PollerConfig configures the M365 UAL poller.
type PollerConfig struct {
	TenantIDs    []string
	M365TenantID string // Microsoft tenant (directory) ID for OAuth token
	// SECURITY: ClientID and ClientSecret must never be logged.
	ClientID     string
	ClientSecret string
	// ContentTypes to subscribe to (e.g. "Audit.AzureActiveDirectory", "Audit.Exchange").
	ContentTypes     []string
	BackfillDuration time.Duration
	PollInterval     time.Duration
	// Mock skips real M365 API calls and reads from SampleFilePath instead.
	Mock           bool
	SampleFilePath string
}

// Poller polls the M365 Unified Audit Log, archives events to S3, persists
// raw_event_refs, and publishes EnvelopeV1 messages to Kafka.
type Poller struct {
	cfg       PollerConfig
	client    *m365client.Client
	checkpts  *CheckpointStore
	archiver  rawarchive.Archiver
	publisher Publisher
	pool      *pgxpool.Pool
	auditLog  *audit.Writer
	logger    *zap.Logger
}

// NewPoller creates a ready-to-run M365 UAL poller.
func NewPoller(
	cfg PollerConfig,
	pool *pgxpool.Pool,
	archiver rawarchive.Archiver,
	publisher Publisher,
	logger *zap.Logger,
) *Poller {
	var client *m365client.Client
	if !cfg.Mock {
		client = m365client.NewClient(cfg.M365TenantID, cfg.ClientID, cfg.ClientSecret)
	}
	if cfg.SampleFilePath == "" {
		cfg.SampleFilePath = "tools/data/sample_m365_ual_events.json"
	}
	if cfg.BackfillDuration == 0 {
		cfg.BackfillDuration = 24 * time.Hour
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 60 * time.Second
	}
	if len(cfg.ContentTypes) == 0 {
		cfg.ContentTypes = []string{
			"Audit.AzureActiveDirectory",
			"Audit.Exchange",
			"Audit.SharePoint",
			"Audit.General",
		}
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

// Run starts the polling loop and blocks until ctx is cancelled.
func (p *Poller) Run(ctx context.Context) error {
	p.logger.Info("m365 poller starting",
		zap.Bool("mock", p.cfg.Mock),
		zap.Strings("tenants", p.cfg.TenantIDs),
	)

	ticker := time.NewTicker(p.cfg.PollInterval)
	defer ticker.Stop()

	if err := p.pollAllTenants(ctx); err != nil && ctx.Err() == nil {
		p.logger.Error("m365 poll cycle failed", zap.Error(err))
	}

	for {
		select {
		case <-ctx.Done():
			p.logger.Info("m365 poller stopping")
			return nil
		case <-ticker.C:
			if err := p.pollAllTenants(ctx); err != nil && ctx.Err() == nil {
				p.logger.Error("m365 poll cycle failed", zap.Error(err))
			}
		}
	}
}

func (p *Poller) pollAllTenants(ctx context.Context) error {
	for _, tenantID := range p.cfg.TenantIDs {
		if err := p.pollTenant(ctx, tenantID); err != nil {
			p.logger.Error("m365 poll tenant failed",
				zap.String("tenant_id", tenantID),
				zap.Error(err),
			)
		}
	}
	return nil
}

func (p *Poller) pollTenant(ctx context.Context, tenantID string) error {
	var records []m365client.UALRecord
	var err error

	if p.cfg.Mock {
		records, err = p.loadMockRecords()
	} else {
		records, err = p.fetchLiveRecords(ctx, tenantID)
	}
	if err != nil {
		return err
	}

	processed := 0
	for _, rec := range records {
		if err := p.processRecord(ctx, tenantID, rec); err != nil {
			p.logger.Error("m365 process record failed",
				zap.String("tenant_id", tenantID),
				zap.String("record_id", rec.ID),
				zap.Error(err),
			)
			continue
		}
		processed++
	}

	if processed > 0 {
		p.logger.Info("m365 poll cycle complete",
			zap.String("tenant_id", tenantID),
			zap.Int("processed", processed),
			zap.Bool("mock", p.cfg.Mock),
		)
	}
	return nil
}

// fetchLiveRecords retrieves UAL records from M365 using the stored watermark.
// M365 UAL has inherent lag (events appear with up to 90-minute delay);
// the watermark is advanced after successful processing to track lag for dashboards.
func (p *Poller) fetchLiveRecords(ctx context.Context, tenantID string) ([]m365client.UALRecord, error) {
	var watermark time.Time
	if p.checkpts != nil {
		var err error
		watermark, err = p.checkpts.Get(ctx, tenantID)
		if err != nil {
			return nil, fmt.Errorf("m365 checkpoint get: %w", err)
		}
	}

	endTime := time.Now().UTC()
	startTime := watermark
	if startTime.IsZero() {
		startTime = endTime.Add(-p.cfg.BackfillDuration)
	}

	var allRecords []m365client.UALRecord
	for _, contentType := range p.cfg.ContentTypes {
		blobs, err := p.client.ListContentBlobs(ctx, contentType, startTime, endTime)
		if err != nil {
			p.logger.Error("m365 list blobs failed",
				zap.String("content_type", contentType),
				zap.Error(err),
			)
			continue
		}
		for _, blob := range blobs {
			recs, err := p.client.FetchContent(ctx, blob.ContentURI)
			if err != nil {
				p.logger.Error("m365 fetch content failed",
					zap.String("content_id", blob.ContentID),
					zap.Error(err),
				)
				continue
			}
			allRecords = append(allRecords, recs...)
		}
	}

	if len(allRecords) > 0 && p.checkpts != nil {
		// Advance checkpoint to end of this window.
		if saveErr := p.checkpts.Save(ctx, tenantID, endTime); saveErr != nil {
			p.logger.Error("m365 checkpoint save failed", zap.Error(saveErr))
		}
	}

	return allRecords, nil
}

// loadMockRecords reads sample UAL records from the configured file.
func (p *Poller) loadMockRecords() ([]m365client.UALRecord, error) {
	data, err := os.ReadFile(p.cfg.SampleFilePath) // #nosec G304 - path from trusted config
	if err != nil {
		return nil, fmt.Errorf("m365 mock: read sample file %q: %w", p.cfg.SampleFilePath, err)
	}
	var records []m365client.UALRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("m365 mock: parse sample file: %w", err)
	}
	return records, nil
}

// processRecord archives the raw record, persists a raw_event_refs row, and publishes to Kafka.
// Idempotent via (tenant_id, source, provider_event_id) UNIQUE constraint.
func (p *Poller) processRecord(ctx context.Context, tenantID string, rec m365client.UALRecord) error {
	rawJSON, err := marshalRecord(rec)
	if err != nil {
		return err
	}

	// 1. Archive raw payload to S3/MinIO.
	s3Key, hashHex, err := p.archiver.Archive(ctx, tenantID, "m365", rec.ID, rec.CreationTime, rawJSON)
	if err != nil {
		return fmt.Errorf("m365 archive record %s: %w", rec.ID, err)
	}

	// 2. Persist raw_event_refs row (idempotent).
	if p.pool != nil {
		_, dbErr := p.pool.Exec(ctx, `
			INSERT INTO raw_event_refs
				(tenant_id, source, provider_event_id, s3_key, s3_bucket, hash_sha256, occurred_at)
			VALUES ($1, 'm365', $2, $3, $4, $5, $6)
			ON CONFLICT (tenant_id, source, provider_event_id) DO NOTHING`,
			tenantID, rec.ID, s3Key, "", hashHex, rec.CreationTime,
		)
		if dbErr != nil {
			return fmt.Errorf("m365 insert raw_event_ref: %w", dbErr)
		}
	}

	// 3. Publish EnvelopeV1 to Kafka.
	env, err := toEnvelope(tenantID, rec, rawJSON)
	if err != nil {
		return err
	}
	if err := p.publisher.Publish(ctx, env); err != nil {
		return fmt.Errorf("m365 publish envelope: %w", err)
	}

	p.logger.Debug("m365 record processed",
		zap.String("tenant_id", tenantID),
		zap.String("record_id", rec.ID),
		zap.String("operation", rec.Operation),
		zap.String("s3_key", s3Key),
	)
	return nil
}

