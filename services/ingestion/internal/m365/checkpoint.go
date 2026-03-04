package m365

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// CheckpointStore persists and retrieves the per-tenant M365 UAL polling watermark.
type CheckpointStore struct {
	pool *pgxpool.Pool
}

// NewCheckpointStore creates a CheckpointStore backed by Postgres.
func NewCheckpointStore(pool *pgxpool.Pool) *CheckpointStore {
	return &CheckpointStore{pool: pool}
}

// Get returns the last recorded watermark for the given tenant.
// Returns the zero time if no checkpoint exists yet.
func (s *CheckpointStore) Get(ctx context.Context, tenantID string) (watermark time.Time, err error) {
	row := s.pool.QueryRow(ctx, `
		SELECT watermark
		FROM   ingestion_checkpoints
		WHERE  tenant_id = $1 AND source = 'm365'`,
		tenantID,
	)
	var wm time.Time
	if scanErr := row.Scan(&wm); scanErr != nil {
		return time.Time{}, nil
	}
	return wm, nil
}

// Save upserts the watermark for the given tenant.
func (s *CheckpointStore) Save(ctx context.Context, tenantID string, watermark time.Time) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO ingestion_checkpoints (tenant_id, source, watermark, updated_at)
		VALUES ($1, 'm365', $2, NOW())
		ON CONFLICT (tenant_id, source)
		DO UPDATE SET watermark  = EXCLUDED.watermark,
		              updated_at = NOW()`,
		tenantID, watermark,
	)
	if err != nil {
		return fmt.Errorf("m365 checkpoint save: %w", err)
	}
	return nil
}

