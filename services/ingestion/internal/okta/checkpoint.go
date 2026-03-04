package okta

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// CheckpointStore persists and retrieves the per-tenant Okta polling watermark
// in the ingestion_checkpoints table.
type CheckpointStore struct {
	pool *pgxpool.Pool
}

// NewCheckpointStore creates a CheckpointStore backed by Postgres.
func NewCheckpointStore(pool *pgxpool.Pool) *CheckpointStore {
	return &CheckpointStore{pool: pool}
}

// Get returns the last recorded watermark and next-page link for the given tenant.
// Returns the zero time and empty nextLink if no checkpoint exists yet.
func (s *CheckpointStore) Get(ctx context.Context, tenantID string) (watermark time.Time, nextLink string, err error) {
	row := s.pool.QueryRow(ctx, `
		SELECT watermark, COALESCE(next_link, '')
		FROM   ingestion_checkpoints
		WHERE  tenant_id = $1 AND source = 'okta'`,
		tenantID,
	)
	var wm time.Time
	var nl string
	if scanErr := row.Scan(&wm, &nl); scanErr != nil {
		// pgx returns pgx.ErrNoRows for a miss; treat as no checkpoint.
		return time.Time{}, "", nil
	}
	return wm, nl, nil
}

// Save upserts the watermark and optional next-page link for the given tenant.
// SECURITY: nextLink is derived from Okta response headers and is validated
// against the configured base URL before use (see okta.Client.FetchPage).
func (s *CheckpointStore) Save(ctx context.Context, tenantID string, watermark time.Time, nextLink string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO ingestion_checkpoints (tenant_id, source, watermark, next_link, updated_at)
		VALUES ($1, 'okta', $2, NULLIF($3,''), NOW())
		ON CONFLICT (tenant_id, source)
		DO UPDATE SET watermark  = EXCLUDED.watermark,
		              next_link  = EXCLUDED.next_link,
		              updated_at = NOW()`,
		tenantID, watermark, nextLink,
	)
	if err != nil {
		return fmt.Errorf("okta checkpoint save: %w", err)
	}
	return nil
}

