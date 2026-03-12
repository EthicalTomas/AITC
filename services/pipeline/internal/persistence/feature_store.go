// Package persistence — feature (baseline) persistence.
package persistence

import (
"context"
"fmt"

"github.com/jackc/pgx/v5/pgxpool"
)

// FeatureStore records per-identity rolling baselines in Postgres.
// These baselines are used by CAS rules that require historical context
// (e.g., rare admin action detection).
type FeatureStore struct {
db *pgxpool.Pool
}

// NewFeatureStore creates a FeatureStore backed by db.
func NewFeatureStore(db *pgxpool.Pool) *FeatureStore {
return &FeatureStore{db: db}
}

// IncrementAdminActionCount increments the admin_action_count for an identity.
// The record is created if it does not exist (upsert).
// SECURITY: sets RLS tenant context before every write.
func (s *FeatureStore) IncrementAdminActionCount(ctx context.Context, tenantID, actorID string) error {
conn, err := s.db.Acquire(ctx)
if err != nil {
return fmt.Errorf("feature_store: acquire conn: %w", err)
}
defer conn.Release()

if _, err := conn.Exec(ctx,
"SELECT set_config('app.tenant_id', $1, TRUE)", tenantID); err != nil {
return fmt.Errorf("feature_store: set rls tenant: %w", err)
}

_, err = conn.Exec(ctx, `
INSERT INTO identity_baselines (tenant_id, actor_id, admin_action_count, last_admin_action_at)
VALUES ($1, $2, 1, NOW())
ON CONFLICT (tenant_id, actor_id) DO UPDATE
SET admin_action_count   = identity_baselines.admin_action_count + 1,
    last_admin_action_at = NOW(),
    updated_at           = NOW()`,
tenantID, actorID,
)
if err != nil {
return fmt.Errorf("feature_store: increment admin_action_count: %w", err)
}
return nil
}

// GetAdminActionCount returns the rolling admin action count for an identity.
// Returns 0 if no record exists.
// SECURITY: sets RLS tenant context before every read.
func (s *FeatureStore) GetAdminActionCount(ctx context.Context, tenantID, actorID string) (int64, error) {
conn, err := s.db.Acquire(ctx)
if err != nil {
return 0, fmt.Errorf("feature_store: acquire conn: %w", err)
}
defer conn.Release()

if _, err := conn.Exec(ctx,
"SELECT set_config('app.tenant_id', $1, TRUE)", tenantID); err != nil {
return 0, fmt.Errorf("feature_store: set rls tenant: %w", err)
}

var count int64
err = conn.QueryRow(ctx,
`SELECT admin_action_count FROM identity_baselines WHERE tenant_id=$1 AND actor_id=$2`,
tenantID, actorID,
).Scan(&count)
if err != nil {
// No row = count of 0
return 0, nil
}
return count, nil
}
