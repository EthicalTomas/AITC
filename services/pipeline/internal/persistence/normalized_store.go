// Package persistence provides storage helpers for the pipeline service.
package persistence

import (
"context"
"fmt"
"time"

"github.com/jackc/pgx/v5/pgxpool"

eventspb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/events"
)

// NormalizedStore inserts NormalizedEventV1 rows into the normalized_events table.
// It enforces tenant RLS by setting app.tenant_id on the connection before each insert.
type NormalizedStore struct {
db *pgxpool.Pool
}

// NewNormalizedStore creates a NormalizedStore backed by db.
func NewNormalizedStore(db *pgxpool.Pool) *NormalizedStore {
return &NormalizedStore{db: db}
}

// Insert persists a normalized event to the database.
// IDEMPOTENT: duplicate (tenant_id, source, source_event_id) tuples are silently skipped.
// SECURITY: sets RLS tenant context before every write.
func (s *NormalizedStore) Insert(ctx context.Context, ev *eventspb.NormalizedEventV1) error {
conn, err := s.db.Acquire(ctx)
if err != nil {
return fmt.Errorf("normalized_store: acquire conn: %w", err)
}
defer conn.Release()

// Enforce RLS — every write must be scoped to the correct tenant.
if _, err := conn.Exec(ctx,
"SELECT set_config('app.tenant_id', $1, TRUE)", ev.GetTenantId()); err != nil {
return fmt.Errorf("normalized_store: set rls tenant: %w", err)
}

var occurredAt time.Time
if ts := ev.GetOccurredAt(); ts != nil {
occurredAt = ts.AsTime()
} else {
occurredAt = time.Now().UTC()
}

_, err = conn.Exec(ctx, `
INSERT INTO normalized_events (
tenant_id, source_event_id, source, category, action, outcome,
actor_id, actor_email, actor_is_privileged,
target_id, target_type,
source_ip, user_agent,
geo_country, geo_city, geo_lat, geo_lon,
authn_method, mfa_used,
occurred_at, ingested_at
) VALUES (
$1, $2, $3, $4, $5, $6,
$7, $8, $9,
$10, $11,
$12, $13,
$14, $15, $16, $17,
$18, $19,
$20, NOW()
)
ON CONFLICT (tenant_id, source, source_event_id) DO NOTHING`,
ev.GetTenantId(), ev.GetSourceEventId(), ev.GetSource(),
ev.GetCategory().String(), ev.GetAction(), ev.GetOutcome(),
ev.GetActorId(), ev.GetActorEmail(), ev.GetActorIsPrivileged(),
ev.GetTargetId(), ev.GetTargetType(),
ev.GetSourceIp(), ev.GetUserAgent(),
ev.GetGeoCountry(), ev.GetGeoCity(), ev.GetGeoLat(), ev.GetGeoLon(),
ev.GetAuthnMethod(), ev.GetMfaUsed(),
occurredAt,
)
if err != nil {
return fmt.Errorf("normalized_store: insert: %w", err)
}
return nil
}
