// Package persistence provides database persistence for the pipeline service.
// All writes use tenant RLS context (see internal/tenant/rls.go).
package persistence

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	eventspb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/events"
)

// NormalizedStore persists NormalizedEventV1 records to the normalized_events table.
type NormalizedStore struct {
	pool *pgxpool.Pool
}

// NewNormalizedStore creates a NormalizedStore backed by the given connection pool.
func NewNormalizedStore(pool *pgxpool.Pool) *NormalizedStore {
	return &NormalizedStore{pool: pool}
}

// Insert writes a normalized event row to normalized_events within a transaction
// that has the tenant RLS context set.
//
// The row is inserted only if no row with the same (tenant_id, source_event_id)
// exists (ON CONFLICT DO NOTHING) to ensure idempotency on message redelivery.
func (s *NormalizedStore) Insert(ctx context.Context, ev *eventspb.NormalizedEventV1) error {
	if ev == nil {
		return fmt.Errorf("normalized_store: nil event")
	}
	if ev.GetTenantId() == "" {
		return fmt.Errorf("normalized_store: event missing tenant_id")
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("normalized_store: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// Set Row Level Security tenant context for this transaction.
	if _, err := tx.Exec(ctx, "SELECT set_tenant_context($1)", ev.GetTenantId()); err != nil {
		return fmt.Errorf("normalized_store: set rls: %w", err)
	}

	const q = `
INSERT INTO normalized_events (
	event_id, tenant_id, source_event_id, source, category, action, outcome,
	actor_id, actor_email, actor_display_name, actor_is_privileged,
	target_id, target_type,
	source_ip, user_agent, geo_country, geo_city, geo_lat, geo_lon,
	authn_method, mfa_used, risk_score_hint, raw_s3_key,
	occurred_at, ingested_at
) VALUES (
	$1, $2, $3, $4, $5, $6, $7,
	$8, $9, $10, $11,
	$12, $13,
	$14, $15, $16, $17, $18, $19,
	$20, $21, $22, $23,
	$24, $25
)
ON CONFLICT (tenant_id, source_event_id) DO NOTHING
`
	var occurredAt, ingestedAt interface{}
	if t := ev.GetOccurredAt(); t != nil {
		occurredAt = t.AsTime()
	}
	if t := ev.GetIngestedAt(); t != nil {
		ingestedAt = t.AsTime()
	}

	_, err = tx.Exec(ctx, q,
		ev.GetEventId(), ev.GetTenantId(), ev.GetSourceEventId(), ev.GetSource(),
		ev.GetCategory().String(), ev.GetAction(), ev.GetOutcome(),
		ev.GetActorId(), ev.GetActorEmail(), ev.GetActorDisplayName(), ev.GetActorIsPrivileged(),
		ev.GetTargetId(), ev.GetTargetType(),
		ev.GetSourceIp(), ev.GetUserAgent(), ev.GetGeoCountry(), ev.GetGeoCity(),
		ev.GetGeoLat(), ev.GetGeoLon(),
		ev.GetAuthnMethod(), ev.GetMfaUsed(), ev.GetRiskScoreHint(), ev.GetRawS3Key(),
		occurredAt, ingestedAt,
	)
	if err != nil {
		return fmt.Errorf("normalized_store: insert: %w", err)
	}

	return tx.Commit(ctx)
}

