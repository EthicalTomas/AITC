// Package persistence provides database persistence for the pipeline service.
package persistence

import (
"context"
"fmt"

"github.com/jackc/pgx/v5"
"github.com/jackc/pgx/v5/pgxpool"

riskpb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/risk"
)

// RiskSignalStore persists RiskSignalV1 records to the risk_signals table.
type RiskSignalStore struct {
pool *pgxpool.Pool
}

// NewRiskSignalStore creates a RiskSignalStore backed by the given connection pool.
func NewRiskSignalStore(pool *pgxpool.Pool) *RiskSignalStore {
return &RiskSignalStore{pool: pool}
}

// Insert writes a risk_signal row within a transaction that has the tenant RLS
// context set. Idempotent on (tenant_id, signal_id).
func (s *RiskSignalStore) Insert(ctx context.Context, signal *riskpb.RiskSignalV1) error {
if signal == nil {
return fmt.Errorf("risk_signal_store: nil signal")
}
if signal.GetTenantId() == "" {
return fmt.Errorf("risk_signal_store: signal missing tenant_id")
}

tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
if err != nil {
return fmt.Errorf("risk_signal_store: begin tx: %w", err)
}
defer tx.Rollback(ctx) //nolint:errcheck

// Set Row Level Security tenant context.
if _, err := tx.Exec(ctx, "SELECT set_tenant_context($1)", signal.GetTenantId()); err != nil {
return fmt.Errorf("risk_signal_store: set rls: %w", err)
}

var detectedAt interface{}
if t := signal.GetDetectedAt(); t != nil {
detectedAt = t.AsTime()
}

const q = `
INSERT INTO risk_signals (
signal_id, tenant_id, identity_id, rule_id, rule_name,
severity, cas_score, confidence, description,
evidence_event_ids, detected_at, trace_id, request_id,
created_at, updated_at
) VALUES (
$1, $2, $3, $4, $5,
$6, $7, $8, $9,
$10, $11, $12, $13,
NOW(), NOW()
)
ON CONFLICT (tenant_id, signal_id) DO NOTHING
`
_, err = tx.Exec(ctx, q,
signal.GetSignalId(),
signal.GetTenantId(),
signal.GetIdentityId(),
signal.GetRuleId(),
signal.GetRuleName(),
signal.GetSeverity().String(),
signal.GetCasScore(),
signal.GetConfidence(),
signal.GetDescription(),
signal.GetEvidenceEventIds(),
detectedAt,
signal.GetTraceId(),
signal.GetRequestId(),
)
if err != nil {
return fmt.Errorf("risk_signal_store: insert: %w", err)
}
return tx.Commit(ctx)
}
