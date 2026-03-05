// Package cases provides case creation and management for the pipeline service.
// Cases group related risk signals by identity + severity + time window.
package cases

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	riskpb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/risk"
)

// Creator manages case creation and risk signal linking.
type Creator struct {
	pool *pgxpool.Pool
}

// NewCreator creates a Creator backed by the given connection pool.
func NewCreator(pool *pgxpool.Pool) *Creator {
	return &Creator{pool: pool}
}

// GetOrCreateCase finds an existing open case for the (tenant_id, identity_id,
// severity) tuple within the dedup window, or creates a new one. It returns
// the case_id to be linked on the risk signal.
//
// Idempotent: safe to call multiple times for the same signal.
func (c *Creator) GetOrCreateCase(ctx context.Context, signal *riskpb.RiskSignalV1) (string, error) {
	if signal == nil {
		return "", fmt.Errorf("cases: nil signal")
	}

	tx, err := c.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return "", fmt.Errorf("cases: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// Set RLS tenant context.
	if _, err := tx.Exec(ctx, "SELECT set_tenant_context($1)", signal.GetTenantId()); err != nil {
		return "", fmt.Errorf("cases: set rls: %w", err)
	}

	severity := severityLabel(signal)
	window := time.Now().UTC().Add(-24 * time.Hour)

	// Attempt to find an existing open case for this identity + severity within
	// the last 24 hours.
	const findQ = `
SELECT case_id FROM cases
WHERE tenant_id = $1
  AND identity_id = $2
  AND severity = $3
  AND status = 'OPEN'
  AND created_at >= $4
LIMIT 1
`
	var caseID string
	err = tx.QueryRow(ctx, findQ,
		signal.GetTenantId(), signal.GetIdentityId(), severity, window,
	).Scan(&caseID)

	if err != nil && err != pgx.ErrNoRows {
		return "", fmt.Errorf("cases: find existing: %w", err)
	}

	if err == pgx.ErrNoRows {
		// Create a new case.
		caseID = uuid.New().String()
		title := fmt.Sprintf("[%s] %s — %s", severity, signal.GetRuleName(), signal.GetIdentityId())
		const insertQ = `
INSERT INTO cases (
	case_id, tenant_id, identity_id, title, description,
	status, severity, signal_ids, created_at, updated_at, trace_id
) VALUES (
	$1, $2, $3, $4, $5,
	'OPEN', $6, $7, NOW(), NOW(), $8
)`
		_, err = tx.Exec(ctx, insertQ,
			caseID,
			signal.GetTenantId(),
			signal.GetIdentityId(),
			title,
			signal.GetDescription(),
			severity,
			[]string{signal.GetSignalId()},
			signal.GetTraceId(),
		)
		if err != nil {
			return "", fmt.Errorf("cases: insert case: %w", err)
		}
	} else {
		// Append signal_id to the existing case's signal_ids array.
		const appendQ = `
UPDATE cases
SET signal_ids = array_append(signal_ids, $1),
    updated_at  = NOW()
WHERE case_id = $2 AND tenant_id = $3
`
		if _, err := tx.Exec(ctx, appendQ,
			signal.GetSignalId(), caseID, signal.GetTenantId(),
		); err != nil {
			return "", fmt.Errorf("cases: append signal_id: %w", err)
		}
	}

	// Link the risk signal to this case.
	const linkQ = `
UPDATE risk_signals
SET case_id    = $1,
    updated_at = NOW()
WHERE signal_id = $2 AND tenant_id = $3
`
	if _, err := tx.Exec(ctx, linkQ,
		caseID, signal.GetSignalId(), signal.GetTenantId(),
	); err != nil {
		return "", fmt.Errorf("cases: link signal: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("cases: commit: %w", err)
	}
	return caseID, nil
}

// severityLabel returns a human-readable severity string for a risk signal.
func severityLabel(signal *riskpb.RiskSignalV1) string {
	switch signal.GetSeverity() {
	case riskpb.Severity_CRITICAL:
		return "CRITICAL"
	case riskpb.Severity_HIGH:
		return "HIGH"
	case riskpb.Severity_MEDIUM:
		return "MEDIUM"
	case riskpb.Severity_LOW:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}

