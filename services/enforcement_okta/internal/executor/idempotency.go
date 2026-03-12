package executor

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ethicaltomas/aitc/internal/tenant"
)

// checkIdempotency queries the response_actions table for an existing row with the
// given idempotency_key. Returns true if the action has already been executed
// (status = 'executed'), meaning the caller should skip re-execution.
//
// SECURITY: Uses RLS — tenant_id must be set before querying.
func checkIdempotency(ctx context.Context, db *pgxpool.Pool, tenantID, idempotencyKey string) (bool, error) {
	if tenantID == "" {
		return false, fmt.Errorf("checkIdempotency: tenant_id is required")
	}
	if idempotencyKey == "" {
		return false, fmt.Errorf("checkIdempotency: idempotency_key is required")
	}

	tx, err := db.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("checkIdempotency: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := tenant.SetRLS(ctx, tx, tenantID); err != nil {
		return false, fmt.Errorf("checkIdempotency: set RLS: %w", err)
	}

	var status string
	err = tx.QueryRow(ctx,
		`SELECT status FROM response_actions WHERE tenant_id = $1 AND idempotency_key = $2 LIMIT 1`,
		tenantID, idempotencyKey,
	).Scan(&status)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("checkIdempotency: query: %w", err)
	}

	// Only skip if the action has successfully completed
	return status == "executed", nil
}

