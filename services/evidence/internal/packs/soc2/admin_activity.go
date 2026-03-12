package soc2

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ethicaltomas/aitc/internal/tenant"
	"github.com/ethicaltomas/aitc/services/evidence/internal/export"
)

// AdminActivityRow represents one administrative event in the activity log.
type AdminActivityRow struct {
	ID         string `json:"id"          csv:"id"`
	Source     string `json:"source"      csv:"source"`
	Action     string `json:"action"      csv:"action"`
	Outcome    string `json:"outcome"     csv:"outcome"`
	ActorID    string `json:"actor_id"    csv:"actor_id"`
	ActorEmail string `json:"actor_email" csv:"actor_email"`
	TargetID   string `json:"target_id"   csv:"target_id"`
	TargetType string `json:"target_type" csv:"target_type"`
	OccurredAt string `json:"occurred_at" csv:"occurred_at"`
}

// GenerateAdminActivity produces a CC7.2/CC7.3 admin-activity artifact.
// It queries normalized_events where category='admin_change' to provide
// evidence of all administrative changes during the evidence period.
func GenerateAdminActivity(ctx context.Context, db *pgxpool.Pool, tenantID string, periodStart, periodEnd time.Time) (*export.Artifact, error) {
	tx, err := db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("admin_activity: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if err := tenant.SetRLS(ctx, tx, tenantID); err != nil {
		return nil, fmt.Errorf("admin_activity: set rls: %w", err)
	}

	rows, err := tx.Query(ctx,
		`SELECT id, source, action, outcome,
		        COALESCE(actor_id,''), COALESCE(actor_email,''),
		        COALESCE(target_id,''), COALESCE(target_type,''),
		        occurred_at
		   FROM normalized_events
		  WHERE tenant_id = $1
		    AND category = 'admin_change'
		    AND occurred_at BETWEEN $2 AND $3
		  ORDER BY occurred_at DESC`,
		tenantID, periodStart, periodEnd)
	if err != nil {
		return nil, fmt.Errorf("admin_activity: query: %w", err)
	}
	defer rows.Close()

	var records []AdminActivityRow
	for rows.Next() {
		var r AdminActivityRow
		var occurredAt time.Time
		if err := rows.Scan(&r.ID, &r.Source, &r.Action, &r.Outcome,
			&r.ActorID, &r.ActorEmail, &r.TargetID, &r.TargetType, &occurredAt); err != nil {
			return nil, fmt.Errorf("admin_activity: scan: %w", err)
		}
		r.OccurredAt = occurredAt.UTC().Format(time.RFC3339)
		records = append(records, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("admin_activity: rows: %w", err)
	}

	return &export.Artifact{
		ControlID:   "CC7.2",
		ControlName: "System Operations — Administrative Activity Log",
		ReportType:  "soc2",
		TenantID:    tenantID,
		PeriodStart: periodStart.UTC().Format(time.RFC3339),
		PeriodEnd:   periodEnd.UTC().Format(time.RFC3339),
		Records:     records,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

