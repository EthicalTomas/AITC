package iso27001

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ethicaltomas/aitc/internal/tenant"
	"github.com/ethicaltomas/aitc/services/evidence/internal/export"
)

// AuditLogRow represents one audit log entry for logging/monitoring evidence.
type AuditLogRow struct {
	ID          string `json:"id"           csv:"id"`
	EventType   string `json:"event_type"   csv:"event_type"`
	Actor       string `json:"actor"        csv:"actor"`
	SubjectType string `json:"subject_type" csv:"subject_type"`
	SubjectID   string `json:"subject_id"   csv:"subject_id"`
	Description string `json:"description"  csv:"description"`
	OccurredAt  string `json:"occurred_at"  csv:"occurred_at"`
}

// GenerateLoggingMonitoring produces an ISO 27001:2022 A.8.15 logging and monitoring artifact.
// A.8.15 — Logging: event logging, protection of log information, clock synchronization.
// Provides the audit trail of security-relevant events during the evidence period.
func GenerateLoggingMonitoring(ctx context.Context, db *pgxpool.Pool, tenantID string, periodStart, periodEnd time.Time) (*export.Artifact, error) {
	tx, err := db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("iso_logging_monitoring: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if err := tenant.SetRLS(ctx, tx, tenantID); err != nil {
		return nil, fmt.Errorf("iso_logging_monitoring: set rls: %w", err)
	}

	rows, err := tx.Query(ctx,
		`SELECT id::text, event_type, actor,
		        COALESCE(subject_type,''), COALESCE(subject_id,''),
		        COALESCE(description,''), occurred_at
		   FROM audit_log
		  WHERE tenant_id = $1
		    AND occurred_at BETWEEN $2 AND $3
		  ORDER BY occurred_at DESC
		  LIMIT 10000`,
		tenantID, periodStart, periodEnd)
	if err != nil {
		return nil, fmt.Errorf("iso_logging_monitoring: query: %w", err)
	}
	defer rows.Close()

	var records []AuditLogRow
	for rows.Next() {
		var r AuditLogRow
		var occurredAt time.Time
		if err := rows.Scan(&r.ID, &r.EventType, &r.Actor,
			&r.SubjectType, &r.SubjectID, &r.Description, &occurredAt); err != nil {
			return nil, fmt.Errorf("iso_logging_monitoring: scan: %w", err)
		}
		r.OccurredAt = occurredAt.UTC().Format(time.RFC3339)
		records = append(records, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iso_logging_monitoring: rows: %w", err)
	}

	return &export.Artifact{
		ControlID:   "A.8.15",
		ControlName: "ISO 27001:2022 — Logging and Monitoring",
		ReportType:  "iso27001",
		TenantID:    tenantID,
		PeriodStart: periodStart.UTC().Format(time.RFC3339),
		PeriodEnd:   periodEnd.UTC().Format(time.RFC3339),
		Records:     records,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

