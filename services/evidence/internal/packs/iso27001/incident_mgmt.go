package iso27001

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ethicaltomas/aitc/internal/tenant"
	"github.com/ethicaltomas/aitc/services/evidence/internal/export"
)

// IncidentMgmtRow represents one incident management event.
type IncidentMgmtRow struct {
	CaseID     string `json:"case_id"     csv:"case_id"`
	Title      string `json:"title"       csv:"title"`
	Status     string `json:"status"      csv:"status"`
	Severity   string `json:"severity"    csv:"severity"`
	AssignedTo string `json:"assigned_to" csv:"assigned_to"`
	CreatedAt  string `json:"created_at"  csv:"created_at"`
	ClosedAt   string `json:"closed_at"   csv:"closed_at"`
}

// GenerateIncidentManagement produces an ISO 27001:2022 A.5.26 incident-management artifact.
// A.5.26 — Response to information security incidents: case records, timelines, action audit trail.
// Lists all cases opened during the period with their status and resolution.
func GenerateIncidentManagement(ctx context.Context, db *pgxpool.Pool, tenantID string, periodStart, periodEnd time.Time) (*export.Artifact, error) {
	tx, err := db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("iso_incident_mgmt: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if err := tenant.SetRLS(ctx, tx, tenantID); err != nil {
		return nil, fmt.Errorf("iso_incident_mgmt: set rls: %w", err)
	}

	rows, err := tx.Query(ctx,
		`SELECT id::text, title, status, severity,
		        COALESCE(assigned_to,''), created_at, COALESCE(closed_at::text,'')
		   FROM cases
		  WHERE tenant_id = $1
		    AND created_at BETWEEN $2 AND $3
		  ORDER BY created_at DESC`,
		tenantID, periodStart, periodEnd)
	if err != nil {
		return nil, fmt.Errorf("iso_incident_mgmt: query: %w", err)
	}
	defer rows.Close()

	var records []IncidentMgmtRow
	for rows.Next() {
		var r IncidentMgmtRow
		var createdAt time.Time
		var closedAt string
		if err := rows.Scan(&r.CaseID, &r.Title, &r.Status, &r.Severity,
			&r.AssignedTo, &createdAt, &closedAt); err != nil {
			return nil, fmt.Errorf("iso_incident_mgmt: scan: %w", err)
		}
		r.CreatedAt = createdAt.UTC().Format(time.RFC3339)
		r.ClosedAt = closedAt
		records = append(records, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iso_incident_mgmt: rows: %w", err)
	}

	return &export.Artifact{
		ControlID:   "A.5.26",
		ControlName: "ISO 27001:2022 — Response to Information Security Incidents",
		ReportType:  "iso27001",
		TenantID:    tenantID,
		PeriodStart: periodStart.UTC().Format(time.RFC3339),
		PeriodEnd:   periodEnd.UTC().Format(time.RFC3339),
		Records:     records,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

