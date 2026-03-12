package soc2

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ethicaltomas/aitc/internal/tenant"
	"github.com/ethicaltomas/aitc/services/evidence/internal/export"
)

// MFARow represents one identity's MFA enrolment status.
type MFARow struct {
	ID          string `json:"id"           csv:"id"`
	Email       string `json:"email"        csv:"email"`
	Provider    string `json:"provider"     csv:"provider"`
	MFAEnrolled bool   `json:"mfa_enrolled" csv:"mfa_enrolled"`
	IsPrivileged bool  `json:"is_privileged" csv:"is_privileged"`
	UpdatedAt   string `json:"updated_at"   csv:"updated_at"`
}

// GenerateMFACoverage produces a CC6.1/CC6.3 MFA coverage artifact.
// It lists every identity and whether they have MFA enrolled, which is
// evidence that multi-factor authentication is enforced for system access.
func GenerateMFACoverage(ctx context.Context, db *pgxpool.Pool, tenantID string, periodStart, periodEnd time.Time) (*export.Artifact, error) {
	tx, err := db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("mfa_coverage: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if err := tenant.SetRLS(ctx, tx, tenantID); err != nil {
		return nil, fmt.Errorf("mfa_coverage: set rls: %w", err)
	}

	rows, err := tx.Query(ctx,
		`SELECT id, COALESCE(email,''), provider, mfa_enrolled, is_privileged, updated_at
		   FROM identities
		  WHERE tenant_id = $1
		    AND updated_at <= $2
		  ORDER BY email`,
		tenantID, periodEnd)
	if err != nil {
		return nil, fmt.Errorf("mfa_coverage: query: %w", err)
	}
	defer rows.Close()

	var records []MFARow
	for rows.Next() {
		var r MFARow
		var updatedAt time.Time
		if err := rows.Scan(&r.ID, &r.Email, &r.Provider, &r.MFAEnrolled, &r.IsPrivileged, &updatedAt); err != nil {
			return nil, fmt.Errorf("mfa_coverage: scan: %w", err)
		}
		r.UpdatedAt = updatedAt.UTC().Format(time.RFC3339)
		records = append(records, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("mfa_coverage: rows: %w", err)
	}

	return &export.Artifact{
		ControlID:   "CC6.3",
		ControlName: "Logical and Physical Access Controls — MFA Coverage",
		ReportType:  "soc2",
		TenantID:    tenantID,
		PeriodStart: periodStart.UTC().Format(time.RFC3339),
		PeriodEnd:   periodEnd.UTC().Format(time.RFC3339),
		Records:     records,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

