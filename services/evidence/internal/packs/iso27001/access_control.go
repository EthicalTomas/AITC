// Package iso27001 generates evidence artifacts for ISO/IEC 27001:2022 Annex A controls.
package iso27001

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ethicaltomas/aitc/internal/tenant"
	"github.com/ethicaltomas/aitc/services/evidence/internal/export"
)

// ISOIdentityRow represents one identity in the ISO access-control artifact.
type ISOIdentityRow struct {
	ID           string `json:"id"            csv:"id"`
	Email        string `json:"email"         csv:"email"`
	DisplayName  string `json:"display_name"  csv:"display_name"`
	Provider     string `json:"provider"      csv:"provider"`
	Roles        string `json:"roles"         csv:"roles"`
	IsPrivileged bool   `json:"is_privileged" csv:"is_privileged"`
	MFAEnrolled  bool   `json:"mfa_enrolled"  csv:"mfa_enrolled"`
	CreatedAt    string `json:"created_at"    csv:"created_at"`
}

// GenerateAccessControl produces an ISO 27001 Annex A.9.2 access-control artifact.
// A.9.2 — User access management: provisioning, de-provisioning, review of user rights.
// The artifact lists all identities with their roles, MFA status, and privileged flag.
func GenerateAccessControl(ctx context.Context, db *pgxpool.Pool, tenantID string, periodStart, periodEnd time.Time) (*export.Artifact, error) {
	tx, err := db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("iso_access_control: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if err := tenant.SetRLS(ctx, tx, tenantID); err != nil {
		return nil, fmt.Errorf("iso_access_control: set rls: %w", err)
	}

	rows, err := tx.Query(ctx,
		`SELECT id, COALESCE(email,''), COALESCE(display_name,''), provider,
		        COALESCE(array_to_string(roles,','),''), is_privileged, mfa_enrolled, created_at
		   FROM identities
		  WHERE tenant_id = $1
		    AND created_at <= $2
		  ORDER BY email`,
		tenantID, periodEnd)
	if err != nil {
		return nil, fmt.Errorf("iso_access_control: query: %w", err)
	}
	defer rows.Close()

	var records []ISOIdentityRow
	for rows.Next() {
		var r ISOIdentityRow
		var createdAt time.Time
		if err := rows.Scan(&r.ID, &r.Email, &r.DisplayName, &r.Provider,
			&r.Roles, &r.IsPrivileged, &r.MFAEnrolled, &createdAt); err != nil {
			return nil, fmt.Errorf("iso_access_control: scan: %w", err)
		}
		r.CreatedAt = createdAt.UTC().Format(time.RFC3339)
		records = append(records, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iso_access_control: rows: %w", err)
	}

	return &export.Artifact{
		ControlID:   "A.9.2",
		ControlName: "ISO 27001 — User Access Management",
		ReportType:  "iso27001",
		TenantID:    tenantID,
		PeriodStart: periodStart.UTC().Format(time.RFC3339),
		PeriodEnd:   periodEnd.UTC().Format(time.RFC3339),
		Records:     records,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

