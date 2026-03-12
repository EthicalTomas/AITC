// Package soc2 generates evidence artifacts for SOC 2 Trust Service Criteria.
// Each file in this package corresponds to one control area.
package soc2

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ethicaltomas/aitc/internal/tenant"
	"github.com/ethicaltomas/aitc/services/evidence/internal/export"
)

// IdentityRow represents one row in the access-control roster artifact.
type IdentityRow struct {
	ID          string `json:"id"           csv:"id"`
	ProviderID  string `json:"provider_id"  csv:"provider_id"`
	Provider    string `json:"provider"     csv:"provider"`
	Email       string `json:"email"        csv:"email"`
	DisplayName string `json:"display_name" csv:"display_name"`
	Roles       string `json:"roles"        csv:"roles"`
	IsPrivileged bool  `json:"is_privileged" csv:"is_privileged"`
	MFAEnrolled bool  `json:"mfa_enrolled"  csv:"mfa_enrolled"`
	CreatedAt   string `json:"created_at"   csv:"created_at"`
	UpdatedAt   string `json:"updated_at"   csv:"updated_at"`
}

// GenerateAccessControlRoster queries the identities table and returns a CC6.1
// access-control roster artifact for the given tenant and time window.
// CC6.1 — Logical access controls are established to restrict access to information
// and information assets to authorised users.
func GenerateAccessControlRoster(ctx context.Context, db *pgxpool.Pool, tenantID string, periodStart, periodEnd time.Time) (*export.Artifact, error) {
	tx, err := db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("access_control: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if err := tenant.SetRLS(ctx, tx, tenantID); err != nil {
		return nil, fmt.Errorf("access_control: set rls: %w", err)
	}

	rows, err := tx.Query(ctx,
		`SELECT id, provider_id, provider, COALESCE(email,''), COALESCE(display_name,''),
		        COALESCE(array_to_string(roles,','),''),
		        is_privileged, mfa_enrolled,
		        created_at, updated_at
		   FROM identities
		  WHERE tenant_id = $1
		    AND created_at <= $2
		  ORDER BY email`,
		tenantID, periodEnd)
	if err != nil {
		return nil, fmt.Errorf("access_control: query: %w", err)
	}
	defer rows.Close()

	var records []IdentityRow
	for rows.Next() {
		var r IdentityRow
		var createdAt, updatedAt time.Time
		if err := rows.Scan(&r.ID, &r.ProviderID, &r.Provider, &r.Email, &r.DisplayName,
			&r.Roles, &r.IsPrivileged, &r.MFAEnrolled, &createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("access_control: scan: %w", err)
		}
		r.CreatedAt = createdAt.UTC().Format(time.RFC3339)
		r.UpdatedAt = updatedAt.UTC().Format(time.RFC3339)
		records = append(records, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("access_control: rows: %w", err)
	}

	return &export.Artifact{
		ControlID:   "CC6.1",
		ControlName: "Logical and Physical Access Controls — Access Roster",
		ReportType:  "soc2",
		TenantID:    tenantID,
		PeriodStart: periodStart.UTC().Format(time.RFC3339),
		PeriodEnd:   periodEnd.UTC().Format(time.RFC3339),
		Records:     records,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

