package soc2

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ethicaltomas/aitc/internal/tenant"
	"github.com/ethicaltomas/aitc/services/evidence/internal/export"
)

// PrivilegedRow represents one privileged identity in the inventory.
type PrivilegedRow struct {
	ID          string `json:"id"           csv:"id"`
	Email       string `json:"email"        csv:"email"`
	DisplayName string `json:"display_name" csv:"display_name"`
	Provider    string `json:"provider"     csv:"provider"`
	Roles       string `json:"roles"        csv:"roles"`
	MFAEnrolled bool   `json:"mfa_enrolled" csv:"mfa_enrolled"`
	CreatedAt   string `json:"created_at"   csv:"created_at"`
	UpdatedAt   string `json:"updated_at"   csv:"updated_at"`
}

// GeneratePrivilegedInventory produces a CC6.2 privileged-access inventory artifact.
// Only identities with is_privileged=true are included, providing evidence that
// privileged access is limited to authorised personnel and appropriately controlled.
func GeneratePrivilegedInventory(ctx context.Context, db *pgxpool.Pool, tenantID string, periodStart, periodEnd time.Time) (*export.Artifact, error) {
	tx, err := db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("privileged_inventory: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if err := tenant.SetRLS(ctx, tx, tenantID); err != nil {
		return nil, fmt.Errorf("privileged_inventory: set rls: %w", err)
	}

	rows, err := tx.Query(ctx,
		`SELECT id, COALESCE(email,''), COALESCE(display_name,''), provider,
		        COALESCE(array_to_string(roles,','),''), mfa_enrolled,
		        created_at, updated_at
		   FROM identities
		  WHERE tenant_id = $1
		    AND is_privileged = TRUE
		    AND created_at <= $2
		  ORDER BY email`,
		tenantID, periodEnd)
	if err != nil {
		return nil, fmt.Errorf("privileged_inventory: query: %w", err)
	}
	defer rows.Close()

	var records []PrivilegedRow
	for rows.Next() {
		var r PrivilegedRow
		var createdAt, updatedAt time.Time
		if err := rows.Scan(&r.ID, &r.Email, &r.DisplayName, &r.Provider,
			&r.Roles, &r.MFAEnrolled, &createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("privileged_inventory: scan: %w", err)
		}
		r.CreatedAt = createdAt.UTC().Format(time.RFC3339)
		r.UpdatedAt = updatedAt.UTC().Format(time.RFC3339)
		records = append(records, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("privileged_inventory: rows: %w", err)
	}

	return &export.Artifact{
		ControlID:   "CC6.2",
		ControlName: "Logical and Physical Access Controls — Privileged Access Inventory",
		ReportType:  "soc2",
		TenantID:    tenantID,
		PeriodStart: periodStart.UTC().Format(time.RFC3339),
		PeriodEnd:   periodEnd.UTC().Format(time.RFC3339),
		Records:     records,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

