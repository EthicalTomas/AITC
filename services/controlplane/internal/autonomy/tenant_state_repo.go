// Package autonomy implements the autonomy state machine for the controlplane service.
// It enforces the 7-day learning mode rule and autopilot gate (Step 0.2).
package autonomy

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TenantStateRepo loads TenantAutonomyState from the tenants table.
type TenantStateRepo struct {
	db *pgxpool.Pool
}

// NewTenantStateRepo creates a new repo backed by the given pool.
func NewTenantStateRepo(db *pgxpool.Pool) *TenantStateRepo {
	return &TenantStateRepo{db: db}
}

// Get loads the autonomy state for the given tenant.
// Returns an error if the tenant does not exist.
func (r *TenantStateRepo) Get(ctx context.Context, tenantID string) (TenantAutonomyState, error) {
	if tenantID == "" {
		return TenantAutonomyState{}, fmt.Errorf("tenantID must not be empty")
	}

	var (
		onboardingStartedAt time.Time
		autopilotEnabled    bool
		autopilotEnabledAt  *time.Time
	)

	err := r.db.QueryRow(ctx, `
		SELECT onboarding_started_at, autopilot_enabled, autopilot_enabled_at
		FROM tenants
		WHERE id = $1
	`, tenantID).Scan(&onboardingStartedAt, &autopilotEnabled, &autopilotEnabledAt)
	if err != nil {
		return TenantAutonomyState{}, fmt.Errorf("tenant_state_repo get %q: %w", tenantID, err)
	}

	return TenantAutonomyState{
		TenantID:            tenantID,
		OnboardingStartedAt: onboardingStartedAt,
		AutopilotEnabled:    autopilotEnabled,
		AutopilotEnabledAt:  autopilotEnabledAt,
	}, nil
}

// EnableAutopilot sets autopilot_enabled=true for the tenant after verifying the 7-day rule.
// Returns an error if the tenant is still in learning mode.
func (r *TenantStateRepo) EnableAutopilot(ctx context.Context, tenantID string) error {
	state, err := r.Get(ctx, tenantID)
	if err != nil {
		return err
	}
	if err := CanEnableAutopilot(state); err != nil {
		return err
	}
	now := time.Now().UTC()
	_, err = r.db.Exec(ctx, `
		UPDATE tenants
		SET autopilot_enabled = TRUE, autopilot_enabled_at = $1, updated_at = $1
		WHERE id = $2
	`, now, tenantID)
	return err
}

