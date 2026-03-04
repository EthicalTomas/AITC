package autonomy

import (
	"context"
	"fmt"
	"time"
)

// LearningModeDuration is the mandatory period before autopilot can be enabled.
// Step 0.2: Autopilot cannot be enabled until the tenant has completed ≥7 full days
// since onboarding start. This is non-negotiable.
const LearningModeDuration = 7 * 24 * time.Hour

// TenantAutonomyState holds the autonomy configuration for a single tenant.
type TenantAutonomyState struct {
	TenantID              string
	OnboardingStartedAt   time.Time
	AutopilotEnabled      bool
	AutopilotEnabledAt    *time.Time
}

// IsInLearningMode returns true if the tenant has NOT yet completed the 7-day
// learning period. During learning mode, no automated actions are executed —
// only recommendations are emitted.
// Step 0.2: enforced here.
func IsInLearningMode(state TenantAutonomyState) bool {
	return time.Since(state.OnboardingStartedAt) < LearningModeDuration
}

// CanEnableAutopilot returns nil if autopilot may be enabled, or an error
// explaining why it cannot be enabled yet.
// Step 0.2: Both conditions must hold:
//  1. ≥7 full days since onboarding_started_at
//  2. Admin explicitly requests enable (enforced by caller requiring this check)
func CanEnableAutopilot(state TenantAutonomyState) error {
	elapsed := time.Since(state.OnboardingStartedAt)
	if elapsed < LearningModeDuration {
		remaining := LearningModeDuration - elapsed
		return fmt.Errorf(
			"autopilot cannot be enabled: learning mode requires %s more (%.1f days remaining)",
			remaining.Round(time.Minute),
			remaining.Hours()/24,
		)
	}
	return nil
}

// LearningModeGate enforces the Step 0.2 autopilot rules at action execution time.
// Returns an error if the tenant is in learning mode and the requested execution
// mode would bypass recommendation-only behaviour.
func LearningModeGate(ctx context.Context, state TenantAutonomyState, executionMode string) error {
	if !IsInLearningMode(state) {
		return nil // past learning period — check autopilot flag next
	}
	// During learning mode, only RECOMMENDED mode is allowed.
	// MANUAL_EXECUTED and AUTOPILOT_EXECUTED are blocked.
	switch executionMode {
	case "recommended":
		return nil
	case "manual_executed", "autopilot_executed":
		return fmt.Errorf(
			"action blocked: tenant %q is in learning mode (onboarding started %s); "+
				"only recommendations are permitted until %s",
			state.TenantID,
			state.OnboardingStartedAt.Format(time.RFC3339),
			state.OnboardingStartedAt.Add(LearningModeDuration).Format(time.RFC3339),
		)
	default:
		return fmt.Errorf("unknown execution mode %q", executionMode)
	}
}

// AutopilotGate enforces that autopilot is only used when explicitly enabled.
// Returns an error if execution mode is AUTOPILOT_EXECUTED but tenant has not
// enabled autopilot.
func AutopilotGate(_ context.Context, state TenantAutonomyState, executionMode string) error {
	if executionMode != "autopilot_executed" {
		return nil
	}
	if !state.AutopilotEnabled {
		return fmt.Errorf(
			"autopilot action blocked: tenant %q has not enabled autopilot",
			state.TenantID,
		)
	}
	return nil
}


