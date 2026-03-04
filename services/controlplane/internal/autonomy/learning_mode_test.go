package autonomy_test

import (
	"context"
	"testing"
	"time"

	"github.com/ethicaltomas/aitc/services/controlplane/internal/autonomy"
)

// ── Step 0.2: Learning Mode Gate Tests ──────────────────────────────────────
// These tests enforce the non-negotiable 7-day learning period before autopilot.

func TestIsInLearningMode_NewTenant(t *testing.T) {
	state := autonomy.TenantAutonomyState{
		TenantID:            "tenant-new",
		OnboardingStartedAt: time.Now().Add(-1 * time.Hour), // onboarded 1 hour ago
		AutopilotEnabled:    false,
	}

	if !autonomy.IsInLearningMode(state) {
		t.Error("tenant onboarded 1 hour ago should be in learning mode")
	}
}

func TestIsInLearningMode_PostLearningPeriod(t *testing.T) {
	state := autonomy.TenantAutonomyState{
		TenantID:            "tenant-mature",
		OnboardingStartedAt: time.Now().Add(-8 * 24 * time.Hour), // 8 days ago
		AutopilotEnabled:    false,
	}

	if autonomy.IsInLearningMode(state) {
		t.Error("tenant onboarded 8 days ago should NOT be in learning mode")
	}
}

func TestIsInLearningMode_ExactlySevenDays(t *testing.T) {
	// The spec says "completed ≥7 full days since onboarding_started_at".
	// At exactly 7 days elapsed the tenant HAS completed the learning period.
	// IsInLearningMode uses elapsed < 7d, so at 7d the tenant is out of LM.
	state := autonomy.TenantAutonomyState{
		TenantID:            "tenant-7days",
		OnboardingStartedAt: time.Now().Add(-7 * 24 * time.Hour),
		AutopilotEnabled:    false,
	}

	// At exactly 7 days the tenant has completed the learning period.
	if autonomy.IsInLearningMode(state) {
		t.Error("tenant at exactly 7 days should NOT be in learning mode (has completed ≥7 full days)")
	}
}

func TestCanEnableAutopilot_TooEarly(t *testing.T) {
	state := autonomy.TenantAutonomyState{
		TenantID:            "tenant-early",
		OnboardingStartedAt: time.Now().Add(-3 * 24 * time.Hour), // 3 days ago
	}

	err := autonomy.CanEnableAutopilot(state)
	if err == nil {
		t.Error("expected error when trying to enable autopilot before 7-day learning period")
	}
}

func TestCanEnableAutopilot_AfterLearningPeriod(t *testing.T) {
	state := autonomy.TenantAutonomyState{
		TenantID:            "tenant-ready",
		OnboardingStartedAt: time.Now().Add(-10 * 24 * time.Hour), // 10 days ago
	}

	err := autonomy.CanEnableAutopilot(state)
	if err != nil {
		t.Errorf("expected no error when enabling autopilot after 7 days, got: %v", err)
	}
}

func TestLearningModeGate_RecommendedAlwaysAllowed(t *testing.T) {
	// During learning mode, RECOMMENDED mode must always be allowed.
	state := autonomy.TenantAutonomyState{
		TenantID:            "tenant-learning",
		OnboardingStartedAt: time.Now().Add(-2 * 24 * time.Hour),
	}

	err := autonomy.LearningModeGate(context.Background(), state, "recommended")
	if err != nil {
		t.Errorf("RECOMMENDED must be allowed in learning mode, got error: %v", err)
	}
}

func TestLearningModeGate_ManualExecutedBlocked(t *testing.T) {
	// During learning mode, MANUAL_EXECUTED must be blocked.
	state := autonomy.TenantAutonomyState{
		TenantID:            "tenant-learning",
		OnboardingStartedAt: time.Now().Add(-2 * 24 * time.Hour),
	}

	err := autonomy.LearningModeGate(context.Background(), state, "manual_executed")
	if err == nil {
		t.Error("MANUAL_EXECUTED must be blocked during learning mode")
	}
}

func TestLearningModeGate_AutopilotExecutedBlocked(t *testing.T) {
	// During learning mode, AUTOPILOT_EXECUTED must be blocked.
	state := autonomy.TenantAutonomyState{
		TenantID:            "tenant-learning",
		OnboardingStartedAt: time.Now().Add(-1 * 24 * time.Hour),
	}

	err := autonomy.LearningModeGate(context.Background(), state, "autopilot_executed")
	if err == nil {
		t.Error("AUTOPILOT_EXECUTED must be blocked during learning mode")
	}
}

func TestLearningModeGate_PostLearning_ManualAllowed(t *testing.T) {
	// After learning mode, manual execution must pass the gate.
	state := autonomy.TenantAutonomyState{
		TenantID:            "tenant-mature",
		OnboardingStartedAt: time.Now().Add(-8 * 24 * time.Hour),
	}

	err := autonomy.LearningModeGate(context.Background(), state, "manual_executed")
	if err != nil {
		t.Errorf("MANUAL_EXECUTED must be allowed post-learning, got: %v", err)
	}
}

func TestAutopilotGate_NotEnabledBlocks(t *testing.T) {
	// Autopilot must be blocked if not explicitly enabled.
	state := autonomy.TenantAutonomyState{
		TenantID:         "tenant-nopilot",
		AutopilotEnabled: false,
	}

	err := autonomy.AutopilotGate(context.Background(), state, "autopilot_executed")
	if err == nil {
		t.Error("autopilot_executed must be blocked when AutopilotEnabled=false")
	}
}

func TestAutopilotGate_EnabledAllows(t *testing.T) {
	now := time.Now().Add(-8 * 24 * time.Hour)
	state := autonomy.TenantAutonomyState{
		TenantID:           "tenant-autopilot",
		AutopilotEnabled:   true,
		AutopilotEnabledAt: &now,
	}

	err := autonomy.AutopilotGate(context.Background(), state, "autopilot_executed")
	if err != nil {
		t.Errorf("autopilot_executed must be allowed when AutopilotEnabled=true, got: %v", err)
	}
}

func TestAutopilotGate_NonAutopilotModes_Unaffected(t *testing.T) {
	// AutopilotGate must not affect recommended or manual modes.
	state := autonomy.TenantAutonomyState{
		TenantID:         "tenant-nopilot",
		AutopilotEnabled: false,
	}

	for _, mode := range []string{"recommended", "manual_executed"} {
		err := autonomy.AutopilotGate(context.Background(), state, mode)
		if err != nil {
			t.Errorf("AutopilotGate must not block mode %q, got: %v", mode, err)
		}
	}
}
