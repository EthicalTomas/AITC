package policy_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	internalpolicy "github.com/ethicaltomas/aitc/internal/policy"
	"github.com/ethicaltomas/aitc/services/controlplane/internal/autonomy"
	"github.com/ethicaltomas/aitc/services/controlplane/internal/policy"
)

// writeTempPolicy writes JSON to a temp file and returns the path.
func writeTempPolicy(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "policy-*.json")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	f.Close()
	return filepath.Clean(f.Name())
}

// newTestValidator creates a Validator from inline JSON policy strings.
func newTestValidator(t *testing.T, allowlistJSON, disallowedJSON string) *policy.Validator {
	t.Helper()
	alPath := writeTempPolicy(t, allowlistJSON)
	daPath := writeTempPolicy(t, disallowedJSON)

	loader, err := internalpolicy.LoadPolicies(alPath, daPath)
	if err != nil {
		t.Fatalf("LoadPolicies: %v", err)
	}
	return policy.NewValidator(loader)
}

const testAllowlist = `{
  "version": "v1",
  "global_allowed": ["revoke_sessions", "mfa_stepup", "signon_policy_adjust"],
  "tenant_overrides": {}
}`

const testDisallowed = `{
  "version": "v1",
  "disallowed": [
    "delete_account",
    "disable_account",
    "isolate_device",
    "change_firewall_rule",
    "bulk_user_policy_mutation"
  ]
}`

// ── Step 0.1: Disallowed action tests ────────────────────────────────────────

func TestValidator_DisallowedAction_HardBlock(t *testing.T) {
	v := newTestValidator(t, testAllowlist, testDisallowed)
	mature := time.Now().Add(-10 * 24 * time.Hour)

	disallowedActions := []string{
		"delete_account",
		"disable_account",
		"isolate_device",
		"change_firewall_rule",
		"bulk_user_policy_mutation",
	}

	for _, action := range disallowedActions {
		t.Run(action, func(t *testing.T) {
			req := policy.ValidationRequest{
				TenantID:      "tenant-test",
				ActionID:      "action-001",
				ActionType:    action,
				ExecutionMode: "manual_executed",
				AutonomyState: autonomy.TenantAutonomyState{
					TenantID:            "tenant-test",
					OnboardingStartedAt: mature,
					AutopilotEnabled:    true,
					AutopilotEnabledAt:  &mature,
				},
			}
			d := v.Validate(context.Background(), req)
			if d.Allowed {
				t.Errorf("action %q must be hard-blocked by Step 0.1 guardrail", action)
			}
			if len(d.RejectionReasons) == 0 {
				t.Error("expected rejection reason for disallowed action")
			}
		})
	}
}

// ── Step 0.1: Allowed action tests ───────────────────────────────────────────

func TestValidator_AllowedAction_Passes(t *testing.T) {
	v := newTestValidator(t, testAllowlist, testDisallowed)
	mature := time.Now().Add(-10 * 24 * time.Hour)

	req := policy.ValidationRequest{
		TenantID:      "tenant-test",
		ActionID:      "action-002",
		ActionType:    "revoke_sessions",
		ExecutionMode: "manual_executed",
		AutonomyState: autonomy.TenantAutonomyState{
			TenantID:            "tenant-test",
			OnboardingStartedAt: mature,
			AutopilotEnabled:    false,
		},
	}

	d := v.Validate(context.Background(), req)
	if !d.Allowed {
		t.Errorf("revoke_sessions should be allowed, got reasons: %v", d.RejectionReasons)
	}
}

func TestValidator_UnknownAction_Blocked(t *testing.T) {
	v := newTestValidator(t, testAllowlist, testDisallowed)
	mature := time.Now().Add(-10 * 24 * time.Hour)

	req := policy.ValidationRequest{
		TenantID:      "tenant-test",
		ActionID:      "action-003",
		ActionType:    "some_unknown_action",
		ExecutionMode: "manual_executed",
		AutonomyState: autonomy.TenantAutonomyState{
			TenantID:            "tenant-test",
			OnboardingStartedAt: mature,
		},
	}

	d := v.Validate(context.Background(), req)
	if d.Allowed {
		t.Error("unknown action not in allowlist should be blocked")
	}
}

// ── Step 0.2: Learning mode integration ──────────────────────────────────────

func TestValidator_LearningMode_BlocksManualExecution(t *testing.T) {
	v := newTestValidator(t, testAllowlist, testDisallowed)

	req := policy.ValidationRequest{
		TenantID:      "tenant-new",
		ActionID:      "action-004",
		ActionType:    "revoke_sessions",
		ExecutionMode: "manual_executed",
		AutonomyState: autonomy.TenantAutonomyState{
			TenantID:            "tenant-new",
			OnboardingStartedAt: time.Now().Add(-2 * 24 * time.Hour), // 2 days in
			AutopilotEnabled:    false,
		},
	}

	d := v.Validate(context.Background(), req)
	if d.Allowed {
		t.Error("manual_executed must be blocked during learning mode")
	}
	if !d.InLearningMode {
		t.Error("InLearningMode must be true for new tenant")
	}
}

func TestValidator_LearningMode_AllowsRecommended(t *testing.T) {
	v := newTestValidator(t, testAllowlist, testDisallowed)

	req := policy.ValidationRequest{
		TenantID:      "tenant-new",
		ActionID:      "action-005",
		ActionType:    "revoke_sessions",
		ExecutionMode: "recommended",
		AutonomyState: autonomy.TenantAutonomyState{
			TenantID:            "tenant-new",
			OnboardingStartedAt: time.Now().Add(-2 * 24 * time.Hour),
			AutopilotEnabled:    false,
		},
	}

	d := v.Validate(context.Background(), req)
	if !d.Allowed {
		t.Errorf("recommended mode must be allowed in learning mode, reasons: %v", d.RejectionReasons)
	}
}

// ── Step 0.2: Autopilot gate integration ─────────────────────────────────────

func TestValidator_AutopilotNotEnabled_BlocksAutopilotExecution(t *testing.T) {
	v := newTestValidator(t, testAllowlist, testDisallowed)
	mature := time.Now().Add(-10 * 24 * time.Hour)

	req := policy.ValidationRequest{
		TenantID:      "tenant-mature",
		ActionID:      "action-006",
		ActionType:    "mfa_stepup",
		ExecutionMode: "autopilot_executed",
		AutonomyState: autonomy.TenantAutonomyState{
			TenantID:            "tenant-mature",
			OnboardingStartedAt: mature,
			AutopilotEnabled:    false, // not enabled
		},
	}

	d := v.Validate(context.Background(), req)
	if d.Allowed {
		t.Error("autopilot_executed must be blocked when AutopilotEnabled=false")
	}
}

func TestValidator_AutopilotEnabled_AllowsAutopilotExecution(t *testing.T) {
	v := newTestValidator(t, testAllowlist, testDisallowed)
	enabledAt := time.Now().Add(-9 * 24 * time.Hour)

	req := policy.ValidationRequest{
		TenantID:      "tenant-autopilot",
		ActionID:      "action-007",
		ActionType:    "revoke_sessions",
		ExecutionMode: "autopilot_executed",
		AutonomyState: autonomy.TenantAutonomyState{
			TenantID:            "tenant-autopilot",
			OnboardingStartedAt: time.Now().Add(-10 * 24 * time.Hour),
			AutopilotEnabled:    true,
			AutopilotEnabledAt:  &enabledAt,
		},
	}

	d := v.Validate(context.Background(), req)
	if !d.Allowed {
		t.Errorf("autopilot_executed must be allowed when enabled, reasons: %v", d.RejectionReasons)
	}
}

// ── Break-glass exclusion ─────────────────────────────────────────────────────

func TestValidator_BreakGlass_BlocksExecution(t *testing.T) {
	v := newTestValidator(t, testAllowlist, testDisallowed)
	mature := time.Now().Add(-10 * 24 * time.Hour)

	req := policy.ValidationRequest{
		TenantID:              "tenant-bg",
		ActionID:              "action-008",
		ActionType:            "revoke_sessions",
		ExecutionMode:         "manual_executed",
		IdentityID:            "ceo-user-id",
		BreakGlassIdentityIDs: []string{"ceo-user-id", "cto-user-id"},
		AutonomyState: autonomy.TenantAutonomyState{
			TenantID:            "tenant-bg",
			OnboardingStartedAt: mature,
		},
	}

	d := v.Validate(context.Background(), req)
	if d.Allowed {
		t.Error("action on break-glass identity must be blocked")
	}
}

// ── Decision always has required fields ──────────────────────────────────────

func TestValidator_DecisionHasRequiredFields(t *testing.T) {
	v := newTestValidator(t, testAllowlist, testDisallowed)
	mature := time.Now().Add(-10 * 24 * time.Hour)

	req := policy.ValidationRequest{
		TenantID:      "tenant-fields",
		ActionID:      "action-009",
		ActionType:    "revoke_sessions",
		ExecutionMode: "recommended",
		AutonomyState: autonomy.TenantAutonomyState{
			TenantID:            "tenant-fields",
			OnboardingStartedAt: mature,
		},
	}

	d := v.Validate(context.Background(), req)

	if d.DecisionID == "" {
		t.Error("Decision must have a DecisionID (Step 0.4 audit requirement)")
	}
	if d.TenantID != "tenant-fields" {
		t.Error("Decision must carry TenantID")
	}
	if d.ActionType != "revoke_sessions" {
		t.Error("Decision must carry ActionType")
	}
	if d.DecidedAt.IsZero() {
		t.Error("Decision must have DecidedAt timestamp")
	}
}
