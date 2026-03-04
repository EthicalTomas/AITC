package policy

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/ethicaltomas/aitc/internal/policy"
	"github.com/ethicaltomas/aitc/services/controlplane/internal/autonomy"
)

// Decision is the outcome of a policy validation check.
type Decision struct {
	DecisionID        string
	TenantID          string
	ActionID          string
	ActionType        string
	Allowed           bool
	RejectionReasons  []string
	BlastRadiusScore  int
	InLearningMode    bool
	DecidedAt         time.Time
}

// Validator enforces Step 0 guardrails and Step 1 policy rules on proposed actions.
// Every proposed action MUST be passed through Validate before execution.
type Validator struct {
	policyLoader *policy.Loader
}

// NewValidator creates a policy Validator backed by the given policy loader.
func NewValidator(loader *policy.Loader) *Validator {
	return &Validator{policyLoader: loader}
}

// ValidationRequest carries all inputs needed for a policy decision.
type ValidationRequest struct {
	TenantID      string
	ActionID      string
	ActionType    string
	ExecutionMode string // "recommended" | "manual_executed" | "autopilot_executed"
	IdentityID    string
	CaseID        string
	AutonomyState autonomy.TenantAutonomyState
	// BreakGlassIdentityIDs are identities excluded from automated actions.
	BreakGlassIdentityIDs []string
}

// Validate runs all policy checks and returns a Decision.
// Step 0.1: disallowed actions are blocked unconditionally.
// Step 0.2: learning mode gate is enforced.
// Step 0.4: caller MUST persist the returned Decision to the audit log.
func (v *Validator) Validate(ctx context.Context, req ValidationRequest) Decision {
	d := Decision{
		DecisionID:     uuid.New().String(),
		TenantID:       req.TenantID,
		ActionID:       req.ActionID,
		ActionType:     req.ActionType,
		InLearningMode: autonomy.IsInLearningMode(req.AutonomyState),
		DecidedAt:      time.Now().UTC(),
	}

	// ── Step 0.1: Hard disallow check (unconditional, cannot be overridden) ──
	if v.policyLoader.IsDisallowed(req.ActionType) {
		d.Allowed = false
		d.RejectionReasons = append(d.RejectionReasons,
			fmt.Sprintf("action_type %q is in the permanent disallow list (Step 0.1 guardrail)", req.ActionType),
		)
		return d
	}

	// ── Allowlist check ──
	if !v.policyLoader.IsAllowed(req.TenantID, req.ActionType) {
		d.Allowed = false
		d.RejectionReasons = append(d.RejectionReasons,
			fmt.Sprintf("action_type %q is not in the allowlist for tenant %q", req.ActionType, req.TenantID),
		)
		return d
	}

	// ── Step 0.2: Learning mode gate ──
	if err := autonomy.LearningModeGate(ctx, req.AutonomyState, req.ExecutionMode); err != nil {
		d.Allowed = false
		d.RejectionReasons = append(d.RejectionReasons, err.Error())
		return d
	}

	// ── Step 0.2: Autopilot gate ──
	if err := autonomy.AutopilotGate(ctx, req.AutonomyState, req.ExecutionMode); err != nil {
		d.Allowed = false
		d.RejectionReasons = append(d.RejectionReasons, err.Error())
		return d
	}

	// ── Break-glass exclusion (blast radius constraint) ──
	for _, bgID := range req.BreakGlassIdentityIDs {
		if bgID == req.IdentityID {
			d.Allowed = false
			d.RejectionReasons = append(d.RejectionReasons,
				fmt.Sprintf("identity %q is excluded from automated actions (break-glass list)", req.IdentityID),
			)
			return d
		}
	}

	// All checks passed.
	d.Allowed = true
	return d
}


