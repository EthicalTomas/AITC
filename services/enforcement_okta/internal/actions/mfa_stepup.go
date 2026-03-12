package actions

import (
	"context"
	"encoding/json"
	"fmt"

	"go.uber.org/zap"

	oktaclient "github.com/ethicaltomas/aitc/internal/okta"
)

// MFAStepUpParams are the parameters for the mfa_stepup action.
type MFAStepUpParams struct {
	UserID string `json:"user_id"`
}

// MFAStepUpResult holds the before/after state for audit.
type MFAStepUpResult struct {
	BeforeState interface{}
	AfterState  interface{}
}

// MFAStepUpExecutor executes the mfa_stepup action.
type MFAStepUpExecutor struct {
	okta   *oktaclient.Client
	logger *zap.Logger
}

// NewMFAStepUpExecutor creates a new MFA step-up executor.
func NewMFAStepUpExecutor(okta *oktaclient.Client, logger *zap.Logger) *MFAStepUpExecutor {
	return &MFAStepUpExecutor{okta: okta, logger: logger}
}

// Execute resets all enrolled MFA factors for the user, forcing re-enrollment.
// Returns before/after state for audit recording.
func (e *MFAStepUpExecutor) Execute(ctx context.Context, parametersJSON string) (*MFAStepUpResult, error) {
	var params MFAStepUpParams
	if err := json.Unmarshal([]byte(parametersJSON), &params); err != nil {
		return nil, fmt.Errorf("mfa_stepup: parse parameters: %w", err)
	}
	if params.UserID == "" {
		return nil, fmt.Errorf("mfa_stepup: user_id is required in parameters")
	}

	// Capture before-state
	beforeFactors, err := e.okta.GetUserEnrolledFactors(ctx, params.UserID)
	if err != nil {
		e.logger.Warn("mfa_stepup: failed to capture before-state", zap.Error(err), zap.String("user_id", params.UserID))
		beforeFactors = nil // non-fatal; proceed with execution
	}

	// Execute action: reset all MFA factors to force re-enrollment
	if err := e.okta.ResetUserMFAFactors(ctx, params.UserID); err != nil {
		return nil, fmt.Errorf("mfa_stepup: execute: %w", err)
	}

	result := &MFAStepUpResult{
		BeforeState: map[string]interface{}{
			"enrolled_factors": beforeFactors,
		},
		AfterState: map[string]interface{}{
			"enrolled_factors": []interface{}{},
			"note":             "all MFA factors reset; re-enrollment required",
		},
	}
	return result, nil
}

