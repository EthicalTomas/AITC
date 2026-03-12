package actions

import (
	"context"
	"encoding/json"
	"fmt"

	"go.uber.org/zap"

	oktaclient "github.com/ethicaltomas/aitc/internal/okta"
)

// SignOnPolicyAdjustParams are the parameters for the signon_policy_adjust action.
// GUARDRAIL: Only scoped (single rule) adjustments are allowed.
// Bulk policy mutations are permanently disallowed.
type SignOnPolicyAdjustParams struct {
	PolicyID string                 `json:"policy_id"`
	RuleID   string                 `json:"rule_id"`
	Patch    map[string]interface{} `json:"patch"`
}

// SignOnPolicyAdjustResult holds the before/after state for audit.
type SignOnPolicyAdjustResult struct {
	BeforeState interface{}
	AfterState  interface{}
}

// SignOnPolicyAdjustExecutor executes the signon_policy_adjust action.
type SignOnPolicyAdjustExecutor struct {
	okta   *oktaclient.Client
	logger *zap.Logger
}

// NewSignOnPolicyAdjustExecutor creates a new sign-on policy adjust executor.
func NewSignOnPolicyAdjustExecutor(okta *oktaclient.Client, logger *zap.Logger) *SignOnPolicyAdjustExecutor {
	return &SignOnPolicyAdjustExecutor{okta: okta, logger: logger}
}

// Execute applies a scoped patch to a single sign-on policy rule.
// Returns before/after state for audit recording.
// GUARDRAIL: Only a single rule can be modified per action; bulk mutation is disallowed.
func (e *SignOnPolicyAdjustExecutor) Execute(ctx context.Context, parametersJSON string) (*SignOnPolicyAdjustResult, error) {
	var params SignOnPolicyAdjustParams
	if err := json.Unmarshal([]byte(parametersJSON), &params); err != nil {
		return nil, fmt.Errorf("signon_policy_adjust: parse parameters: %w", err)
	}
	if params.PolicyID == "" {
		return nil, fmt.Errorf("signon_policy_adjust: policy_id is required in parameters")
	}
	if params.RuleID == "" {
		return nil, fmt.Errorf("signon_policy_adjust: rule_id is required in parameters")
	}
	if len(params.Patch) == 0 {
		return nil, fmt.Errorf("signon_policy_adjust: patch must not be empty")
	}

	// Capture before-state
	beforeRule, err := e.okta.GetSignOnPolicyRule(ctx, params.PolicyID, params.RuleID)
	if err != nil {
		e.logger.Warn("signon_policy_adjust: failed to capture before-state", zap.Error(err),
			zap.String("policy_id", params.PolicyID), zap.String("rule_id", params.RuleID))
		beforeRule = nil // non-fatal; proceed with execution
	}

	// Execute scoped patch
	if err := e.okta.UpdateSignOnPolicyRule(ctx, params.PolicyID, params.RuleID, params.Patch); err != nil {
		return nil, fmt.Errorf("signon_policy_adjust: execute: %w", err)
	}

	result := &SignOnPolicyAdjustResult{
		BeforeState: map[string]interface{}{
			"policy_id": params.PolicyID,
			"rule_id":   params.RuleID,
			"rule":      beforeRule,
		},
		AfterState: map[string]interface{}{
			"policy_id": params.PolicyID,
			"rule_id":   params.RuleID,
			"patch":     params.Patch,
		},
	}
	return result, nil
}

