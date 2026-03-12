// Package actions implements allowlisted Okta enforcement actions.
// GUARDRAILS: Only revoke_sessions, mfa_stepup, and signon_policy_adjust are permitted.
// Each action captures before/after state for audit and records it in response_actions.
package actions

import (
	"context"
	"encoding/json"
	"fmt"

	"go.uber.org/zap"

	oktaclient "github.com/ethicaltomas/aitc/internal/okta"
)

// RevokeSessionsParams are the parameters for the revoke_sessions action.
type RevokeSessionsParams struct {
	UserID string `json:"user_id"`
}

// RevokeSessionsResult holds the before/after state for audit.
type RevokeSessionsResult struct {
	BeforeState interface{}
	AfterState  interface{}
}

// RevokeSessionsExecutor executes the revoke_sessions action.
type RevokeSessionsExecutor struct {
	okta   *oktaclient.Client
	logger *zap.Logger
}

// NewRevokeSessionsExecutor creates a new revoke sessions executor.
func NewRevokeSessionsExecutor(okta *oktaclient.Client, logger *zap.Logger) *RevokeSessionsExecutor {
	return &RevokeSessionsExecutor{okta: okta, logger: logger}
}

// Execute revokes all active sessions for the user identified in parametersJSON.
// Returns before/after state for audit recording.
func (e *RevokeSessionsExecutor) Execute(ctx context.Context, parametersJSON string) (*RevokeSessionsResult, error) {
	var params RevokeSessionsParams
	if err := json.Unmarshal([]byte(parametersJSON), &params); err != nil {
		return nil, fmt.Errorf("revoke_sessions: parse parameters: %w", err)
	}
	if params.UserID == "" {
		return nil, fmt.Errorf("revoke_sessions: user_id is required in parameters")
	}

	// Capture before-state
	beforeSessions, err := e.okta.GetUserSessions(ctx, params.UserID)
	if err != nil {
		e.logger.Warn("revoke_sessions: failed to capture before-state", zap.Error(err), zap.String("user_id", params.UserID))
		beforeSessions = nil // non-fatal; proceed with execution
	}

	// Execute action
	if err := e.okta.RevokeUserSessions(ctx, params.UserID); err != nil {
		return nil, fmt.Errorf("revoke_sessions: execute: %w", err)
	}

	result := &RevokeSessionsResult{
		BeforeState: map[string]interface{}{
			"sessions": beforeSessions,
			"count":    len(beforeSessions),
		},
		AfterState: map[string]interface{}{
			"sessions": []interface{}{},
			"count":    0,
		},
	}
	return result, nil
}

