// Package executor implements the enforcement action dispatcher.
// It checks idempotency, dispatches to the correct action handler,
// records before/after state in response_actions, and writes audit entries.
package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	casespb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/cases"
	globalaudit "github.com/ethicaltomas/aitc/internal/audit"
	oktaclient "github.com/ethicaltomas/aitc/internal/okta"
	"github.com/ethicaltomas/aitc/internal/policy"
	"github.com/ethicaltomas/aitc/internal/tenant"
	enfaudit "github.com/ethicaltomas/aitc/services/enforcement_okta/internal/audit"
	"github.com/ethicaltomas/aitc/services/enforcement_okta/internal/actions"
)

// Executor dispatches validated action-request messages to Okta actions.
// GUARDRAIL: Only actions in the policy allowlist may be executed.
type Executor struct {
	db       *pgxpool.Pool
	okta     *oktaclient.Client
	policy   *policy.Loader
	recorder *enfaudit.Recorder
	logger   *zap.Logger
}

// NewExecutor creates a new action executor.
func NewExecutor(
	db *pgxpool.Pool,
	okta *oktaclient.Client,
	pol *policy.Loader,
	auditWriter *globalaudit.Writer,
	logger *zap.Logger,
) *Executor {
	return &Executor{
		db:       db,
		okta:     okta,
		policy:   pol,
		recorder: enfaudit.NewRecorder(auditWriter),
		logger:   logger,
	}
}

// Dispatch processes a ResponseActionV1 with idempotency, allowlist enforcement, and audit logging.
// Steps:
//  1. Check allowlist (hard block for disallowed actions).
//  2. Check idempotency — skip if already executed.
//  3. Write proposed audit entry.
//  4. Insert/update response_actions row to "executing".
//  5. Dispatch to correct action handler.
//  6. Record before/after state in response_actions and write executed/failed audit entry.
func (e *Executor) Dispatch(ctx context.Context, action *casespb.ResponseActionV1) error {
	tenantID := action.GetTenantId()
	actionType := action.GetActionType()
	idempotencyKey := action.GetIdempotencyKey()

	e.logger.Info("dispatch action",
		zap.String("action_id", action.GetActionId()),
		zap.String("tenant_id", tenantID),
		zap.String("action_type", actionType),
		zap.String("idempotency_key", idempotencyKey),
	)

	// Step 1: Allowlist check (disallowed actions are hard-blocked)
	if e.policy.IsDisallowed(actionType) {
		return fmt.Errorf("executor: action type %q is permanently disallowed", actionType)
	}
	if !e.policy.IsAllowed(tenantID, actionType) {
		return fmt.Errorf("executor: action type %q is not in the allowlist for tenant %s", actionType, tenantID)
	}

	// Step 2: Idempotency check — skip if already executed
	alreadyExecuted, err := checkIdempotency(ctx, e.db, tenantID, idempotencyKey)
	if err != nil {
		return fmt.Errorf("executor: idempotency check: %w", err)
	}
	if alreadyExecuted {
		e.logger.Info("action already executed; skipping (idempotent)",
			zap.String("idempotency_key", idempotencyKey),
			zap.String("action_id", action.GetActionId()),
		)
		return nil
	}

	// Step 3: Write proposed audit entry
	if auditErr := e.recorder.RecordProposed(ctx, action); auditErr != nil {
		e.logger.Warn("failed to write proposed audit entry", zap.Error(auditErr))
	}

	// Step 4: Upsert response_actions row to "executing"
	if dbErr := upsertResponseAction(ctx, e.db, tenantID, action, "executing", "", nil, nil); dbErr != nil {
		return fmt.Errorf("executor: upsert response_action: %w", dbErr)
	}

	// Step 5: Write validated audit entry (idempotency passed, action executing)
	if auditErr := e.recorder.RecordValidated(ctx, action); auditErr != nil {
		e.logger.Warn("failed to write validated audit entry", zap.Error(auditErr))
	}

	// Step 6: Dispatch to action handler (with retries)
	var beforeState, afterState interface{}
	execErr := withRetries(ctx, e.logger, action, func() error {
		return e.execute(ctx, action, &beforeState, &afterState)
	})
	if execErr != nil {
		// Record failure in DB and audit
		_ = upsertResponseAction(ctx, e.db, tenantID, action, "failed", execErr.Error(), nil, nil)
		if auditErr := e.recorder.RecordFailed(ctx, action, execErr.Error()); auditErr != nil {
			e.logger.Warn("failed to write failed audit entry", zap.Error(auditErr))
		}
		return fmt.Errorf("executor: execute action: %w", execErr)
	}

	// Step 7: Record success
	if dbErr := upsertResponseAction(ctx, e.db, tenantID, action, "executed", "", beforeState, afterState); dbErr != nil {
		e.logger.Error("failed to update response_action to executed", zap.Error(dbErr))
	}
	if auditErr := e.recorder.RecordExecuted(ctx, action, beforeState, afterState); auditErr != nil {
		e.logger.Warn("failed to write executed audit entry", zap.Error(auditErr))
	}
	return nil
}

// execute dispatches to the specific action implementation.
// GUARDRAIL: Only revoke_sessions, mfa_stepup, and signon_policy_adjust are allowed.
func (e *Executor) execute(ctx context.Context, action *casespb.ResponseActionV1, beforeState, afterState *interface{}) error {
	params := action.GetParametersJson()

	switch action.GetActionType() {
	case "revoke_sessions":
		exec := actions.NewRevokeSessionsExecutor(e.okta, e.logger)
		result, err := exec.Execute(ctx, params)
		if err != nil {
			return err
		}
		*beforeState = result.BeforeState
		*afterState = result.AfterState

	case "mfa_stepup":
		exec := actions.NewMFAStepUpExecutor(e.okta, e.logger)
		result, err := exec.Execute(ctx, params)
		if err != nil {
			return err
		}
		*beforeState = result.BeforeState
		*afterState = result.AfterState

	case "signon_policy_adjust":
		exec := actions.NewSignOnPolicyAdjustExecutor(e.okta, e.logger)
		result, err := exec.Execute(ctx, params)
		if err != nil {
			return err
		}
		*beforeState = result.BeforeState
		*afterState = result.AfterState

	default:
		// Should never reach here because the allowlist check already blocked unknown types.
		return fmt.Errorf("executor: unknown action type %q — not in switch (allowlist enforcement failed)", action.GetActionType())
	}
	return nil
}

// upsertResponseAction inserts or updates the response_actions row for this action.
// Uses ON CONFLICT on (tenant_id, idempotency_key) to update status and state.
func upsertResponseAction(
	ctx context.Context,
	db *pgxpool.Pool,
	tenantID string,
	action *casespb.ResponseActionV1,
	status string,
	rejectionReason string,
	beforeState interface{},
	afterState interface{},
) error {
	tx, err := db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("upsert response_action: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := tenant.SetRLS(ctx, tx, tenantID); err != nil {
		return fmt.Errorf("upsert response_action: set RLS: %w", err)
	}

	beforeJSON, err := json.Marshal(beforeState)
	if err != nil {
		beforeJSON = []byte("null")
	}
	afterJSON, err := json.Marshal(afterState)
	if err != nil {
		afterJSON = []byte("null")
	}

	var executedAt *time.Time
	if status == "executed" {
		now := time.Now().UTC()
		executedAt = &now
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO response_actions
			(tenant_id, case_id, identity_id, action_type, mode, status,
			 parameters_json, idempotency_key, validator_decision_id,
			 rejection_reason, before_state_json, after_state_json,
			 trace_id, request_id, executed_at, executed_by, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, NOW())
		ON CONFLICT (tenant_id, idempotency_key)
		DO UPDATE SET
			status           = EXCLUDED.status,
			rejection_reason = EXCLUDED.rejection_reason,
			before_state_json = CASE WHEN EXCLUDED.before_state_json IS NOT NULL THEN EXCLUDED.before_state_json ELSE response_actions.before_state_json END,
			after_state_json  = CASE WHEN EXCLUDED.after_state_json IS NOT NULL THEN EXCLUDED.after_state_json ELSE response_actions.after_state_json END,
			executed_at      = EXCLUDED.executed_at,
			executed_by      = EXCLUDED.executed_by,
			updated_at       = NOW()`,
		tenantID,
		nullableString(action.GetCaseId()),
		nullableString(action.GetIdentityId()),
		action.GetActionType(),
		action.GetMode().String(),
		status,
		action.GetParametersJson(),
		action.GetIdempotencyKey(),
		nullableString(action.GetValidatorDecisionId()),
		nullableString(rejectionReason),
		beforeJSON,
		afterJSON,
		nullableString(action.GetTraceId()),
		nullableString(action.GetRequestId()),
		executedAt,
		"enforcement-okta",
	)
	if err != nil {
		return fmt.Errorf("upsert response_action exec: %w", err)
	}
	return tx.Commit(ctx)
}

// nullableString returns nil for empty strings (for nullable DB columns).
func nullableString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

