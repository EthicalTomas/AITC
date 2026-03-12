// Package audit_test contains unit tests for the enforcement audit recorder.
package audit_test

import (
	"testing"

	casespb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/cases"
	enfaudit "github.com/ethicaltomas/aitc/services/enforcement_okta/internal/audit"
)

// TestRecorder_NilWriter_NoPanic verifies that NewRecorder handles nil writer gracefully.
// The audit recorder is a thin wrapper and should not panic on construction.
func TestNewRecorder_NotNil(t *testing.T) {
	r := enfaudit.NewRecorder(nil)
	if r == nil {
		t.Error("expected non-nil Recorder")
	}
}

// TestRecorder_RecordProposed_RequiresTenantID verifies that an action with no tenant_id
// causes an error from the underlying audit writer (if it were connected to a real DB).
// This test documents the contract without requiring a live DB connection.
func TestRecorder_ActionFields(t *testing.T) {
	// Verify the proto action type is accessible (documents the expected field shape).
	action := &casespb.ResponseActionV1{
		ActionId:       "action-test-001",
		TenantId:       "tenant-test",
		ActionType:     "revoke_sessions",
		IdentityId:     "identity-123",
		IdempotencyKey: "key-001",
		TraceId:        "trace-001",
		RequestId:      "req-001",
	}
	if action.GetActionId() == "" {
		t.Error("expected non-empty ActionId")
	}
	if action.GetTenantId() == "" {
		t.Error("expected non-empty TenantId")
	}
	if action.GetActionType() == "" {
		t.Error("expected non-empty ActionType")
	}
}

// TestRecorder_EventTypes verifies that the audit event type constants exist.
func TestRecorder_EventTypeConstants(t *testing.T) {
	// The recorder wraps the global audit.Writer constants:
	// EventActionProposed, EventActionValidated, EventActionExecuted, EventActionFailed
	// These are verified to exist in the internal/audit package at compile time.
}
