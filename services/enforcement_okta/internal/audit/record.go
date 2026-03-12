// Package audit provides enforcement-specific audit recording helpers.
// All writes delegate to internal/audit.Writer (append-only).
package audit

import (
	"context"
	"fmt"

	globalaudit "github.com/ethicaltomas/aitc/internal/audit"
	casespb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/cases"
)

const actor = "enforcement-okta"

// Recorder wraps the shared audit Writer with enforcement-specific helpers.
type Recorder struct {
	w *globalaudit.Writer
}

// NewRecorder creates a new enforcement audit Recorder.
func NewRecorder(w *globalaudit.Writer) *Recorder {
	return &Recorder{w: w}
}

// RecordProposed writes an ActionProposed audit entry.
func (r *Recorder) RecordProposed(ctx context.Context, action *casespb.ResponseActionV1) error {
	return r.w.Write(ctx, globalaudit.Entry{
		TenantID:    action.GetTenantId(),
		EventType:   globalaudit.EventActionProposed,
		Actor:       actor,
		SubjectType: "ResponseAction",
		SubjectID:   action.GetActionId(),
		Description: fmt.Sprintf("action proposed: %s for identity %s", action.GetActionType(), action.GetIdentityId()),
		TraceID:     action.GetTraceId(),
		RequestID:   action.GetRequestId(),
	})
}

// RecordValidated writes an ActionValidated audit entry (idempotency check passed; action is safe to execute).
func (r *Recorder) RecordValidated(ctx context.Context, action *casespb.ResponseActionV1) error {
	return r.w.Write(ctx, globalaudit.Entry{
		TenantID:    action.GetTenantId(),
		EventType:   globalaudit.EventActionValidated,
		Actor:       actor,
		SubjectType: "ResponseAction",
		SubjectID:   action.GetActionId(),
		Description: fmt.Sprintf("action validated: %s", action.GetActionType()),
		TraceID:     action.GetTraceId(),
		RequestID:   action.GetRequestId(),
	})
}

// RecordExecuted writes an ActionExecuted audit entry with before/after state.
func (r *Recorder) RecordExecuted(ctx context.Context, action *casespb.ResponseActionV1, beforeState, afterState interface{}) error {
	return r.w.Write(ctx, globalaudit.Entry{
		TenantID:    action.GetTenantId(),
		EventType:   globalaudit.EventActionExecuted,
		Actor:       actor,
		SubjectType: "ResponseAction",
		SubjectID:   action.GetActionId(),
		Description: fmt.Sprintf("action executed: %s for identity %s", action.GetActionType(), action.GetIdentityId()),
		BeforeState: beforeState,
		AfterState:  afterState,
		TraceID:     action.GetTraceId(),
		RequestID:   action.GetRequestId(),
	})
}

// RecordFailed writes an ActionFailed audit entry.
func (r *Recorder) RecordFailed(ctx context.Context, action *casespb.ResponseActionV1, reason string) error {
	return r.w.Write(ctx, globalaudit.Entry{
		TenantID:    action.GetTenantId(),
		EventType:   globalaudit.EventActionFailed,
		Actor:       actor,
		SubjectType: "ResponseAction",
		SubjectID:   action.GetActionId(),
		Description: fmt.Sprintf("action failed: %s — %s", action.GetActionType(), reason),
		Metadata:    map[string]interface{}{"failure_reason": reason},
		TraceID:     action.GetTraceId(),
		RequestID:   action.GetRequestId(),
	})
}

