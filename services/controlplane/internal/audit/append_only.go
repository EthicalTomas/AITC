// Package audit provides a thin wrapper around internal/audit for the controlplane service.
// All policy decisions and state changes must be written to the audit log (Step 0.4).
package audit

import (
	"context"

	globalaudit "github.com/ethicaltomas/aitc/internal/audit"
	ctrpolicy "github.com/ethicaltomas/aitc/services/controlplane/internal/policy"
)

// Recorder writes controlplane-specific audit events.
type Recorder struct {
	writer *globalaudit.Writer
}

// NewRecorder creates a Recorder backed by the global audit writer.
func NewRecorder(w *globalaudit.Writer) *Recorder {
	return &Recorder{writer: w}
}

// RecordDecision appends a policy decision to the audit log.
// Must be called for every Validate() call regardless of outcome (Step 0.4).
func (r *Recorder) RecordDecision(ctx context.Context, d ctrpolicy.Decision) error {
	reasons := ""
	if len(d.RejectionReasons) > 0 {
		for i, re := range d.RejectionReasons {
			if i > 0 {
				reasons += "; "
			}
			reasons += re
		}
	}

	eventType := globalaudit.EventActionValidated
	if !d.Allowed {
		eventType = globalaudit.EventActionRejected
	}

	return r.writer.Write(ctx, globalaudit.Entry{
		TenantID:    d.TenantID,
		EventType:   eventType,
		Actor:       "controlplane",
		SubjectType: "ResponseAction",
		SubjectID:   d.ActionID,
		Description: reasons,
		Metadata: map[string]interface{}{
			"decision_id":      d.DecisionID,
			"action_type":      d.ActionType,
			"allowed":          d.Allowed,
			"in_learning_mode": d.InLearningMode,
			"blast_radius":     d.BlastRadiusScore,
		},
	})
}

// RecordAutonomyStateChange appends an autonomy state change to the audit log.
func (r *Recorder) RecordAutonomyStateChange(ctx context.Context, tenantID, actor, description string, before, after interface{}) error {
	return r.writer.Write(ctx, globalaudit.Entry{
		TenantID:    tenantID,
		EventType:   globalaudit.EventAutonomyStateChanged,
		Actor:       actor,
		SubjectType: "Tenant",
		SubjectID:   tenantID,
		Description: description,
		BeforeState: before,
		AfterState:  after,
	})
}

