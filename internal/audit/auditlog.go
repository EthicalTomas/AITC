package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// EventType constants for audit log entries.
const (
	EventIngestCheckpointUpdated   = "IngestCheckpointUpdated"
	EventRiskSignalEmitted         = "RiskSignalEmitted"
	EventCaseCreated               = "CaseCreated"
	EventCaseUpdated               = "CaseUpdated"
	EventCaseClosed                = "CaseClosed"
	EventActionProposed            = "ActionProposed"
	EventActionValidated           = "ActionValidated"
	EventActionRejected            = "ActionRejected"
	EventActionExecuted            = "ActionExecuted"
	EventActionFailed              = "ActionFailed"
	EventActionRolledBack          = "ActionRolledBack"
	EventAutonomyStateChanged      = "AutonomyStateChanged"
	EventComplianceReportGenerated = "ComplianceReportGenerated"
)

// Entry represents an audit log record.
type Entry struct {
	ID          string
	TenantID    string
	EventType   string
	Actor       string // service name or user ID
	SubjectType string
	SubjectID   string
	Description string
	BeforeState interface{}
	AfterState  interface{}
	Metadata    map[string]interface{}
	TraceID     string
	RequestID   string
	OccurredAt  time.Time
}

// Writer writes append-only audit log entries.
type Writer struct {
	pool *pgxpool.Pool
}

// NewWriter creates a new audit log writer.
func NewWriter(pool *pgxpool.Pool) *Writer {
	return &Writer{pool: pool}
}

// Write appends an audit entry to the audit_log table.
// SECURITY: This is append-only; the DB role must not have UPDATE/DELETE on audit_log.
func (w *Writer) Write(ctx context.Context, e Entry) error {
	if e.TenantID == "" {
		return fmt.Errorf("audit: tenant_id is required")
	}
	if e.EventType == "" {
		return fmt.Errorf("audit: event_type is required")
	}
	if e.Actor == "" {
		return fmt.Errorf("audit: actor is required")
	}

	if e.ID == "" {
		e.ID = uuid.New().String()
	}
	if e.OccurredAt.IsZero() {
		e.OccurredAt = time.Now().UTC()
	}

	beforeJSON, _ := json.Marshal(e.BeforeState)
	afterJSON, _ := json.Marshal(e.AfterState)
	metaJSON, _ := json.Marshal(e.Metadata)

	_, err := w.pool.Exec(ctx, `
		INSERT INTO audit_log
			(id, tenant_id, event_type, actor, subject_type, subject_id,
			 description, before_state, after_state, metadata,
			 trace_id, request_id, occurred_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		e.ID, e.TenantID, e.EventType, e.Actor,
		e.SubjectType, e.SubjectID, e.Description,
		beforeJSON, afterJSON, metaJSON,
		e.TraceID, e.RequestID, e.OccurredAt,
	)
	if err != nil {
		return fmt.Errorf("audit write: %w", err)
	}
	return nil
}
