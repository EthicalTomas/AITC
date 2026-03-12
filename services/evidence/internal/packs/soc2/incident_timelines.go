package soc2

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ethicaltomas/aitc/internal/tenant"
	"github.com/ethicaltomas/aitc/services/evidence/internal/export"
)

// IncidentTimelineRow represents one event on an incident timeline.
type IncidentTimelineRow struct {
	CaseID      string `json:"case_id"      csv:"case_id"`
	CaseTitle   string `json:"case_title"   csv:"case_title"`
	CaseStatus  string `json:"case_status"  csv:"case_status"`
	Severity    string `json:"severity"     csv:"severity"`
	EventType   string `json:"event_type"   csv:"event_type"`
	Description string `json:"description"  csv:"description"`
	Actor       string `json:"actor"        csv:"actor"`
	OccurredAt  string `json:"occurred_at"  csv:"occurred_at"`
}

// GenerateIncidentTimelines produces a CC7.4 incident-timeline artifact.
// For each Case in the period it joins risk_signals, response_actions, and the
// audit_log to reconstruct the full incident timeline, providing evidence of
// detection, investigation, and response activities.
func GenerateIncidentTimelines(ctx context.Context, db *pgxpool.Pool, tenantID string, periodStart, periodEnd time.Time) (*export.Artifact, error) {
	tx, err := db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("incident_timelines: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if err := tenant.SetRLS(ctx, tx, tenantID); err != nil {
		return nil, fmt.Errorf("incident_timelines: set rls: %w", err)
	}

	// Reconstruct timeline: case open + signals + actions + audit entries.
	rows, err := tx.Query(ctx,
		`-- Case opened
		 SELECT c.id::text, c.title, c.status, c.severity,
		        'case_opened' AS event_type,
		        'Case created: ' || c.title AS description,
		        COALESCE(c.assigned_to, 'system') AS actor,
		        c.created_at AS occurred_at
		   FROM cases c
		  WHERE c.tenant_id = $1
		    AND c.created_at BETWEEN $2 AND $3

		 UNION ALL

		 -- Risk signals attached to cases in period
		 SELECT c.id::text, c.title, c.status, c.severity,
		        'risk_signal' AS event_type,
		        rs.rule_name || ' (' || rs.severity || ')' AS description,
		        'pipeline' AS actor,
		        rs.detected_at AS occurred_at
		   FROM risk_signals rs
		   JOIN cases c ON c.id = rs.case_id AND c.tenant_id = $1
		  WHERE rs.tenant_id = $1
		    AND rs.detected_at BETWEEN $2 AND $3

		 UNION ALL

		 -- Response actions on cases in period
		 SELECT c.id::text, c.title, c.status, c.severity,
		        'response_action' AS event_type,
		        ra.action_type || ' — ' || ra.status AS description,
		        COALESCE(ra.executed_by, 'system') AS actor,
		        ra.proposed_at AS occurred_at
		   FROM response_actions ra
		   JOIN cases c ON c.id = ra.case_id AND c.tenant_id = $1
		  WHERE ra.tenant_id = $1
		    AND ra.proposed_at BETWEEN $2 AND $3

		 UNION ALL

		 -- Audit log entries for cases in period
		 SELECT c.id::text, c.title, c.status, c.severity,
		        al.event_type AS event_type,
		        COALESCE(al.description, al.event_type) AS description,
		        al.actor AS actor,
		        al.occurred_at AS occurred_at
		   FROM audit_log al
		   JOIN cases c ON c.id::text = al.subject_id AND c.tenant_id = $1
		  WHERE al.tenant_id = $1
		    AND al.subject_type = 'Case'
		    AND al.occurred_at BETWEEN $2 AND $3

		 ORDER BY occurred_at DESC`,
		tenantID, periodStart, periodEnd)
	if err != nil {
		return nil, fmt.Errorf("incident_timelines: query: %w", err)
	}
	defer rows.Close()

	var records []IncidentTimelineRow
	for rows.Next() {
		var r IncidentTimelineRow
		var occurredAt time.Time
		if err := rows.Scan(&r.CaseID, &r.CaseTitle, &r.CaseStatus, &r.Severity,
			&r.EventType, &r.Description, &r.Actor, &occurredAt); err != nil {
			return nil, fmt.Errorf("incident_timelines: scan: %w", err)
		}
		r.OccurredAt = occurredAt.UTC().Format(time.RFC3339)
		records = append(records, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("incident_timelines: rows: %w", err)
	}

	return &export.Artifact{
		ControlID:   "CC7.4",
		ControlName: "System Operations — Incident Timelines",
		ReportType:  "soc2",
		TenantID:    tenantID,
		PeriodStart: periodStart.UTC().Format(time.RFC3339),
		PeriodEnd:   periodEnd.UTC().Format(time.RFC3339),
		Records:     records,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

