// Package export provides formatters for evidence artifacts.
// Artifacts are emitted as JSON or CSV for archival and auditor delivery.
package export

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Artifact is a named collection of evidence records that can be serialised.
type Artifact struct {
	// ControlID identifies the SOC 2 TSC or ISO 27001 Annex A control.
	ControlID string `json:"control_id"`
	// ControlName is the human-readable control title.
	ControlName string `json:"control_name"`
	// ReportType is "soc2" or "iso27001".
	ReportType string `json:"report_type"`
	// TenantID is the tenant that owns this artifact.
	TenantID string `json:"tenant_id"`
	// PeriodStart / PeriodEnd define the evidence window (RFC 3339).
	PeriodStart string `json:"period_start"`
	PeriodEnd   string `json:"period_end"`
	// Records holds the typed evidence rows returned by the DB query.
	Records interface{} `json:"records"`
	// GeneratedAt is the RFC 3339 timestamp of artifact generation.
	GeneratedAt string `json:"generated_at"`
}

// MarshalJSON serialises the artifact to a compact JSON byte slice.
// Fields are rendered in a stable, deterministic order via the Artifact struct tags.
func MarshalJSON(a *Artifact) ([]byte, error) {
	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(a); err != nil {
		return nil, fmt.Errorf("json export: encode artifact: %w", err)
	}
	return buf.Bytes(), nil
}

