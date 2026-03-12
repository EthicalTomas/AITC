package export_test

import (
	"strings"
	"testing"
	"time"

	"github.com/ethicaltomas/aitc/services/evidence/internal/export"
)

type testRow struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Count int    `json:"count"`
}

func makeArtifact(records interface{}) *export.Artifact {
	return &export.Artifact{
		ControlID:   "CC6.1",
		ControlName: "Test Control",
		ReportType:  "soc2",
		TenantID:    "tenant-test",
		PeriodStart: time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339),
		PeriodEnd:   time.Now().UTC().Format(time.RFC3339),
		Records:     records,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

func TestMarshalJSON_WithRecords(t *testing.T) {
	records := []testRow{
		{ID: "1", Email: "alice@example.com", Count: 3},
		{ID: "2", Email: "bob@example.com", Count: 1},
	}
	a := makeArtifact(records)

	data, err := export.MarshalJSON(a)
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}

	s := string(data)
	if !strings.Contains(s, "alice@example.com") {
		t.Error("expected alice@example.com in JSON output")
	}
	if !strings.Contains(s, "CC6.1") {
		t.Error("expected control_id CC6.1 in JSON output")
	}
	if !strings.Contains(s, `"report_type": "soc2"`) {
		t.Error("expected report_type soc2 in JSON output")
	}
}

func TestMarshalJSON_NilRecords(t *testing.T) {
	a := makeArtifact(nil)
	data, err := export.MarshalJSON(a)
	if err != nil {
		t.Fatalf("MarshalJSON nil records: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty JSON for nil records")
	}
}

func TestMarshalCSV_WithRecords(t *testing.T) {
	records := []testRow{
		{ID: "1", Email: "alice@example.com", Count: 3},
		{ID: "2", Email: "bob@example.com", Count: 1},
	}
	a := makeArtifact(records)

	data, err := export.MarshalCSV(a)
	if err != nil {
		t.Fatalf("MarshalCSV: %v", err)
	}

	s := string(data)
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) != 3 { // header + 2 data rows
		t.Errorf("expected 3 lines (header+2 rows), got %d:\n%s", len(lines), s)
	}

	// Header should contain JSON tag names.
	if !strings.Contains(lines[0], "id") {
		t.Errorf("expected 'id' in CSV header, got: %s", lines[0])
	}
	if !strings.Contains(lines[0], "email") {
		t.Errorf("expected 'email' in CSV header, got: %s", lines[0])
	}

	// Data rows.
	if !strings.Contains(s, "alice@example.com") {
		t.Error("expected alice@example.com in CSV output")
	}
}

func TestMarshalCSV_NilRecords(t *testing.T) {
	a := makeArtifact(nil)
	data, err := export.MarshalCSV(a)
	if err != nil {
		t.Fatalf("MarshalCSV nil records: %v", err)
	}
	// Should return fallback header row.
	if !strings.Contains(string(data), "control_id") {
		t.Error("expected fallback header in nil CSV output")
	}
}

func TestMarshalCSV_EmptySlice(t *testing.T) {
	a := makeArtifact([]testRow{})
	data, err := export.MarshalCSV(a)
	if err != nil {
		t.Fatalf("MarshalCSV empty slice: %v", err)
	}
	// Empty slice: no header, no rows (struct headers require at least one element).
	_ = data
}

func TestMarshalCSV_NonSlice(t *testing.T) {
	a := makeArtifact("not a slice")
	_, err := export.MarshalCSV(a)
	if err == nil {
		t.Error("expected error for non-slice Records")
	}
}
