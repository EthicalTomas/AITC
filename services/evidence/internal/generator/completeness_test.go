// Package generator_test contains completeness tests that verify the SOC 2 and
// ISO 27001 evidence export artifacts produced by this service include all
// fields required by docs/compliance/soc2-iso-pack.md.
//
// Tests run entirely in-memory (no DB required): each test builds a fixture
// Artifact and verifies its JSON / CSV output against:
//
//  1. A set of required field/column names derived from the compliance spec.
//  2. A golden file stored under testdata/ for exact structural regression.
//
// To regenerate golden files after an intentional format change, run:
//
//	go test ./services/evidence/internal/generator/... -run TestGolden -update
package generator_test

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethicaltomas/aitc/services/evidence/internal/export"
	"github.com/ethicaltomas/aitc/services/evidence/internal/packs/iso27001"
	"github.com/ethicaltomas/aitc/services/evidence/internal/packs/soc2"
)

var updateGolden = flag.Bool("update", false, "regenerate golden testdata files from current output")

// ── Fixed deterministic timestamps used in all fixture data ────────────────

var (
	fixtureGenAt      = time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	fixturePeriodStart = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fixturePeriodEnd   = time.Date(2026, 1, 31, 23, 59, 59, 0, time.UTC)
	fixtureCreatedAt  = time.Date(2026, 1, 1, 8, 0, 0, 0, time.UTC)
	fixtureUpdatedAt  = time.Date(2026, 1, 10, 8, 0, 0, 0, time.UTC)
)

const fixtureTenantID = "tenant-test-fixture"

// ── Helpers ────────────────────────────────────────────────────────────────

func fixtureArtifact(controlID, controlName, reportType string, records interface{}) *export.Artifact {
	return &export.Artifact{
		ControlID:   controlID,
		ControlName: controlName,
		ReportType:  reportType,
		TenantID:    fixtureTenantID,
		PeriodStart: fixturePeriodStart.UTC().Format(time.RFC3339),
		PeriodEnd:   fixturePeriodEnd.UTC().Format(time.RFC3339),
		Records:     records,
		GeneratedAt: fixtureGenAt.UTC().Format(time.RFC3339),
	}
}

// assertArtifactFields verifies that the artifact's top-level metadata fields
// required by the compliance pack are present and non-empty.
func assertArtifactFields(t *testing.T, a *export.Artifact) {
	t.Helper()
	if a.ControlID == "" {
		t.Error("artifact: control_id is empty")
	}
	if a.ControlName == "" {
		t.Error("artifact: control_name is empty")
	}
	if a.ReportType == "" {
		t.Error("artifact: report_type is empty")
	}
	if a.TenantID == "" {
		t.Error("artifact: tenant_id is empty")
	}
	if a.PeriodStart == "" {
		t.Error("artifact: period_start is empty")
	}
	if a.PeriodEnd == "" {
		t.Error("artifact: period_end is empty")
	}
	if a.GeneratedAt == "" {
		t.Error("artifact: generated_at is empty")
	}
}

// assertRequiredJSONKeys verifies that the JSON-serialised artifact contains
// all of the given field-name tokens.
func assertRequiredJSONKeys(t *testing.T, a *export.Artifact, keys []string) {
	t.Helper()
	data, err := export.MarshalJSON(a)
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	s := string(data)
	for _, k := range keys {
		needle := `"` + k + `"`
		if !strings.Contains(s, needle) {
			t.Errorf("JSON output is missing required key %q", k)
		}
	}
}

// assertRequiredCSVCols verifies that the CSV-serialised artifact's header row
// contains all of the given column names.
func assertRequiredCSVCols(t *testing.T, a *export.Artifact, cols []string) {
	t.Helper()
	data, err := export.MarshalCSV(a)
	if err != nil {
		t.Fatalf("MarshalCSV: %v", err)
	}
	lines := strings.SplitN(string(data), "\n", 2)
	if len(lines) == 0 {
		t.Fatal("CSV output is empty")
	}
	header := lines[0]
	for _, c := range cols {
		if !strings.Contains(header, c) {
			t.Errorf("CSV header is missing required column %q (header: %s)", c, header)
		}
	}
}

// assertGoldenJSON compares the JSON output of a against the file at golden.
// When -update is passed the golden file is (re)written from the current output.
func assertGoldenJSON(t *testing.T, golden string, a *export.Artifact) {
	t.Helper()
	got, err := export.MarshalJSON(a)
	if err != nil {
		t.Fatalf("MarshalJSON for golden: %v", err)
	}
	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
			t.Fatalf("mkdir testdata: %v", err)
		}
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatalf("write golden %s: %v", golden, err)
		}
		return
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden %s (run with -update to create): %v", golden, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("JSON output does not match golden file %s\n--- want ---\n%s\n--- got ---\n%s", golden, want, got)
	}
}

// assertGoldenCSV compares the CSV output of a against the file at golden.
func assertGoldenCSV(t *testing.T, golden string, a *export.Artifact) {
	t.Helper()
	got, err := export.MarshalCSV(a)
	if err != nil {
		t.Fatalf("MarshalCSV for golden: %v", err)
	}
	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
			t.Fatalf("mkdir testdata: %v", err)
		}
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatalf("write golden %s: %v", golden, err)
		}
		return
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden %s (run with -update to create): %v", golden, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("CSV output does not match golden file %s\n--- want ---\n%s\n--- got ---\n%s", golden, want, got)
	}
}

// ── SOC 2 compliance assertions ────────────────────────────────────────────
//
// Required fields come from docs/compliance/soc2-iso-pack.md §3 (Control Mapping).

// TestSOC2_CC6_1_AccessRoster verifies that the CC6.1 access-control roster
// artifact includes all identity fields required by the compliance pack.
func TestSOC2_CC6_1_AccessRoster(t *testing.T) {
	records := []soc2.IdentityRow{
		{
			ID:           "id-001",
			ProviderID:   "okta-001",
			Provider:     "okta",
			Email:        "alice@example.com",
			DisplayName:  "Alice Smith",
			Roles:        "admin,analyst",
			IsPrivileged: true,
			MFAEnrolled:  true,
			CreatedAt:    fixtureCreatedAt.UTC().Format(time.RFC3339),
			UpdatedAt:    fixtureUpdatedAt.UTC().Format(time.RFC3339),
		},
	}
	a := fixtureArtifact("CC6.1", "Logical and Physical Access Controls — Access Roster", "soc2", records)

	assertArtifactFields(t, a)

	// Compliance spec §3 CC6.1: identity inventory with role/group membership, MFA status.
	required := []string{"id", "email", "provider", "roles", "is_privileged", "mfa_enrolled", "display_name"}
	assertRequiredJSONKeys(t, a, required)
	assertRequiredCSVCols(t, a, required)

	assertGoldenJSON(t, "testdata/expected_soc2_access_control.json", a)
	assertGoldenCSV(t, "testdata/expected_soc2_access_control.csv", a)
}

// TestSOC2_CC6_3_MFACoverage verifies the CC6.3 MFA coverage artifact.
func TestSOC2_CC6_3_MFACoverage(t *testing.T) {
	records := []soc2.MFARow{
		{
			ID:           "id-002",
			Email:        "bob@example.com",
			Provider:     "okta",
			MFAEnrolled:  true,
			IsPrivileged: false,
			UpdatedAt:    fixtureUpdatedAt.UTC().Format(time.RFC3339),
		},
	}
	a := fixtureArtifact("CC6.3", "Logical and Physical Access Controls — MFA Coverage", "soc2", records)

	assertArtifactFields(t, a)

	// Compliance spec §3 CC6.3 / CC6.6: MFA enrollment status per identity.
	required := []string{"id", "email", "provider", "mfa_enrolled", "is_privileged"}
	assertRequiredJSONKeys(t, a, required)
	assertRequiredCSVCols(t, a, required)

	assertGoldenJSON(t, "testdata/expected_soc2_mfa_coverage.json", a)
	assertGoldenCSV(t, "testdata/expected_soc2_mfa_coverage.csv", a)
}

// TestSOC2_CC6_2_PrivilegedInventory verifies the CC6.2 privileged-access
// inventory artifact.
func TestSOC2_CC6_2_PrivilegedInventory(t *testing.T) {
	records := []soc2.PrivilegedRow{
		{
			ID:          "id-003",
			Email:       "carol@example.com",
			DisplayName: "Carol Jones",
			Provider:    "okta",
			Roles:       "super-admin",
			MFAEnrolled: true,
			CreatedAt:   fixtureCreatedAt.UTC().Format(time.RFC3339),
			UpdatedAt:   fixtureUpdatedAt.UTC().Format(time.RFC3339),
		},
	}
	a := fixtureArtifact("CC6.2", "Logical and Physical Access Controls — Privileged Access Inventory", "soc2", records)

	assertArtifactFields(t, a)

	// Compliance spec §3 CC6.2: privileged access list with roles and MFA status.
	required := []string{"id", "email", "display_name", "provider", "roles", "mfa_enrolled"}
	assertRequiredJSONKeys(t, a, required)
	assertRequiredCSVCols(t, a, required)

	assertGoldenJSON(t, "testdata/expected_soc2_privileged_inventory.json", a)
	assertGoldenCSV(t, "testdata/expected_soc2_privileged_inventory.csv", a)
}

// TestSOC2_CC7_2_AdminActivity verifies the CC7.2 administrative-activity
// artifact contains all fields required by compliance spec §3 CC7.
func TestSOC2_CC7_2_AdminActivity(t *testing.T) {
	records := []soc2.AdminActivityRow{
		{
			ID:         "evt-001",
			Source:     "okta",
			Action:     "admin_change.role.assigned",
			Outcome:    "success",
			ActorID:    "actor-001",
			ActorEmail: "admin@example.com",
			TargetID:   "user-001",
			TargetType: "User",
			OccurredAt: fixtureCreatedAt.UTC().Format(time.RFC3339),
		},
	}
	a := fixtureArtifact("CC7.2", "System Operations — Administrative Activity Log", "soc2", records)

	assertArtifactFields(t, a)

	// Compliance spec §3 CC7.2: admin change events with actor, target, outcome.
	required := []string{"id", "source", "action", "outcome", "actor_id", "actor_email", "target_id", "target_type", "occurred_at"}
	assertRequiredJSONKeys(t, a, required)
	assertRequiredCSVCols(t, a, required)

	assertGoldenJSON(t, "testdata/expected_soc2_admin_activity.json", a)
	assertGoldenCSV(t, "testdata/expected_soc2_admin_activity.csv", a)
}

// TestSOC2_CC7_4_IncidentTimelines verifies the CC7.4 incident-timeline
// artifact contains all required fields from compliance spec §2.2 and §3 CC7.
func TestSOC2_CC7_4_IncidentTimelines(t *testing.T) {
	records := []soc2.IncidentTimelineRow{
		{
			CaseID:      "case-001",
			CaseTitle:   "Impossible travel detected",
			CaseStatus:  "resolved",
			Severity:    "high",
			EventType:   "case_opened",
			Description: "Case created: Impossible travel detected",
			Actor:       "pipeline",
			OccurredAt:  fixtureCreatedAt.UTC().Format(time.RFC3339),
		},
		{
			CaseID:      "case-001",
			CaseTitle:   "Impossible travel detected",
			CaseStatus:  "resolved",
			Severity:    "high",
			EventType:   "response_action",
			Description: "revoke_sessions — executed",
			Actor:       "system",
			OccurredAt:  fixtureUpdatedAt.UTC().Format(time.RFC3339),
		},
	}
	a := fixtureArtifact("CC7.4", "System Operations — Incident Timelines", "soc2", records)

	assertArtifactFields(t, a)

	// Compliance spec §2.2 / §3 CC7.4: incident timeline with case, event, actor, timestamp.
	required := []string{"case_id", "case_title", "case_status", "severity", "event_type", "description", "actor", "occurred_at"}
	assertRequiredJSONKeys(t, a, required)
	assertRequiredCSVCols(t, a, required)

	assertGoldenJSON(t, "testdata/expected_soc2_incident_timelines.json", a)
	assertGoldenCSV(t, "testdata/expected_soc2_incident_timelines.csv", a)
}

// ── ISO 27001:2022 compliance assertions ───────────────────────────────────
//
// Required fields come from docs/compliance/soc2-iso-pack.md §4 (ISO 27001 Mapping).

// TestISO27001_A5_15_AccessControl verifies the A.5.15 access-control artifact
// (ISO 27001:2022 identity inventory).
func TestISO27001_A5_15_AccessControl(t *testing.T) {
	records := []iso27001.ISOIdentityRow{
		{
			ID:           "id-101",
			Email:        "dave@example.com",
			DisplayName:  "Dave Kim",
			Provider:     "m365",
			Roles:        "GlobalAdmin",
			IsPrivileged: true,
			MFAEnrolled:  true,
			CreatedAt:    fixtureCreatedAt.UTC().Format(time.RFC3339),
		},
	}
	a := fixtureArtifact("A.5.15", "ISO 27001:2022 — Access Control (Identity Inventory)", "iso27001", records)

	assertArtifactFields(t, a)
	if a.ReportType != "iso27001" {
		t.Errorf("report_type: got %q, want iso27001", a.ReportType)
	}

	// Compliance spec §4 A.5.15/A.5.18: identity inventory with role membership and MFA.
	required := []string{"id", "email", "display_name", "provider", "roles", "is_privileged", "mfa_enrolled"}
	assertRequiredJSONKeys(t, a, required)
	assertRequiredCSVCols(t, a, required)

	assertGoldenJSON(t, "testdata/expected_iso27001_access_control.json", a)
	assertGoldenCSV(t, "testdata/expected_iso27001_access_control.csv", a)
}

// TestISO27001_A5_26_IncidentManagement verifies the A.5.26 incident-management
// artifact (ISO 27001:2022 response to information security incidents).
func TestISO27001_A5_26_IncidentManagement(t *testing.T) {
	records := []iso27001.IncidentMgmtRow{
		{
			CaseID:     "case-201",
			Title:      "Credential stuffing attempt",
			Status:     "resolved",
			Severity:   "high",
			AssignedTo: "security-team",
			CreatedAt:  fixtureCreatedAt.UTC().Format(time.RFC3339),
			ClosedAt:   fixtureUpdatedAt.UTC().Format(time.RFC3339),
		},
	}
	a := fixtureArtifact("A.5.26", "ISO 27001:2022 — Response to Information Security Incidents", "iso27001", records)

	assertArtifactFields(t, a)

	// Compliance spec §4 A.5.26/A.5.27: case records with title, status, severity, resolution.
	required := []string{"case_id", "title", "status", "severity", "assigned_to", "created_at", "closed_at"}
	assertRequiredJSONKeys(t, a, required)
	assertRequiredCSVCols(t, a, required)

	assertGoldenJSON(t, "testdata/expected_iso27001_incident_mgmt.json", a)
	assertGoldenCSV(t, "testdata/expected_iso27001_incident_mgmt.csv", a)
}

// TestISO27001_A8_15_LoggingMonitoring verifies the A.8.15 logging and monitoring
// artifact (ISO 27001:2022 audit-log evidence).
func TestISO27001_A8_15_LoggingMonitoring(t *testing.T) {
	records := []iso27001.AuditLogRow{
		{
			ID:          "log-301",
			EventType:   "aitc.action.executed",
			Actor:       "system",
			SubjectType: "Case",
			SubjectID:   "case-201",
			Description: "revoke_sessions executed successfully",
			OccurredAt:  fixtureCreatedAt.UTC().Format(time.RFC3339),
		},
	}
	a := fixtureArtifact("A.8.15", "ISO 27001:2022 — Logging and Monitoring", "iso27001", records)

	assertArtifactFields(t, a)

	// Compliance spec §4 A.8.15/A.8.16: append-only audit log with event, actor, subject.
	required := []string{"id", "event_type", "actor", "subject_type", "subject_id", "description", "occurred_at"}
	assertRequiredJSONKeys(t, a, required)
	assertRequiredCSVCols(t, a, required)

	assertGoldenJSON(t, "testdata/expected_iso27001_logging_monitoring.json", a)
	assertGoldenCSV(t, "testdata/expected_iso27001_logging_monitoring.csv", a)
}

// ── Bundle structure assertions ────────────────────────────────────────────

// TestSOC2BundleControlIDs verifies that a SOC 2 bundle serialises all five
// required control artifacts and includes the expected control IDs.
func TestSOC2BundleControlIDs(t *testing.T) {
	requiredControlIDs := []string{"CC6.1", "CC6.2", "CC6.3", "CC7.2", "CC7.4"}

	arts := make([]*export.Artifact, len(requiredControlIDs))
	for i, id := range requiredControlIDs {
		arts[i] = &export.Artifact{ControlID: id, ReportType: "soc2"}
	}

	var buf bytes.Buffer
	for _, a := range arts {
		data, err := export.MarshalJSON(a)
		if err != nil {
			t.Fatalf("marshal artifact: %v", err)
		}
		buf.Write(data)
	}
	s := buf.String()

	for _, id := range requiredControlIDs {
		if !strings.Contains(s, id) {
			t.Errorf("SOC2 artifacts missing required control_id %q", id)
		}
	}
}

// TestISO27001BundleControlIDs verifies that an ISO 27001 bundle serialises all
// three required control artifacts using ISO 27001:2022 control IDs.
func TestISO27001BundleControlIDs(t *testing.T) {
	// These control IDs must match the 2022 Annex A numbering used in
	// docs/compliance/soc2-iso-pack.md §4.
	requiredControlIDs := []string{"A.5.15", "A.5.26", "A.8.15"}

	arts := make([]*export.Artifact, len(requiredControlIDs))
	for i, id := range requiredControlIDs {
		arts[i] = &export.Artifact{ControlID: id, ReportType: "iso27001"}
	}

	var buf bytes.Buffer
	for _, a := range arts {
		data, err := export.MarshalJSON(a)
		if err != nil {
			t.Fatalf("marshal artifact: %v", err)
		}
		buf.Write(data)
	}
	s := buf.String()

	for _, id := range requiredControlIDs {
		if !strings.Contains(s, id) {
			t.Errorf("ISO 27001 artifacts missing required control_id %q", id)
		}
	}
}
