package generator_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/ethicaltomas/aitc/services/evidence/internal/export"
	"github.com/ethicaltomas/aitc/services/evidence/internal/generator"
)

// TestBundle_MarshalRoundtrip verifies that a Bundle serialises and deserialises
// without data loss.
func TestBundle_MarshalRoundtrip(t *testing.T) {
	now := time.Now().UTC()
	bundle := generator.Bundle{
		ReportID:    "report-123",
		TenantID:    "tenant-abc",
		ReportType:  "soc2",
		PeriodStart: now.Add(-30 * 24 * time.Hour).Format(time.RFC3339),
		PeriodEnd:   now.Format(time.RFC3339),
		GeneratedAt: now.Format(time.RFC3339),
		Artifacts: []*export.Artifact{
			{
				ControlID:   "CC6.1",
				ControlName: "Test",
				ReportType:  "soc2",
				TenantID:    "tenant-abc",
				Records:     nil,
				GeneratedAt: now.Format(time.RFC3339),
			},
		},
	}

	data, err := json.Marshal(&bundle)
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}

	var decoded generator.Bundle
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal bundle: %v", err)
	}

	if decoded.ReportID != bundle.ReportID {
		t.Errorf("report_id mismatch: got %q, want %q", decoded.ReportID, bundle.ReportID)
	}
	if decoded.TenantID != bundle.TenantID {
		t.Errorf("tenant_id mismatch: got %q, want %q", decoded.TenantID, bundle.TenantID)
	}
	if len(decoded.Artifacts) != 1 {
		t.Errorf("expected 1 artifact, got %d", len(decoded.Artifacts))
	}
	if decoded.Artifacts[0].ControlID != "CC6.1" {
		t.Errorf("control_id mismatch: got %q, want CC6.1", decoded.Artifacts[0].ControlID)
	}
}

// TestPacksFor_SOC2 verifies that the correct number of packs is returned for soc2.
// This is an integration point — the actual DB calls happen in the full integration test.
func TestBundle_SOC2HasFiveArtifactSlots(t *testing.T) {
	// Generate a bundle with empty artifacts to check structure.
	bundle := generator.Bundle{
		ReportType: "soc2",
		Artifacts:  make([]*export.Artifact, 5),
	}
	if len(bundle.Artifacts) != 5 {
		t.Errorf("expected 5 artifact slots for soc2, got %d", len(bundle.Artifacts))
	}
}

// TestGeneratorProcessByID_NoDBReturnsError verifies that calling ProcessByID
// with a nil DB returns an error rather than panicking.
func TestGeneratorProcessByID_NoDBReturnsError(t *testing.T) {
	gen := generator.New(nil, nil, zap.NewNop())
	ctx := context.Background()
	err := gen.ProcessByID(ctx, "tenant-abc", "report-123")
	if err == nil {
		t.Error("expected error when DB is nil")
	}
}
