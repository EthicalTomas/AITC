package archive_test

import (
	"testing"

	"github.com/ethicaltomas/aitc/services/evidence/internal/archive"
)

func TestBuildKey_Format(t *testing.T) {
	key := archive.BuildKey("tenant-abc", "soc2", "report-xyz")
	expected := "reports/tenant-abc/soc2/report-xyz.json"
	if key != expected {
		t.Errorf("BuildKey: got %q, want %q", key, expected)
	}
}

func TestBuildKey_ISO(t *testing.T) {
	key := archive.BuildKey("tenant-123", "iso27001", "rpt-456")
	expected := "reports/tenant-123/iso27001/rpt-456.json"
	if key != expected {
		t.Errorf("BuildKey ISO: got %q, want %q", key, expected)
	}
}

func TestNoopUploader_Upload(t *testing.T) {
	n := &archive.NoopUploader{Bucket: "test-bucket"}
	err := n.Upload(nil, "tenant-abc", "report-xyz", "reports/x.json", []byte(`{}`)) //nolint:staticcheck
	if err != nil {
		t.Fatalf("NoopUploader.Upload: %v", err)
	}
}
