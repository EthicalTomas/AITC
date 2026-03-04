package m365_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	commonpb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/common"
	ingestionm365 "github.com/ethicaltomas/aitc/services/ingestion/internal/m365"
	"github.com/ethicaltomas/aitc/services/ingestion/internal/rawarchive"
)

// ---- test doubles ----

type recordingPublisher struct {
	mu  sync.Mutex
	got []*commonpb.EnvelopeV1
}

func (r *recordingPublisher) Publish(_ context.Context, env *commonpb.EnvelopeV1) error {
	r.mu.Lock()
	r.got = append(r.got, env)
	r.mu.Unlock()
	return nil
}

// ---- helpers ----

func tempSampleFile(t *testing.T, records []map[string]interface{}) string {
	t.Helper()
	data, err := json.Marshal(records)
	if err != nil {
		t.Fatalf("marshal sample records: %v", err)
	}
	dir := t.TempDir()
	f := filepath.Join(dir, "sample_m365_ual_events.json")
	if err := os.WriteFile(f, data, 0600); err != nil {
		t.Fatalf("write sample file: %v", err)
	}
	return f
}

func nilPool() *pgxpool.Pool { return nil }

// ---- tests ----

// TestM365MockPoller_LoadsAndPublishes verifies that in mock mode the poller
// reads the sample file, archives (via NoopArchiver), and publishes EnvelopeV1.
func TestM365MockPoller_LoadsAndPublishes(t *testing.T) {
	sampleRecords := []map[string]interface{}{
		{
			"Id":             "m365-event-001",
			"CreationTime":   "2026-03-04T10:00:00Z",
			"Operation":      "UserLoggedIn",
			"OrganizationId": "org-test-id",
			"RecordType":     15,
			"ResultStatus":   "Success",
			"UserId":         "bob@example.com",
			"UserType":       0,
			"Workload":       "AzureActiveDirectory",
			"ObjectId":       "bob@example.com",
			"ClientIP":       "198.51.100.10",
		},
	}

	samplePath := tempSampleFile(t, sampleRecords)

	pub := &recordingPublisher{}

	poller := ingestionm365.NewPoller(
		ingestionm365.PollerConfig{
			TenantIDs:      []string{"tenant-test-001"},
			Mock:           true,
			SampleFilePath: samplePath,
			PollInterval:   1 * time.Hour,
		},
		nilPool(),
		rawarchive.NoopArchiver{},
		pub,
		zap.NewNop(),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- poller.Run(ctx) }()

	// Wait for publish.
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		pub.mu.Lock()
		n := len(pub.got)
		pub.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("poller returned error: %v", err)
	}

	pub.mu.Lock()
	envelopes := pub.got
	pub.mu.Unlock()

	if len(envelopes) == 0 {
		t.Fatal("expected at least one envelope to be published, got 0")
	}

	env := envelopes[0]
	if env.TenantId != "tenant-test-001" {
		t.Errorf("expected tenant_id=tenant-test-001, got %q", env.TenantId)
	}
	if env.Source != commonpb.Source_M365_UAL {
		t.Errorf("expected source=M365_UAL, got %v", env.Source)
	}
	if env.PayloadType != "aitc.events.M365UALEventV1" {
		t.Errorf("expected payload_type=aitc.events.M365UALEventV1, got %q", env.PayloadType)
	}
	if env.SchemaVersion != "v1" {
		t.Errorf("expected schema_version=v1, got %q", env.SchemaVersion)
	}
	if len(env.Payload) == 0 {
		t.Error("expected non-empty payload bytes")
	}
}

// TestM365MockPoller_EmptySampleFile verifies zero publishes for an empty file.
func TestM365MockPoller_EmptySampleFile(t *testing.T) {
	dir := t.TempDir()
	samplePath := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(samplePath, []byte("[]"), 0600); err != nil {
		t.Fatal(err)
	}

	pub := &recordingPublisher{}

	poller := ingestionm365.NewPoller(
		ingestionm365.PollerConfig{
			TenantIDs:      []string{"tenant-empty"},
			Mock:           true,
			SampleFilePath: samplePath,
			PollInterval:   1 * time.Hour,
		},
		nilPool(),
		rawarchive.NoopArchiver{},
		pub,
		zap.NewNop(),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- poller.Run(ctx) }()

	time.Sleep(300 * time.Millisecond)
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("poller returned error: %v", err)
	}

	pub.mu.Lock()
	n := len(pub.got)
	pub.mu.Unlock()
	if n != 0 {
		t.Errorf("expected 0 publishes for empty sample file, got %d", n)
	}
}
