package okta_test

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
	ingestionokta "github.com/ethicaltomas/aitc/services/ingestion/internal/okta"
	"github.com/ethicaltomas/aitc/services/ingestion/internal/rawarchive"
)

// ---- test doubles ----

// recordingPublisher captures all published envelopes for assertions.
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

func tempSampleFile(t *testing.T, events []map[string]interface{}) string {
	t.Helper()
	data, err := json.Marshal(events)
	if err != nil {
		t.Fatalf("marshal sample events: %v", err)
	}
	dir := t.TempDir()
	f := filepath.Join(dir, "sample_okta_events.json")
	if err := os.WriteFile(f, data, 0600); err != nil {
		t.Fatalf("write sample file: %v", err)
	}
	return f
}

// ---- tests ----

// TestOktaMockPoller_LoadsAndPublishes verifies that in mock mode the poller
// reads the sample file, archives (via NoopArchiver), inserts DB refs, and
// publishes EnvelopeV1 messages on Kafka.
// DB interactions are skipped by passing a nil pool; the poller handles nil
// DB gracefully by skipping checkpoint/ref inserts.
func TestOktaMockPoller_LoadsAndPublishes(t *testing.T) {
	sampleEvents := []map[string]interface{}{
		{
			"uuid":           "test-event-001",
			"published":      "2026-03-04T10:00:00Z",
			"eventType":      "user.session.start",
			"displayMessage": "User login to Okta",
			"severity":       "INFO",
			"actor": map[string]interface{}{
				"id":          "uid-001",
				"type":        "User",
				"alternateId": "alice@example.com",
				"displayName": "Alice Smith",
			},
			"outcome":               map[string]interface{}{"result": "SUCCESS", "reason": ""},
			"client":                map[string]interface{}{"ipAddress": "203.0.113.1"},
			"authenticationContext": map[string]interface{}{},
			"target":                []interface{}{},
			"transaction":           map[string]interface{}{"id": "txn-001"},
			"request":               map[string]interface{}{"ipChain": []interface{}{}},
		},
	}

	samplePath := tempSampleFile(t, sampleEvents)

	pub := &recordingPublisher{}
	archiver := rawarchive.NoopArchiver{}

	logger := zap.NewNop()

	poller := ingestionokta.NewPoller(
		ingestionokta.PollerConfig{
			TenantIDs:      []string{"tenant-test-001"},
			Mock:           true,
			SampleFilePath: samplePath,
			PollInterval:   1 * time.Hour, // not triggered; we call Run with immediate cancel
		},
		nilPool(), // nil pool — poller skips DB when pool unavailable
		archiver,
		pub,
		logger,
	)

	// Run one poll cycle by cancelling context immediately after the first tick.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Run in a goroutine; it will poll once then block on ticker.
	done := make(chan error, 1)
	go func() { done <- poller.Run(ctx) }()

	// Wait for at least one publish.
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

	cancel() // stop the poller
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
	if env.Source != commonpb.Source_OKTA_SYSTEM_LOG {
		t.Errorf("expected source=OKTA_SYSTEM_LOG, got %v", env.Source)
	}
	if env.PayloadType != "aitc.events.OktaSystemLogEventV1" {
		t.Errorf("expected payload_type=aitc.events.OktaSystemLogEventV1, got %q", env.PayloadType)
	}
	if env.SchemaVersion != "v1" {
		t.Errorf("expected schema_version=v1, got %q", env.SchemaVersion)
	}
	if len(env.Payload) == 0 {
		t.Error("expected non-empty payload bytes")
	}
}

// TestOktaMockPoller_EmptySampleFile verifies that an empty sample file results
// in zero publishes and no error.
func TestOktaMockPoller_EmptySampleFile(t *testing.T) {
	dir := t.TempDir()
	samplePath := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(samplePath, []byte("[]"), 0600); err != nil {
		t.Fatal(err)
	}

	pub := &recordingPublisher{}

	poller := ingestionokta.NewPoller(
		ingestionokta.PollerConfig{
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

	// Wait a moment for the initial poll cycle to complete.
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

// TestRawarchiveKey verifies the S3 key format for the NoopArchiver.
func TestRawarchiveKey(t *testing.T) {
	archiver := rawarchive.NoopArchiver{}
	ctx := context.Background()
	ts := time.Date(2026, 3, 4, 10, 0, 0, 0, time.UTC)

	key, hash, err := archiver.Archive(ctx, "tenant-001", "okta", "uuid-123", ts, []byte(`{"test":true}`))
	if err != nil {
		t.Fatalf("archive: %v", err)
	}
	// Key format: raw/<tenantID>/<source>/<YYYY>/<MM>/<DD>/<HH>/<eventID>.json
	expectedKey := "raw/tenant-001/okta/2026/03/04/10/uuid-123.json"
	if key != expectedKey {
		t.Errorf("key mismatch: got %q want %q", key, expectedKey)
	}
	if len(hash) != 64 {
		t.Errorf("expected 64-char hex hash, got len=%d", len(hash))
	}
}

// nilPool returns a *pgxpool.Pool nil value for tests that skip DB operations.
func nilPool() *pgxpool.Pool {
	return nil
}
