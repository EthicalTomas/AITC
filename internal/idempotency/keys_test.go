package idempotency_test

import (
	"testing"

	"github.com/ethicaltomas/aitc/internal/idempotency"
)

// TestActionKey_Deterministic verifies the same inputs always produce the same key.
func TestActionKey_Deterministic(t *testing.T) {
	k1 := idempotency.ActionKey("tenant-1", "case-abc", "revoke_sessions", "user-xyz")
	k2 := idempotency.ActionKey("tenant-1", "case-abc", "revoke_sessions", "user-xyz")

	if k1 != k2 {
		t.Errorf("ActionKey must be deterministic: got %q and %q", k1, k2)
	}
}

// TestActionKey_DifferentTenants produces different keys.
func TestActionKey_DifferentTenants(t *testing.T) {
	k1 := idempotency.ActionKey("tenant-A", "case-1", "revoke_sessions", "user-1")
	k2 := idempotency.ActionKey("tenant-B", "case-1", "revoke_sessions", "user-1")

	if k1 == k2 {
		t.Error("ActionKey must differ for different tenants")
	}
}

// TestActionKey_DifferentActions produces different keys.
func TestActionKey_DifferentActions(t *testing.T) {
	k1 := idempotency.ActionKey("tenant-1", "case-1", "revoke_sessions", "user-1")
	k2 := idempotency.ActionKey("tenant-1", "case-1", "mfa_stepup", "user-1")

	if k1 == k2 {
		t.Error("ActionKey must differ for different action types")
	}
}

// TestActionKey_DifferentCases produces different keys.
func TestActionKey_DifferentCases(t *testing.T) {
	k1 := idempotency.ActionKey("tenant-1", "case-A", "revoke_sessions", "user-1")
	k2 := idempotency.ActionKey("tenant-1", "case-B", "revoke_sessions", "user-1")

	if k1 == k2 {
		t.Error("ActionKey must differ for different cases")
	}
}

// TestEnvelopeKey_Deterministic verifies ingestion dedup key is deterministic.
func TestEnvelopeKey_Deterministic(t *testing.T) {
	k1 := idempotency.EnvelopeKey("tenant-1", "okta", "event-uuid-123")
	k2 := idempotency.EnvelopeKey("tenant-1", "okta", "event-uuid-123")

	if k1 != k2 {
		t.Errorf("EnvelopeKey must be deterministic: got %q and %q", k1, k2)
	}
}

// TestEnvelopeKey_DifferentSources produces different keys.
func TestEnvelopeKey_DifferentSources(t *testing.T) {
	k1 := idempotency.EnvelopeKey("tenant-1", "okta", "event-123")
	k2 := idempotency.EnvelopeKey("tenant-1", "m365", "event-123")

	if k1 == k2 {
		t.Error("EnvelopeKey must differ for different sources (dedup requires source scoping)")
	}
}

// TestEnvelopeKey_DifferentTenants ensures tenant isolation in dedup keys (Step 0.5).
func TestEnvelopeKey_DifferentTenants(t *testing.T) {
	k1 := idempotency.EnvelopeKey("tenant-A", "okta", "event-123")
	k2 := idempotency.EnvelopeKey("tenant-B", "okta", "event-123")

	if k1 == k2 {
		t.Error("EnvelopeKey must differ for different tenants (Step 0.5: tenant isolation)")
	}
}

// TestActionKey_NonEmpty ensures keys are non-empty hex strings.
func TestActionKey_NonEmpty(t *testing.T) {
	k := idempotency.ActionKey("t", "c", "a", "i")
	if k == "" {
		t.Error("ActionKey must not be empty")
	}
	// SHA-256 produces 64 hex characters
	if len(k) != 64 {
		t.Errorf("expected 64-char hex key, got len=%d: %q", len(k), k)
	}
}
