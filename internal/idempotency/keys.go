package idempotency

import (
	"crypto/sha256"
	"fmt"
)

// ActionKey generates a deterministic idempotency key for an action.
// Components: tenantID + caseID + actionType + identityID
func ActionKey(tenantID, caseID, actionType, identityID string) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%s", tenantID, caseID, actionType, identityID)))
	return fmt.Sprintf("%x", h)
}

// EnvelopeKey generates a dedup key for an ingestion envelope.
func EnvelopeKey(tenantID, source, providerEventID string) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s", tenantID, source, providerEventID)))
	return fmt.Sprintf("%x", h)
}
