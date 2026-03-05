// Package features extracts scoring-relevant features from normalized events
// and stores them in Redis with TTL windows for subsequent CAS rule evaluation.
package features

import (
	"context"
	"time"

	eventspb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/events"
	"github.com/ethicaltomas/aitc/services/pipeline/internal/persistence"
)

// Windows defines the TTL windows used for feature extraction.
const (
	WindowMFAPush      = 30 * time.Minute
	WindowFileDownload = 1 * time.Hour
	WindowAdminAction  = 24 * time.Hour
	WindowGeoCheckpoint = 8 * time.Hour
)

// Features contains the extracted signals needed by CAS rules.
type Features struct {
	// MFAPushCount is the number of MFA push deny/failure events within WindowMFAPush.
	MFAPushCount int64
	// PrevGeoPoint is the last known geo-location of the actor (for impossible travel).
	PrevGeoPoint *persistence.GeoPoint
	// FileDownloadCount is the number of file downloads within WindowFileDownload.
	FileDownloadCount int64
	// AdminActionCount is the number of admin actions within WindowAdminAction.
	AdminActionCount int64
}

// Extract updates Redis counters/checkpoints based on ev and returns the
// current feature values for the event's actor. Errors from Redis are
// returned but do not prevent the caller from proceeding with zero-value
// features (degraded mode).
func Extract(ctx context.Context, store *persistence.FeatureStore, ev *eventspb.NormalizedEventV1) (*Features, error) {
	if store == nil || ev == nil {
		return &Features{}, nil
	}

	tenantID := ev.GetTenantId()
	identityID := ev.GetActorId()
	if identityID == "" {
		identityID = ev.GetActorEmail()
	}

	f := &Features{}
	var lastErr error

	// ── Geo checkpoint (impossible travel) ───────────────────────────────────
	if ev.GetGeoLat() != 0 || ev.GetGeoLon() != 0 {
		prev, err := store.GetLastGeoPoint(ctx, tenantID, identityID)
		if err != nil {
			lastErr = err
		} else {
			f.PrevGeoPoint = prev
		}
		// Update checkpoint with the current location.
		newGP := persistence.GeoPoint{
			Lat:    ev.GetGeoLat(),
			Lon:    ev.GetGeoLon(),
			Source: ev.GetSource(),
		}
		if t := ev.GetOccurredAt(); t != nil {
			newGP.Timestamp = t.AsTime()
		} else {
			newGP.Timestamp = time.Now().UTC()
		}
		if err := store.SetLastGeoPoint(ctx, tenantID, identityID, newGP, WindowGeoCheckpoint); err != nil {
			lastErr = err
		}
	}

	// ── MFA push counting ─────────────────────────────────────────────────────
	if isMFADeny(ev) {
		count, err := store.IncrMFAPush(ctx, tenantID, identityID, WindowMFAPush)
		if err != nil {
			lastErr = err
		} else {
			f.MFAPushCount = count
		}
	} else {
		count, err := store.GetMFAPushCount(ctx, tenantID, identityID)
		if err != nil {
			lastErr = err
		} else {
			f.MFAPushCount = count
		}
	}

	// ── File download counting ────────────────────────────────────────────────
	if isFileDownload(ev) {
		count, err := store.IncrFileDownload(ctx, tenantID, identityID, WindowFileDownload)
		if err != nil {
			lastErr = err
		} else {
			f.FileDownloadCount = count
		}
	} else {
		count, err := store.GetFileDownloadCount(ctx, tenantID, identityID)
		if err != nil {
			lastErr = err
		} else {
			f.FileDownloadCount = count
		}
	}

	// ── Admin action counting ─────────────────────────────────────────────────
	if isAdminAction(ev) {
		count, err := store.IncrAdminAction(ctx, tenantID, identityID, WindowAdminAction)
		if err != nil {
			lastErr = err
		} else {
			f.AdminActionCount = count
		}
	} else {
		count, err := store.GetAdminActionCount(ctx, tenantID, identityID)
		if err != nil {
			lastErr = err
		} else {
			f.AdminActionCount = count
		}
	}

	return f, lastErr
}

// isMFADeny returns true for events that represent an MFA push denial.
func isMFADeny(ev *eventspb.NormalizedEventV1) bool {
	return ev.GetAction() == "auth.mfa.push_denied" ||
		(ev.GetAction() == "auth.mfa.failure" && ev.GetOutcome() == "failure")
}

// isFileDownload returns true for file download events.
func isFileDownload(ev *eventspb.NormalizedEventV1) bool {
	return ev.GetAction() == "file_access.downloaded"
}

// isAdminAction returns true for events that represent an administrative change.
func isAdminAction(ev *eventspb.NormalizedEventV1) bool {
	return ev.GetCategory() == eventspb.EventCategory_ADMIN ||
		ev.GetCategory() == eventspb.EventCategory_POLICY_CHANGE
}

