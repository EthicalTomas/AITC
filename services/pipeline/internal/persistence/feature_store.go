// Package persistence provides Redis-backed rolling baseline and feature storage.
// Keys are namespaced by tenant to maintain isolation (tenant_id:feature:...).
package persistence

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// FeatureStore persists short-lived feature counters and geo checkpoints in Redis.
// All keys are scoped by tenant_id to enforce isolation.
type FeatureStore struct {
	client *redis.Client
}

// NewFeatureStore creates a FeatureStore connected to the given Redis address.
func NewFeatureStore(addr, password string, db int) *FeatureStore {
	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})
	return &FeatureStore{client: client}
}

// NewFeatureStoreFromClient creates a FeatureStore from an existing Redis client.
// Useful in tests to inject a test double.
func NewFeatureStoreFromClient(client *redis.Client) *FeatureStore {
	return &FeatureStore{client: client}
}

// Close closes the underlying Redis connection.
func (f *FeatureStore) Close() error {
	return f.client.Close()
}

// ─── MFA Push Counting ────────────────────────────────────────────────────────

// IncrMFAPush increments the MFA push counter for an identity within the given
// TTL window and returns the new count. The key expires automatically after ttl.
func (f *FeatureStore) IncrMFAPush(ctx context.Context, tenantID, identityID string, ttl time.Duration) (int64, error) {
	key := mfaPushKey(tenantID, identityID)
	pipe := f.client.Pipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, fmt.Errorf("feature_store: incr mfa push: %w", err)
	}
	return incr.Val(), nil
}

// GetMFAPushCount returns the current MFA push counter for an identity.
// Returns 0 if no counter exists.
func (f *FeatureStore) GetMFAPushCount(ctx context.Context, tenantID, identityID string) (int64, error) {
	key := mfaPushKey(tenantID, identityID)
	val, err := f.client.Get(ctx, key).Int64()
	if err == redis.Nil {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("feature_store: get mfa push count: %w", err)
	}
	return val, nil
}

// ─── Geo Checkpoint ──────────────────────────────────────────────────────────

// GeoPoint is a lat/lon location with a timestamp, stored for impossible-travel detection.
type GeoPoint struct {
	Lat       float64
	Lon       float64
	Timestamp time.Time
	Source    string
}

// SetLastGeoPoint stores the most recent geo location for an identity.
// The key expires after ttl to bound memory usage.
func (f *FeatureStore) SetLastGeoPoint(ctx context.Context, tenantID, identityID string, gp GeoPoint, ttl time.Duration) error {
	key := geoKey(tenantID, identityID)
	val := fmt.Sprintf("%f:%f:%d:%s", gp.Lat, gp.Lon, gp.Timestamp.Unix(), gp.Source)
	return f.client.Set(ctx, key, val, ttl).Err()
}

// GetLastGeoPoint retrieves the most recent geo location for an identity.
// Returns (nil, nil) if no previous location is recorded.
func (f *FeatureStore) GetLastGeoPoint(ctx context.Context, tenantID, identityID string) (*GeoPoint, error) {
	key := geoKey(tenantID, identityID)
	val, err := f.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("feature_store: get geo point: %w", err)
	}
	gp, err := parseGeoPoint(val)
	if err != nil {
		return nil, fmt.Errorf("feature_store: parse geo point: %w", err)
	}
	return gp, nil
}

// ─── File Download Counting ───────────────────────────────────────────────────

// IncrFileDownload increments the file download counter for an identity and
// returns the new total count within the TTL window.
func (f *FeatureStore) IncrFileDownload(ctx context.Context, tenantID, identityID string, ttl time.Duration) (int64, error) {
	key := fileDownloadKey(tenantID, identityID)
	pipe := f.client.Pipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, fmt.Errorf("feature_store: incr file download: %w", err)
	}
	return incr.Val(), nil
}

// GetFileDownloadCount returns the current file download count for an identity.
func (f *FeatureStore) GetFileDownloadCount(ctx context.Context, tenantID, identityID string) (int64, error) {
	key := fileDownloadKey(tenantID, identityID)
	val, err := f.client.Get(ctx, key).Int64()
	if err == redis.Nil {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("feature_store: get file download count: %w", err)
	}
	return val, nil
}

// ─── Admin Action Counting ────────────────────────────────────────────────────

// IncrAdminAction increments the admin action counter for an identity within
// the given TTL window and returns the new count.
func (f *FeatureStore) IncrAdminAction(ctx context.Context, tenantID, identityID string, ttl time.Duration) (int64, error) {
	key := adminActionKey(tenantID, identityID)
	pipe := f.client.Pipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, fmt.Errorf("feature_store: incr admin action: %w", err)
	}
	return incr.Val(), nil
}

// GetAdminActionCount returns the current admin action count for an identity.
func (f *FeatureStore) GetAdminActionCount(ctx context.Context, tenantID, identityID string) (int64, error) {
	key := adminActionKey(tenantID, identityID)
	val, err := f.client.Get(ctx, key).Int64()
	if err == redis.Nil {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("feature_store: get admin action count: %w", err)
	}
	return val, nil
}

// ─── Key helpers ──────────────────────────────────────────────────────────────

func mfaPushKey(tenantID, identityID string) string {
	return fmt.Sprintf("aitc:%s:mfa_push:%s", tenantID, identityID)
}

func geoKey(tenantID, identityID string) string {
	return fmt.Sprintf("aitc:%s:geo:%s", tenantID, identityID)
}

func fileDownloadKey(tenantID, identityID string) string {
	return fmt.Sprintf("aitc:%s:file_dl:%s", tenantID, identityID)
}

func adminActionKey(tenantID, identityID string) string {
	return fmt.Sprintf("aitc:%s:admin_act:%s", tenantID, identityID)
}

// parseGeoPoint parses a stored geo string "lat:lon:unixts:source".
func parseGeoPoint(s string) (*GeoPoint, error) {
	// Split into exactly 4 parts: lat, lon, timestamp, source
	parts := strings.SplitN(s, ":", 4)
	if len(parts) < 3 {
		return nil, fmt.Errorf("malformed geo point: %q", s)
	}
	lat, err := strconv.ParseFloat(parts[0], 64)
	if err != nil {
		return nil, fmt.Errorf("malformed geo lat in %q: %w", s, err)
	}
	lon, err := strconv.ParseFloat(parts[1], 64)
	if err != nil {
		return nil, fmt.Errorf("malformed geo lon in %q: %w", s, err)
	}
	ts, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("malformed geo ts in %q: %w", s, err)
	}
	source := ""
	if len(parts) == 4 {
		source = parts[3]
	}
	return &GeoPoint{
		Lat:       lat,
		Lon:       lon,
		Timestamp: time.Unix(ts, 0).UTC(),
		Source:    source,
	}, nil
}

