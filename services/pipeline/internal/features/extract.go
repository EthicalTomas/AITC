// Package features extracts per-identity feature vectors from Redis TTL windows.
// Features feed directly into CAS scoring rules.
package features

import (
"context"
"encoding/json"
"fmt"
"time"

"github.com/redis/go-redis/v9"
"go.uber.org/zap"

eventspb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/events"
)

// Window durations for each feature type.
const (
WindowGeoHistory   = 24 * time.Hour
WindowMFADenials   = 30 * time.Minute
WindowFileDownload = 60 * time.Minute
WindowAdminAction  = 24 * time.Hour
)

// GeoEntry is a single geo-location observation stored in Redis.
type GeoEntry struct {
Lat       float64   `json:"lat"`
Lon       float64   `json:"lon"`
Timestamp time.Time `json:"ts"`
Source    string    `json:"src"` // "okta" | "m365"
}

// Features holds the extracted feature values for a single event evaluation.
type Features struct {
// GeoHistory contains the recent geo-locations for the identity (newest first).
GeoHistory []GeoEntry
// MFADenialCount is the number of MFA push denials in the last 30 minutes.
MFADenialCount int
// FileDownloadCount is the number of file downloads in the last 60 minutes.
FileDownloadCount int
// AdminActionCount is the cached admin action count from Postgres baselines.
// Loaded separately; set to -1 if not yet loaded.
AdminActionCount int
}

// Extractor reads and updates Redis feature windows.
type Extractor struct {
rdb    *redis.Client
logger *zap.Logger
}

// NewExtractor creates a new feature extractor using the given Redis client.
func NewExtractor(rdb *redis.Client) *Extractor {
return &Extractor{rdb: rdb, logger: zap.NewNop()}
}

// NewExtractorWithLogger creates a new feature extractor with the provided logger.
func NewExtractorWithLogger(rdb *redis.Client, logger *zap.Logger) *Extractor {
if logger == nil {
logger = zap.NewNop()
}
return &Extractor{rdb: rdb, logger: logger}
}

// Extract reads current feature values for the identity in ev and updates
// the relevant Redis windows based on the event type.
func (e *Extractor) Extract(ctx context.Context, ev *eventspb.NormalizedEventV1) (*Features, error) {
feats := &Features{AdminActionCount: -1}
tenantActor := fmt.Sprintf("%s:%s", ev.GetTenantId(), ev.GetActorId())

// ── Update + read geo history ─────────────────────────────────────────────
if ev.GetGeoLat() != 0 || ev.GetGeoLon() != 0 {
entry := GeoEntry{
Lat:    ev.GetGeoLat(),
Lon:    ev.GetGeoLon(),
Source: ev.GetSource(),
}
if t := ev.GetOccurredAt(); t != nil {
entry.Timestamp = t.AsTime()
} else {
entry.Timestamp = time.Now().UTC()
}
if err := e.appendGeo(ctx, tenantActor, entry, WindowGeoHistory); err != nil {
e.logger.Warn("features: append geo failed", zap.Error(err))
}
}
geoHistory, err := e.getGeoHistory(ctx, tenantActor)
if err != nil {
e.logger.Warn("features: get geo history failed", zap.Error(err))
} else {
feats.GeoHistory = geoHistory
}

// ── MFA denial counter ────────────────────────────────────────────────────
if ev.GetCategory() == eventspb.EventCategory_MFA {
action := ev.GetAction()
if action == "auth.mfa.push_denied" || ev.GetOutcome() == "failure" {
if err := e.incrCounter(ctx, tenantActor+":mfa_denials", WindowMFADenials); err != nil {
e.logger.Warn("features: incr mfa_denials failed", zap.Error(err))
}
}
}
mfaCount, err := e.getCounter(ctx, tenantActor+":mfa_denials")
if err != nil {
e.logger.Warn("features: get mfa_denials failed", zap.Error(err))
}
feats.MFADenialCount = mfaCount

// ── File download counter ─────────────────────────────────────────────────
if ev.GetAction() == "file.downloaded" {
if err := e.incrCounter(ctx, tenantActor+":file_downloads", WindowFileDownload); err != nil {
e.logger.Warn("features: incr file_downloads failed", zap.Error(err))
}
}
dlCount, err := e.getCounter(ctx, tenantActor+":file_downloads")
if err != nil {
e.logger.Warn("features: get file_downloads failed", zap.Error(err))
}
feats.FileDownloadCount = dlCount

return feats, nil
}

func (e *Extractor) appendGeo(ctx context.Context, key string, entry GeoEntry, window time.Duration) error {
data, err := json.Marshal(entry)
if err != nil {
return fmt.Errorf("features: marshal geo entry: %w", err)
}
geoKey := "feat:geo:" + key
pipe := e.rdb.Pipeline()
pipe.LPush(ctx, geoKey, data)
pipe.LTrim(ctx, geoKey, 0, 49) // keep last 50 locations
pipe.Expire(ctx, geoKey, window)
_, err = pipe.Exec(ctx)
return err
}

func (e *Extractor) getGeoHistory(ctx context.Context, key string) ([]GeoEntry, error) {
geoKey := "feat:geo:" + key
rawList, err := e.rdb.LRange(ctx, geoKey, 0, -1).Result()
if err != nil {
return nil, err
}
entries := make([]GeoEntry, 0, len(rawList))
for _, raw := range rawList {
var entry GeoEntry
if err := json.Unmarshal([]byte(raw), &entry); err == nil {
entries = append(entries, entry)
}
}
return entries, nil
}

func (e *Extractor) incrCounter(ctx context.Context, key string, window time.Duration) error {
counterKey := "feat:cnt:" + key
pipe := e.rdb.Pipeline()
pipe.Incr(ctx, counterKey)
pipe.Expire(ctx, counterKey, window)
_, err := pipe.Exec(ctx)
return err
}

func (e *Extractor) getCounter(ctx context.Context, key string) (int, error) {
counterKey := "feat:cnt:" + key
val, err := e.rdb.Get(ctx, counterKey).Int()
if err == redis.Nil {
return 0, nil
}
return val, err
}
