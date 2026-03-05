// Package features provides rolling baseline storage helpers.
// Baselines represent the "normal" behaviour window for an identity,
// used to detect anomalies relative to historical activity.
package features

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Baseline holds rolling aggregate stats for a single identity.
type Baseline struct {
	// AvgDailyLogins is the moving average of logins per day.
	AvgDailyLogins float64
	// AvgDailyDownloads is the moving average of file downloads per day.
	AvgDailyDownloads float64
	// KnownCountries contains the set of countries observed in the baseline window.
	KnownCountries []string
}

// baselineTTL is how long a baseline record is kept before expiring.
const baselineTTL = 30 * 24 * time.Hour // 30 days

// BaselineStore persists rolling baseline data in Redis.
type BaselineStore struct {
	client *redis.Client
}

// NewBaselineStore creates a BaselineStore connected to the given Redis client.
func NewBaselineStore(client *redis.Client) *BaselineStore {
	return &BaselineStore{client: client}
}

// IncrLoginCount increments the daily login counter for an identity and returns
// the updated count. The counter resets after 24 hours.
func (b *BaselineStore) IncrLoginCount(ctx context.Context, tenantID, identityID string) (int64, error) {
	key := fmt.Sprintf("aitc:%s:baseline:logins:%s:%s", tenantID, identityID, today())
	pipe := b.client.Pipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, 25*time.Hour) // slight buffer over 24h
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, fmt.Errorf("baseline: incr login: %w", err)
	}
	return incr.Val(), nil
}

// AddKnownCountry records a country code in the identity's baseline country set.
func (b *BaselineStore) AddKnownCountry(ctx context.Context, tenantID, identityID, country string) error {
	if country == "" {
		return nil
	}
	key := fmt.Sprintf("aitc:%s:baseline:countries:%s", tenantID, identityID)
	pipe := b.client.Pipeline()
	pipe.SAdd(ctx, key, country)
	pipe.Expire(ctx, key, baselineTTL)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("baseline: add country: %w", err)
	}
	return nil
}

// IsKnownCountry returns true if the country has been observed in the baseline window.
func (b *BaselineStore) IsKnownCountry(ctx context.Context, tenantID, identityID, country string) (bool, error) {
	key := fmt.Sprintf("aitc:%s:baseline:countries:%s", tenantID, identityID)
	ok, err := b.client.SIsMember(ctx, key, country).Result()
	if err != nil {
		return false, fmt.Errorf("baseline: is known country: %w", err)
	}
	return ok, nil
}

// today returns the current UTC date string (YYYY-MM-DD) used in Redis keys.
func today() string {
	return time.Now().UTC().Format("2006-01-02")
}

