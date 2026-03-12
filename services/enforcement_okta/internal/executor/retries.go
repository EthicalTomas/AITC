package executor

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"

	casespb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/cases"
	oktaclient "github.com/ethicaltomas/aitc/internal/okta"
)

const (
	maxRetries     = 3
	retryBaseDelay = 500 * time.Millisecond
)

// withRetries executes fn up to maxRetries times with exponential backoff.
// RateLimitError is handled by waiting the RetryAfter duration before retrying.
// Returns the last error if all retries are exhausted.
func withRetries(ctx context.Context, logger *zap.Logger, action *casespb.ResponseActionV1, fn func() error) error {
	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		lastErr = fn()
		if lastErr == nil {
			return nil
		}

		var rateLimitErr *oktaclient.RateLimitError
		if errors.As(lastErr, &rateLimitErr) {
			wait := rateLimitErr.RetryAfter
			logger.Warn("okta rate limited; waiting before retry",
				zap.Duration("wait", wait),
				zap.Int("attempt", attempt+1),
				zap.String("action_id", action.GetActionId()),
			)
			select {
			case <-ctx.Done():
				return fmt.Errorf("retries: context cancelled during rate limit wait: %w", ctx.Err())
			case <-time.After(wait):
				continue
			}
		}

		// Exponential backoff for other transient errors
		delay := retryBaseDelay * (1 << attempt)
		logger.Warn("action execution failed; retrying",
			zap.Error(lastErr),
			zap.Int("attempt", attempt+1),
			zap.Duration("backoff", delay),
			zap.String("action_id", action.GetActionId()),
		)
		select {
		case <-ctx.Done():
			return fmt.Errorf("retries: context cancelled: %w", ctx.Err())
		case <-time.After(delay):
		}
	}
	return fmt.Errorf("retries: all %d attempts failed: %w", maxRetries, lastErr)
}

