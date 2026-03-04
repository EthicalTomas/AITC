package okta

import (
	"fmt"
	"time"
)

// RateLimitError is returned when Okta returns 429 Too Many Requests.
type RateLimitError struct {
	RetryAfter time.Duration
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("okta rate limited: retry after %s", e.RetryAfter)
}
