package rules

import (
	"fmt"
	"math"
	"time"
)

// MassDownloadResult is the output of the bulk file download detection rule.
type MassDownloadResult struct {
	Triggered   bool
	CASScore    float64
	Confidence  float64
	Description string
	Count       int
	Window      time.Duration
}

const (
	// MassDownloadThreshold is the number of downloads within the window that triggers the rule.
	MassDownloadThreshold = 50
	// MassDownloadWindowDefault is the rolling window for download counting.
	MassDownloadWindowDefault = 1 * time.Hour
)

// MassDownload detects when an identity downloads an unusually high number of
// files within a short window — a strong indicator of data exfiltration.
// count is the total downloads observed in window.
func MassDownload(count int, window time.Duration) MassDownloadResult {
	if window <= 0 {
		window = MassDownloadWindowDefault
	}
	result := MassDownloadResult{
		Count:  count,
		Window: window,
	}
	if count >= MassDownloadThreshold {
		result.Triggered = true
		// Score scales with volume above threshold, capped at 1.0
		excess := count - MassDownloadThreshold
		result.CASScore = math.Min(0.6+float64(excess)*0.002, 1.0)
		result.Confidence = math.Min(float64(count)/200.0+0.5, 1.0)
		result.Description = fmt.Sprintf(
			"Mass download detected: %d file downloads in %s (threshold: %d)",
			count, window, MassDownloadThreshold,
		)
	}
	return result
}

