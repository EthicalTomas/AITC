package rules

import (
"fmt"
"math"
"time"
)

// MassDownloadResult is the output of the mass file download detection rule.
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
)

// MassDownload detects when an identity downloads an unusually high number of files
// within a rolling time window — a strong indicator of data exfiltration.
//
// count is the number of file downloads observed in window.
func MassDownload(count int, window time.Duration) MassDownloadResult {
result := MassDownloadResult{
Count:  count,
Window: window,
}

if count < MassDownloadThreshold {
return result
}

excess := count - MassDownloadThreshold
// Score scales logarithmically with excess count, capped at 1.0.
score := math.Min(0.5+0.1*math.Log1p(float64(excess)), 1.0)
// Confidence grows with count — a higher count is less likely to be benign.
confidence := math.Min(float64(count)/200.0+0.5, 1.0)

result.Triggered = true
result.CASScore = score
result.Confidence = confidence
result.Description = fmt.Sprintf(
"Mass download detected: %d file downloads in %s (threshold: %d)",
count, window, MassDownloadThreshold,
)
return result
}
