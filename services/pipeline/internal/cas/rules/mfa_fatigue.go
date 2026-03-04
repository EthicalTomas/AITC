package rules

import (
	"fmt"
	"math"
	"time"
)

// MFAFatigueResult is the output of the MFA fatigue (push bombing) detection rule.
type MFAFatigueResult struct {
	Triggered   bool
	CASScore    float64
	Confidence  float64
	Description string
	PushCount   int
	WindowSize  time.Duration
}

// MFAFatigueEvent is a single MFA push event.
type MFAFatigueEvent struct {
	Timestamp time.Time
	Outcome   string // "success" | "failure" | "deny" | "timeout"
}

const (
	// MFAFatigueWindowDefault is the rolling window for push counting.
	MFAFatigueWindowDefault = 30 * time.Minute
	// MFAFatigueThreshold is the number of MFA pushes in the window that triggers the rule.
	MFAFatigueThreshold = 5
)

// MFAFatigue detects when a user receives an abnormally high number of MFA push
// requests within a short window — a sign of push bombing / fatigue attack.
// Events should be provided in chronological order.
func MFAFatigue(events []MFAFatigueEvent, window time.Duration) MFAFatigueResult {
	if window <= 0 {
		window = MFAFatigueWindowDefault
	}
	if len(events) == 0 {
		return MFAFatigueResult{}
	}

	// Count denials/failures in window from the most recent event
	latest := events[len(events)-1].Timestamp
	windowStart := latest.Add(-window)

	denyCount := 0
	for _, e := range events {
		if e.Timestamp.After(windowStart) {
			if e.Outcome == "failure" || e.Outcome == "deny" || e.Outcome == "timeout" {
				denyCount++
			}
		}
	}

	result := MFAFatigueResult{
		PushCount:  denyCount,
		WindowSize: window,
	}

	if denyCount >= MFAFatigueThreshold {
		result.Triggered = true
		// Score scales with count above threshold
		excess := denyCount - MFAFatigueThreshold
		result.CASScore = math.Min(0.5+float64(excess)*0.05, 1.0)
		result.Confidence = math.Min(float64(denyCount)/20.0+0.5, 1.0)
		result.Description = fmt.Sprintf(
			"MFA fatigue detected: %d push denials in %s window (threshold: %d)",
			denyCount, window, MFAFatigueThreshold,
		)
	}
	return result
}


