// Package cas provides confidence score computation helpers for the
// Composite Anomaly Score (CAS) engine.
package cas

import "math"

// CombineScores computes a composite score from multiple individual CAS scores
// using a weighted geometric mean capped at 1.0. Scores of 0 are ignored.
// Returns 0 if no non-zero scores are provided.
func CombineScores(scores []float64) float64 {
	if len(scores) == 0 {
		return 0
	}
	sum := 0.0
	count := 0
	for _, s := range scores {
		if s > 0 {
			sum += s
			count++
		}
	}
	if count == 0 {
		return 0
	}
	return math.Min(sum/float64(count), 1.0)
}

// SeverityFromScore maps a CAS score to a human-readable severity label.
func SeverityFromScore(score float64) string {
	switch {
	case score >= 0.85:
		return "critical"
	case score >= 0.65:
		return "high"
	case score >= 0.40:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "none"
	}
}

// CombineConfidence returns the maximum confidence across all provided values,
// representing the most certain signal available.
func CombineConfidence(values []float64) float64 {
	max := 0.0
	for _, v := range values {
		if v > max {
			max = v
		}
	}
	return math.Min(max, 1.0)
}

