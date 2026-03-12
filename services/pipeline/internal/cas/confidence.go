// Package cas — confidence and severity helpers for CAS scoring.
package cas

import (
"math"

riskpb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/risk"
)

// WeightedScore returns a combined score weighted by confidence.
// result = casScore * confidence
// This dampens signals where the rule's confidence is low.
func WeightedScore(casScore, confidence float64) float64 {
return math.Min(casScore*confidence, 1.0)
}

// SeverityFromScore maps a CAS score to a risk Severity enum value.
//   - score >= 0.8 → CRITICAL
//   - score >= 0.6 → HIGH
//   - score >= 0.4 → MEDIUM
//   - score >  0   → LOW
//   - score == 0   → SEVERITY_UNSPECIFIED
func SeverityFromScore(score float64) riskpb.Severity {
switch {
case score >= 0.8:
return riskpb.Severity_CRITICAL
case score >= 0.6:
return riskpb.Severity_HIGH
case score >= 0.4:
return riskpb.Severity_MEDIUM
case score > 0:
return riskpb.Severity_LOW
default:
return riskpb.Severity_SEVERITY_UNSPECIFIED
}
}

// SeverityString returns the lowercase string representation for DB storage.
func SeverityString(sev riskpb.Severity) string {
switch sev {
case riskpb.Severity_CRITICAL:
return "critical"
case riskpb.Severity_HIGH:
return "high"
case riskpb.Severity_MEDIUM:
return "medium"
case riskpb.Severity_LOW:
return "low"
default:
return "unspecified"
}
}
