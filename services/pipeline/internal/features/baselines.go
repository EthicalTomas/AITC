// Package features — baseline helpers for building CAS rule inputs.
package features

import (
"time"

"github.com/ethicaltomas/aitc/services/pipeline/internal/cas/rules"
)

// ToGeoPoints converts a GeoHistory slice to the rules.GeoPoint slice
// expected by the ImpossibleTravel rule. Entries are returned in
// chronological order (oldest first).
func ToGeoPoints(history []GeoEntry) []rules.GeoPoint {
pts := make([]rules.GeoPoint, 0, len(history))
for i := len(history) - 1; i >= 0; i-- {
e := history[i]
pts = append(pts, rules.GeoPoint{
Lat:       e.Lat,
Lon:       e.Lon,
Timestamp: e.Timestamp,
Source:    e.Source,
})
}
return pts
}

// LastTwo returns the last two GeoPoints from history for impossible travel checks.
// Returns (zero, zero, false) if there are fewer than two entries.
func LastTwo(history []GeoEntry) (prev, next rules.GeoPoint, ok bool) {
pts := ToGeoPoints(history)
if len(pts) < 2 {
return rules.GeoPoint{}, rules.GeoPoint{}, false
}
return pts[len(pts)-2], pts[len(pts)-1], true
}

// BuildMFAEvents constructs synthetic MFAFatigueEvent slice from a denial count.
// Since we only store counts in Redis (not timestamps), we spread events evenly
// across the MFA window to give the rule accurate timing inputs.
func BuildMFAEvents(denialCount int, windowEnd time.Time, window time.Duration) []rules.MFAFatigueEvent {
if denialCount <= 0 {
return nil
}
events := make([]rules.MFAFatigueEvent, denialCount)
interval := window / time.Duration(denialCount)
for i := 0; i < denialCount; i++ {
events[i] = rules.MFAFatigueEvent{
Timestamp: windowEnd.Add(-window + time.Duration(i)*interval),
Outcome:   "deny",
}
}
return events
}
