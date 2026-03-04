package rules

import (
	"math"
	"time"
)

// ImpossibleTravelResult is the output of the impossible travel detection rule.
type ImpossibleTravelResult struct {
	Triggered    bool
	CASScore     float64
	Confidence   float64
	Description  string
	DistanceKM   float64
	TimeHours    float64
	SpeedKMH     float64
}

// GeoPoint represents a geographic location from a login event.
type GeoPoint struct {
	Lat       float64
	Lon       float64
	Timestamp time.Time
	Source    string // "okta" | "m365"
}

// ImpossibleTravelThresholdKMH is the maximum plausible travel speed.
// Commercial aircraft cruise at ~900 km/h; we use 800 to account for processing lag.
const ImpossibleTravelThresholdKMH = 800.0

// ImpossibleTravel detects when a user logs in from two geographically distant
// locations within a time window that would require physically impossible travel.
// Returns a result with CASScore > 0 if triggered.
func ImpossibleTravel(prev, next GeoPoint) ImpossibleTravelResult {
	elapsed := next.Timestamp.Sub(prev.Timestamp)
	if elapsed <= 0 {
		return ImpossibleTravelResult{}
	}

	distKM := haversineKM(prev.Lat, prev.Lon, next.Lat, next.Lon)
	hours := elapsed.Hours()
	if hours == 0 {
		hours = 1.0 / 3600 // 1 second minimum to avoid div/0
	}
	speedKMH := distKM / hours

	result := ImpossibleTravelResult{
		DistanceKM: distKM,
		TimeHours:  hours,
		SpeedKMH:   speedKMH,
	}

	if speedKMH > ImpossibleTravelThresholdKMH && distKM > 100 {
		result.Triggered = true
		// Score scales with speed ratio above threshold, capped at 1.0
		ratio := speedKMH / ImpossibleTravelThresholdKMH
		result.CASScore = math.Min(0.4+0.6*math.Tanh(ratio-1), 1.0)
		// Confidence is higher when both distance and speed are extreme
		result.Confidence = math.Min(distKM/10000.0+0.3, 1.0)
		result.Description = "Impossible travel detected: login from geographically distant location within implausible timeframe"
	}
	return result
}

// haversineKM computes great-circle distance in kilometres between two lat/lon points.
func haversineKM(lat1, lon1, lat2, lon2 float64) float64 {
	const earthRadiusKM = 6371.0
	dLat := toRad(lat2 - lat1)
	dLon := toRad(lon2 - lon1)
	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(toRad(lat1))*math.Cos(toRad(lat2))*
			math.Sin(dLon/2)*math.Sin(dLon/2)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
	return earthRadiusKM * c
}

func toRad(deg float64) float64 {
	return deg * math.Pi / 180
}


