package rules

import (
	"fmt"
	"math"
	"strings"
)

// RiskyOAuthGrantResult is the output of the risky OAuth grant detection rule.
type RiskyOAuthGrantResult struct {
	Triggered   bool
	CASScore    float64
	Confidence  float64
	Description string
	AppName     string
	Scopes      []string
}

// OAuthGrantEvent contains context about an OAuth authorization grant.
type OAuthGrantEvent struct {
	// AppName is the display name of the OAuth application.
	AppName string
	// Scopes is the list of OAuth scopes requested/granted.
	Scopes []string
	// IsFirstTimeApp is true when this app has not been seen before for this tenant.
	IsFirstTimeApp bool
	// GrantedByNonAdmin is true when a non-privileged user granted admin-level scopes.
	GrantedByNonAdmin bool
}

// sensitiveOAuthScopes are OAuth scope patterns that indicate elevated privileges.
var sensitiveOAuthScopes = []string{
	"mail.read", "mail.readwrite", "mail.send",
	"files.read.all", "files.readwrite.all",
	"user.read.all", "user.readwrite.all",
	"directory.read.all", "directory.readwrite.all",
	"calendars.readwrite",
	"contacts.readwrite",
	"offline_access",
	"https://graph.microsoft.com/.default",
	"https://outlook.office365.com/.default",
	"all", // overly broad scope
}

// RiskyOAuthGrant detects OAuth application authorizations that grant sensitive
// or overly-broad permissions, particularly when granted by non-admin users or
// for first-time applications.
func RiskyOAuthGrant(event OAuthGrantEvent) RiskyOAuthGrantResult {
	result := RiskyOAuthGrantResult{
		AppName: event.AppName,
		Scopes:  event.Scopes,
	}

	score := 0.0
	reasons := []string{}

	// Check for sensitive scopes
	sensitiveCount := 0
	for _, granted := range event.Scopes {
		lower := strings.ToLower(granted)
		for _, sensitive := range sensitiveOAuthScopes {
			if strings.Contains(lower, sensitive) {
				sensitiveCount++
				break
			}
		}
	}
	if sensitiveCount > 0 {
		score += math.Min(float64(sensitiveCount)*0.25, 0.6)
		reasons = append(reasons, fmt.Sprintf("%d sensitive scope(s) granted", sensitiveCount))
	}

	// First-time app is inherently riskier
	if event.IsFirstTimeApp {
		score += 0.2
		reasons = append(reasons, "first-time OAuth application for this tenant")
	}

	// Non-admin granting admin-level scopes
	if event.GrantedByNonAdmin && sensitiveCount > 0 {
		score += 0.2
		reasons = append(reasons, "sensitive scopes granted by non-privileged user")
	}

	if score > 0 {
		if score > 1.0 {
			score = 1.0
		}
		result.Triggered = true
		result.CASScore = score
		result.Confidence = math.Min(0.5+float64(len(reasons))*0.1, 1.0)
		result.Description = "Risky OAuth grant detected: " + strings.Join(reasons, "; ")
	}
	return result
}

