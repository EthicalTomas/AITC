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
Operation   string
}

// oauthGrantOperations are normalized action names that represent OAuth grants.
var oauthGrantOperations = []string{
"oauth.delegated_permission.granted",
"oauth.app_role.assigned",
"oauth.app.consent",
}

// highRiskScopes are OAuth scope patterns that grant broad data access.
var highRiskScopes = []string{
"mail.read", "mail.readwrite", "mail.send",
"files.read", "files.readwrite",
"contacts.read", "contacts.readwrite",
"calendars.read", "calendars.readwrite",
"user.read.all", "user.readwrite.all",
"directory.read.all", "directory.readwrite.all",
"group.readwrite.all", "application.readwrite.all",
"offline_access",
"https://graph.microsoft.com/.default",
}

// RiskyOAuthGrant detects OAuth application consent events that grant high-privilege
// scopes — a common technique in phishing and BEC campaigns.
//
// operation is the normalized action name.
// grantedScopes is the list of OAuth scopes from the grant event (may be nil when
// scope data is not available from the normalized event; the operation type alone
// still produces a low-confidence base signal).
// grantedByNonAdmin is true when the consent was given by a regular user.
func RiskyOAuthGrant(operation string, grantedScopes []string, grantedByNonAdmin bool) RiskyOAuthGrantResult {
result := RiskyOAuthGrantResult{Operation: operation}

// Only evaluate OAuth grant operations.
isGrant := false
for _, op := range oauthGrantOperations {
if operation == op {
isGrant = true
break
}
}
if !isGrant {
return result
}

reasons := []string{}
score := 0.0

// Base score for any OAuth grant event — consent can be obtained via phishing.
score += 0.3
reasons = append(reasons, fmt.Sprintf("OAuth grant operation %q detected", operation))

// Count how many high-risk scopes were granted.
highRiskCount := 0
matched := []string{}
for _, scope := range grantedScopes {
lower := strings.ToLower(scope)
for _, risk := range highRiskScopes {
if strings.Contains(lower, risk) {
highRiskCount++
matched = append(matched, scope)
break
}
}
}

if highRiskCount > 0 {
score += math.Min(float64(highRiskCount)*0.15, 0.5)
reasons = append(reasons, fmt.Sprintf("%d high-risk scope(s): %s", highRiskCount, strings.Join(matched, ", ")))
}

// Non-admin granting access is higher risk.
if grantedByNonAdmin {
score += 0.2
reasons = append(reasons, "consent granted by non-privileged user")
}

if score > 1.0 {
score = 1.0
}

// Confidence is lower without scope data.
confidence := 0.4
if highRiskCount > 0 {
confidence = math.Min(0.6+float64(highRiskCount)*0.05, 1.0)
}

result.Triggered = true
result.CASScore = score
result.Confidence = confidence
result.Description = "Risky OAuth grant detected: " + strings.Join(reasons, "; ")
return result
}
