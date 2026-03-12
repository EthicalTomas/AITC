package rules

import (
"fmt"
"math"
"strings"
)

// RareAdminActionResult is the output of the rare admin action detection rule.
type RareAdminActionResult struct {
Triggered   bool
CASScore    float64
Confidence  float64
Description string
Action      string
}

// adminActionPrefixes are normalized action name prefixes considered admin actions.
var adminActionPrefixes = []string{
"admin.",
"oauth.",
}

// RareAdminActionThreshold is the number of historical admin actions below which
// the current action is considered "rare" for that identity.
const RareAdminActionThreshold = 5

// RareAdminAction detects when a privileged action is performed by an identity
// that has little or no history of similar actions — indicating a potential
// account takeover or privilege escalation.
//
// action is the normalized AITC action name (e.g. "admin.user.created").
// historicalCount is how many times this identity has performed admin actions
// in the long-term baseline window.
func RareAdminAction(action string, historicalCount int) RareAdminActionResult {
result := RareAdminActionResult{Action: action}

// Only evaluate admin/privileged action types.
isAdmin := false
for _, prefix := range adminActionPrefixes {
if strings.HasPrefix(action, prefix) {
isAdmin = true
break
}
}
if !isAdmin {
return result
}

if historicalCount >= RareAdminActionThreshold {
return result // not rare for this identity
}

// Score inversely proportional to history: zero history → high score.
ratio := 1.0 - float64(historicalCount)/float64(RareAdminActionThreshold)
score := math.Min(0.4+0.5*ratio, 1.0)
confidence := 0.5 + 0.1*float64(RareAdminActionThreshold-historicalCount)
if confidence > 1.0 {
confidence = 1.0
}

result.Triggered = true
result.CASScore = score
result.Confidence = confidence
result.Description = fmt.Sprintf(
"Rare admin action %q by identity with only %d prior admin action(s) (threshold: %d)",
action, historicalCount, RareAdminActionThreshold,
)
return result
}
