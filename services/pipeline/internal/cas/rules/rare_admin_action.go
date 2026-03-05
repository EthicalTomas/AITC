package rules

import (
	"fmt"
	"math"
	"strings"
	"time"
)

// RareAdminActionResult is the output of the rare admin action detection rule.
type RareAdminActionResult struct {
	Triggered   bool
	CASScore    float64
	Confidence  float64
	Description string
	ActionType  string
}

// AdminActionEvent contains context needed to evaluate whether an admin action is rare.
type AdminActionEvent struct {
	// ActionType is the normalized AITC action string (e.g. "admin_change.api_token.created").
	ActionType string
	// ActorIsPrivileged is true when the actor holds an admin role.
	ActorIsPrivileged bool
	// CountInWindow is how many times this actor performed admin actions recently.
	CountInWindow int
	// Window is the duration over which CountInWindow was measured.
	Window time.Duration
	// IsAfterHours is true when the action occurred outside normal business hours (UTC).
	IsAfterHours bool
}

// highRiskAdminActions are admin action types that are always considered elevated risk.
var highRiskAdminActions = map[string]float64{
	"admin_change.api_token.created":   0.7,
	"admin_change.role.assigned":       0.65,
	"admin_change.mfa.unenrolled":      0.6,
	"admin_change.policy.deleted":      0.6,
	"admin_change.policy.updated":      0.5,
	"admin_change.policy.created":      0.45,
	"admin_change.user.created":        0.3,
	"admin_change.user.deactivated":    0.4,
}

const (
	// RareAdminThreshold is how few prior admin actions indicate a "rare" actor.
	RareAdminThreshold = 3
)

// RareAdminAction detects unusual administrative actions — especially those
// performed by accounts that rarely exercise admin capabilities, or high-risk
// action types performed outside normal hours.
func RareAdminAction(event AdminActionEvent) RareAdminActionResult {
	result := RareAdminActionResult{
		ActionType: event.ActionType,
	}

	baseScore, isHighRisk := highRiskAdminActions[event.ActionType]
	if !isHighRisk {
		// Low-risk admin action from a regular actor — skip
		if !event.ActorIsPrivileged {
			return result
		}
		baseScore = 0.2
	}

	reasons := []string{}

	score := baseScore

	// Rare actor: performed very few admin actions recently
	if event.CountInWindow <= RareAdminThreshold && event.CountInWindow >= 0 {
		score += 0.2
		reasons = append(reasons, fmt.Sprintf("actor performed only %d admin action(s) recently (rare)", event.CountInWindow))
	}

	// After-hours multiplier
	if event.IsAfterHours {
		score = math.Min(score+0.15, 1.0)
		reasons = append(reasons, "action occurred outside normal business hours")
	}

	if score > 0.3 {
		if score > 1.0 {
			score = 1.0
		}
		result.Triggered = true
		result.CASScore = score
		result.Confidence = math.Min(0.5+float64(len(reasons))*0.1, 1.0)
		result.Description = "Rare admin action detected"
		if len(reasons) > 0 {
			result.Description += ": " + strings.Join(reasons, "; ")
		}
	}
	return result
}

