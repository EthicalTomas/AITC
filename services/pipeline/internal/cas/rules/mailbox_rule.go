package rules

import (
	"fmt"
	"strings"
)

// MailboxRuleResult is the output of the suspicious inbox rule detection.
type MailboxRuleResult struct {
	Triggered   bool
	CASScore    float64
	Confidence  float64
	Description string
	RuleName    string
	Conditions  []string
}

// MailboxRuleEvent represents a mailbox rule creation/modification event.
type MailboxRuleEvent struct {
	// RuleName is the name of the inbox rule set by the user.
	RuleName string
	// ForwardTo contains external email addresses the rule forwards to.
	ForwardTo []string
	// DeleteMessage is true if the rule silently deletes messages.
	DeleteMessage bool
	// MarkAsRead is true if the rule marks messages as read (hides from inbox).
	MarkAsRead bool
	// MoveToFolder is the destination folder (empty = no move action).
	MoveToFolder string
	// Conditions are the match conditions on the rule.
	Conditions []string
}

// suspiciousKeywords in rule names or conditions indicate data exfiltration intent.
var suspiciousKeywords = []string{
	"password", "invoice", "wire", "transfer", "payroll", "confidential",
	"secret", "credential", "account", "bank", "reset", "verify",
}

// MailboxRule detects suspicious inbox rule creation indicative of BEC
// (Business Email Compromise) or data exfiltration setup.
func MailboxRule(event MailboxRuleEvent) MailboxRuleResult {
	result := MailboxRuleResult{
		RuleName:   event.RuleName,
		Conditions: event.Conditions,
	}

	score := 0.0
	reasons := []string{}

	// External forwarding is always high-risk
	if len(event.ForwardTo) > 0 {
		score += 0.6
		reasons = append(reasons, fmt.Sprintf("rule forwards to external address(es): %s", strings.Join(event.ForwardTo, ", ")))
	}

	// Silent deletion covers tracks after exfiltration
	if event.DeleteMessage {
		score += 0.3
		reasons = append(reasons, "rule deletes matching messages (covers tracks)")
	}

	// Mark-as-read hides alerts from the victim
	if event.MarkAsRead {
		score += 0.1
		reasons = append(reasons, "rule marks messages as read")
	}

	// Suspicious keywords in conditions
	allText := strings.ToLower(event.RuleName + " " + strings.Join(event.Conditions, " "))
	for _, kw := range suspiciousKeywords {
		if strings.Contains(allText, kw) {
			score += 0.15
			reasons = append(reasons, fmt.Sprintf("suspicious keyword in rule: %q", kw))
			break // count once
		}
	}

	if score > 0 {
		if score > 1.0 {
			score = 1.0
		}
		result.Triggered = true
		result.CASScore = score
		result.Confidence = 0.7 + float64(len(reasons))*0.05
		if result.Confidence > 1.0 {
			result.Confidence = 1.0
		}
		result.Description = "Suspicious mailbox rule detected: " + strings.Join(reasons, "; ")
	}
	return result
}


