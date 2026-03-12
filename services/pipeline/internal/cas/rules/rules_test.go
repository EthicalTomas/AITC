package rules_test

import (
	"testing"
	"time"

	"github.com/ethicaltomas/aitc/services/pipeline/internal/cas/rules"
)

// ── Impossible Travel ────────────────────────────────────────────────────────

func TestImpossibleTravel_Triggered(t *testing.T) {
	// New York → London in 1 hour → physically impossible (~5570 km / 1h = 5570 km/h)
	now := time.Now()
	prev := rules.GeoPoint{Lat: 40.7128, Lon: -74.0060, Timestamp: now, Source: "okta"}
	next := rules.GeoPoint{Lat: 51.5074, Lon: -0.1278, Timestamp: now.Add(1 * time.Hour), Source: "okta"}

	result := rules.ImpossibleTravel(prev, next)

	if !result.Triggered {
		t.Fatalf("expected impossible travel to be triggered, got: %+v", result)
	}
	if result.CASScore <= 0 {
		t.Errorf("expected CASScore > 0, got %f", result.CASScore)
	}
	if result.Confidence <= 0 {
		t.Errorf("expected Confidence > 0, got %f", result.Confidence)
	}
	if result.SpeedKMH <= rules.ImpossibleTravelThresholdKMH {
		t.Errorf("expected speed > threshold, got %f km/h", result.SpeedKMH)
	}
}

func TestImpossibleTravel_NotTriggered_ShortDistance(t *testing.T) {
	// Same city logins — no trigger
	now := time.Now()
	prev := rules.GeoPoint{Lat: 40.7128, Lon: -74.0060, Timestamp: now}
	next := rules.GeoPoint{Lat: 40.7500, Lon: -73.9800, Timestamp: now.Add(30 * time.Minute)}

	result := rules.ImpossibleTravel(prev, next)

	if result.Triggered {
		t.Errorf("expected no trigger for same-city login, got: %+v", result)
	}
}

func TestImpossibleTravel_NotTriggered_SlowTravel(t *testing.T) {
	// NY → LA in 6 hours by plane — legitimate, ~3940 km / 6h = 657 km/h < threshold
	now := time.Now()
	prev := rules.GeoPoint{Lat: 40.7128, Lon: -74.0060, Timestamp: now}
	next := rules.GeoPoint{Lat: 34.0522, Lon: -118.2437, Timestamp: now.Add(6 * time.Hour)}

	result := rules.ImpossibleTravel(prev, next)

	if result.Triggered {
		t.Errorf("expected no trigger for plausible flight, speed: %.0f km/h", result.SpeedKMH)
	}
}

func TestImpossibleTravel_CASScoreCapped(t *testing.T) {
	// Extreme case: antipodal points in 1 minute → score must not exceed 1.0
	now := time.Now()
	prev := rules.GeoPoint{Lat: 90, Lon: 0, Timestamp: now}
	next := rules.GeoPoint{Lat: -90, Lon: 0, Timestamp: now.Add(1 * time.Minute)}

	result := rules.ImpossibleTravel(prev, next)

	if result.CASScore > 1.0 {
		t.Errorf("CASScore must not exceed 1.0, got %f", result.CASScore)
	}
	if result.Confidence > 1.0 {
		t.Errorf("Confidence must not exceed 1.0, got %f", result.Confidence)
	}
}

// ── MFA Fatigue ──────────────────────────────────────────────────────────────

func TestMFAFatigue_Triggered(t *testing.T) {
	now := time.Now()
	events := make([]rules.MFAFatigueEvent, 10)
	for i := range events {
		events[i] = rules.MFAFatigueEvent{
			Timestamp: now.Add(time.Duration(i) * time.Minute),
			Outcome:   "deny",
		}
	}

	result := rules.MFAFatigue(events, 30*time.Minute)

	if !result.Triggered {
		t.Fatalf("expected MFA fatigue to trigger with 10 denials, got: %+v", result)
	}
	if result.CASScore <= 0 {
		t.Errorf("expected CASScore > 0, got %f", result.CASScore)
	}
	if result.PushCount != 10 {
		t.Errorf("expected PushCount=10, got %d", result.PushCount)
	}
}

func TestMFAFatigue_NotTriggered_BelowThreshold(t *testing.T) {
	now := time.Now()
	events := []rules.MFAFatigueEvent{
		{Timestamp: now, Outcome: "deny"},
		{Timestamp: now.Add(5 * time.Minute), Outcome: "deny"},
		{Timestamp: now.Add(10 * time.Minute), Outcome: "success"}, // success
	}

	result := rules.MFAFatigue(events, 30*time.Minute)

	if result.Triggered {
		t.Errorf("expected no trigger with only 2 denials, got: %+v", result)
	}
}

func TestMFAFatigue_WindowRespected(t *testing.T) {
	// 8 denials but spread across 2 hours — only 3 fall within 30-min window
	now := time.Now()
	events := []rules.MFAFatigueEvent{
		{Timestamp: now.Add(-90 * time.Minute), Outcome: "deny"},
		{Timestamp: now.Add(-80 * time.Minute), Outcome: "deny"},
		{Timestamp: now.Add(-70 * time.Minute), Outcome: "deny"},
		{Timestamp: now.Add(-60 * time.Minute), Outcome: "deny"},
		{Timestamp: now.Add(-50 * time.Minute), Outcome: "deny"},
		{Timestamp: now.Add(-10 * time.Minute), Outcome: "deny"},
		{Timestamp: now.Add(-5 * time.Minute), Outcome: "deny"},
		{Timestamp: now, Outcome: "deny"},
	}

	result := rules.MFAFatigue(events, 30*time.Minute)

	// Only the last 3 events fall within the 30-min window
	if result.Triggered {
		t.Errorf("expected no trigger: only 3 events in window, but got PushCount=%d", result.PushCount)
	}
}

func TestMFAFatigue_EmptyEvents(t *testing.T) {
	result := rules.MFAFatigue(nil, 30*time.Minute)
	if result.Triggered {
		t.Error("expected no trigger for empty events")
	}
}

// ── Mailbox Rule ─────────────────────────────────────────────────────────────

func TestMailboxRule_ExternalForward_Triggered(t *testing.T) {
	event := rules.MailboxRuleEvent{
		RuleName:  "Auto forward",
		ForwardTo: []string{"attacker@evil.com"},
	}

	result := rules.MailboxRule(event)

	if !result.Triggered {
		t.Fatalf("expected mailbox rule to trigger on external forward, got: %+v", result)
	}
	if result.CASScore <= 0 {
		t.Errorf("expected CASScore > 0, got %f", result.CASScore)
	}
}

func TestMailboxRule_DeleteAndForward_HighScore(t *testing.T) {
	event := rules.MailboxRuleEvent{
		RuleName:      "Cleanup",
		ForwardTo:     []string{"external@attacker.io"},
		DeleteMessage: true,
		MarkAsRead:    true,
	}

	result := rules.MailboxRule(event)

	if !result.Triggered {
		t.Fatalf("expected trigger, got: %+v", result)
	}
	if result.CASScore < 0.8 {
		t.Errorf("expected CASScore >= 0.8 for delete+forward, got %f", result.CASScore)
	}
}

func TestMailboxRule_SuspiciousKeyword(t *testing.T) {
	event := rules.MailboxRuleEvent{
		RuleName:   "password reset",
		Conditions: []string{"subject contains 'password'"},
	}

	result := rules.MailboxRule(event)

	if !result.Triggered {
		t.Fatalf("expected trigger on suspicious keyword, got: %+v", result)
	}
}

func TestMailboxRule_Benign_NoTrigger(t *testing.T) {
	event := rules.MailboxRuleEvent{
		RuleName:     "Move newsletters",
		MoveToFolder: "Newsletters",
		Conditions:   []string{"from contains 'newsletter'"},
	}

	result := rules.MailboxRule(event)

	if result.Triggered {
		t.Errorf("expected no trigger for benign rule, got: %+v", result)
	}
}

func TestMailboxRule_CASScoreCapped(t *testing.T) {
	event := rules.MailboxRuleEvent{
		RuleName:      "exfil",
		ForwardTo:     []string{"a@b.com", "c@d.com"},
		DeleteMessage: true,
		MarkAsRead:    true,
		Conditions:    []string{"subject contains 'password'", "from contains 'bank'"},
	}

	result := rules.MailboxRule(event)

	if result.CASScore > 1.0 {
		t.Errorf("CASScore must not exceed 1.0, got %f", result.CASScore)
	}
	if result.Confidence > 1.0 {
		t.Errorf("Confidence must not exceed 1.0, got %f", result.Confidence)
	}
}

// ── Mass Download ─────────────────────────────────────────────────────────────

func TestMassDownload_Triggered(t *testing.T) {
result := rules.MassDownload(75, time.Hour)

if !result.Triggered {
t.Fatalf("expected mass download to trigger at 75 downloads, got: %+v", result)
}
if result.CASScore <= 0 {
t.Errorf("expected CASScore > 0, got %f", result.CASScore)
}
if result.Count != 75 {
t.Errorf("expected Count=75, got %d", result.Count)
}
}

func TestMassDownload_NotTriggered_BelowThreshold(t *testing.T) {
result := rules.MassDownload(10, time.Hour)

if result.Triggered {
t.Errorf("expected no trigger for 10 downloads, got: %+v", result)
}
}

func TestMassDownload_AtThreshold_Triggered(t *testing.T) {
result := rules.MassDownload(rules.MassDownloadThreshold, time.Hour)

if !result.Triggered {
t.Errorf("expected trigger exactly at threshold (%d), got: %+v", rules.MassDownloadThreshold, result)
}
}

func TestMassDownload_CASScoreCapped(t *testing.T) {
result := rules.MassDownload(10000, time.Hour)

if result.CASScore > 1.0 {
t.Errorf("CASScore must not exceed 1.0, got %f", result.CASScore)
}
if result.Confidence > 1.0 {
t.Errorf("Confidence must not exceed 1.0, got %f", result.Confidence)
}
}

// ── Rare Admin Action ─────────────────────────────────────────────────────────

func TestRareAdminAction_HighRisk_Triggered(t *testing.T) {
event := rules.AdminActionEvent{
ActionType:        "admin_change.api_token.created",
ActorIsPrivileged: true,
CountInWindow:     1, // rare
Window:            24 * time.Hour,
IsAfterHours:      true,
}

result := rules.RareAdminAction(event)

if !result.Triggered {
t.Fatalf("expected rare admin action to trigger, got: %+v", result)
}
if result.CASScore <= 0 {
t.Errorf("expected CASScore > 0, got %f", result.CASScore)
}
}

func TestRareAdminAction_LowRisk_NoTrigger(t *testing.T) {
event := rules.AdminActionEvent{
ActionType:        "admin_change.user.updated",
ActorIsPrivileged: false,
CountInWindow:     10, // frequent
Window:            24 * time.Hour,
IsAfterHours:      false,
}

result := rules.RareAdminAction(event)

if result.Triggered {
t.Errorf("expected no trigger for low-risk frequent action, got: %+v", result)
}
}

func TestRareAdminAction_CASScoreCapped(t *testing.T) {
event := rules.AdminActionEvent{
ActionType:        "admin_change.api_token.created",
ActorIsPrivileged: true,
CountInWindow:     0,
Window:            24 * time.Hour,
IsAfterHours:      true,
}

result := rules.RareAdminAction(event)

if result.CASScore > 1.0 {
t.Errorf("CASScore must not exceed 1.0, got %f", result.CASScore)
}
}

// ── Risky OAuth Grant ─────────────────────────────────────────────────────────

func TestRiskyOAuthGrant_SensitiveScopes_Triggered(t *testing.T) {
event := rules.OAuthGrantEvent{
AppName:           "malicious-app",
Scopes:            []string{"mail.read", "files.readwrite.all"},
IsFirstTimeApp:    true,
GrantedByNonAdmin: true,
}

result := rules.RiskyOAuthGrant(event)

if !result.Triggered {
t.Fatalf("expected risky OAuth grant to trigger, got: %+v", result)
}
if result.CASScore <= 0 {
t.Errorf("expected CASScore > 0, got %f", result.CASScore)
}
}

func TestRiskyOAuthGrant_NoSensitiveScopes_NoTrigger(t *testing.T) {
event := rules.OAuthGrantEvent{
AppName:           "safe-app",
Scopes:            []string{"openid", "profile", "email"},
IsFirstTimeApp:    false,
GrantedByNonAdmin: false,
}

result := rules.RiskyOAuthGrant(event)

if result.Triggered {
t.Errorf("expected no trigger for safe scopes, got: %+v", result)
}
}

func TestRiskyOAuthGrant_CASScoreCapped(t *testing.T) {
event := rules.OAuthGrantEvent{
AppName: "mega-risky",
Scopes: []string{
"mail.read", "mail.readwrite", "files.readwrite.all",
"directory.readwrite.all", "all",
},
IsFirstTimeApp:    true,
GrantedByNonAdmin: true,
}

result := rules.RiskyOAuthGrant(event)

if result.CASScore > 1.0 {
t.Errorf("CASScore must not exceed 1.0, got %f", result.CASScore)
}
if result.Confidence > 1.0 {
t.Errorf("Confidence must not exceed 1.0, got %f", result.Confidence)
}
}
