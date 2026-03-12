package rules_test

import (
"testing"
"time"

"github.com/ethicaltomas/aitc/services/pipeline/internal/cas/rules"
)

// ── Mass Download ─────────────────────────────────────────────────────────────

func TestMassDownload_Triggered(t *testing.T) {
result := rules.MassDownload(100, time.Hour)
if !result.Triggered {
t.Fatalf("expected mass download to trigger with 100 downloads, got: %+v", result)
}
if result.CASScore <= 0 {
t.Errorf("expected CASScore > 0, got %f", result.CASScore)
}
if result.CASScore > 1.0 {
t.Errorf("CASScore must not exceed 1.0, got %f", result.CASScore)
}
if result.Count != 100 {
t.Errorf("expected Count=100, got %d", result.Count)
}
}

func TestMassDownload_BelowThreshold(t *testing.T) {
result := rules.MassDownload(10, time.Hour)
if result.Triggered {
t.Errorf("expected no trigger for 10 downloads (threshold=%d)", rules.MassDownloadThreshold)
}
}

func TestMassDownload_AtThreshold(t *testing.T) {
result := rules.MassDownload(rules.MassDownloadThreshold, time.Hour)
if !result.Triggered {
t.Errorf("expected trigger at exactly threshold=%d", rules.MassDownloadThreshold)
}
}

func TestMassDownload_ScoreCapped(t *testing.T) {
result := rules.MassDownload(100000, time.Hour)
if result.CASScore > 1.0 {
t.Errorf("CASScore must not exceed 1.0 for extreme count, got %f", result.CASScore)
}
}

// ── Rare Admin Action ─────────────────────────────────────────────────────────

func TestRareAdminAction_Triggered_ZeroHistory(t *testing.T) {
result := rules.RareAdminAction("admin.user.created", 0)
if !result.Triggered {
t.Fatalf("expected rare admin action to trigger with 0 history, got: %+v", result)
}
if result.CASScore <= 0 {
t.Errorf("expected CASScore > 0, got %f", result.CASScore)
}
}

func TestRareAdminAction_Triggered_LowHistory(t *testing.T) {
result := rules.RareAdminAction("admin.role.assigned", 2)
if !result.Triggered {
t.Fatalf("expected trigger with 2 prior actions (threshold=%d)", rules.RareAdminActionThreshold)
}
}

func TestRareAdminAction_NotTriggered_HighHistory(t *testing.T) {
result := rules.RareAdminAction("admin.user.deactivated", 100)
if result.Triggered {
t.Errorf("expected no trigger with 100 prior admin actions, got: %+v", result)
}
}

func TestRareAdminAction_NotTriggered_NonAdminAction(t *testing.T) {
result := rules.RareAdminAction("auth.login.success", 0)
if result.Triggered {
t.Errorf("expected no trigger for non-admin action, got: %+v", result)
}
}

func TestRareAdminAction_ScoreCapped(t *testing.T) {
result := rules.RareAdminAction("admin.api_token.created", 0)
if result.CASScore > 1.0 {
t.Errorf("CASScore must not exceed 1.0, got %f", result.CASScore)
}
if result.Confidence > 1.0 {
t.Errorf("Confidence must not exceed 1.0, got %f", result.Confidence)
}
}

// ── Risky OAuth Grant ─────────────────────────────────────────────────────────

func TestRiskyOAuthGrant_Triggered_HighRiskScopes(t *testing.T) {
scopes := []string{"mail.readwrite", "files.readwrite"}
result := rules.RiskyOAuthGrant("oauth.delegated_permission.granted", scopes, false)
if !result.Triggered {
t.Fatalf("expected risky OAuth grant to trigger, got: %+v", result)
}
if result.CASScore <= 0 {
t.Errorf("expected CASScore > 0, got %f", result.CASScore)
}
}

func TestRiskyOAuthGrant_HigherScore_NonAdminGrant(t *testing.T) {
scopes := []string{"mail.readwrite"}
adminResult := rules.RiskyOAuthGrant("oauth.delegated_permission.granted", scopes, false)
nonAdminResult := rules.RiskyOAuthGrant("oauth.delegated_permission.granted", scopes, true)
if nonAdminResult.CASScore <= adminResult.CASScore {
t.Errorf("non-admin grant should have higher score: admin=%f nonAdmin=%f",
adminResult.CASScore, nonAdminResult.CASScore)
}
}

func TestRiskyOAuthGrant_LowScore_SafeScopes(t *testing.T) {
// OAuth grant with only safe scopes still produces a base-level signal
// because any OAuth consent event can be part of a phishing attack.
// Score should be low (< 0.6) without high-risk scopes.
scopes := []string{"openid", "profile", "email"}
result := rules.RiskyOAuthGrant("oauth.delegated_permission.granted", scopes, false)
if !result.Triggered {
t.Errorf("expected base signal for any OAuth grant operation, got: %+v", result)
}
if result.CASScore >= 0.6 {
t.Errorf("expected low score for safe-scope grant, got %f", result.CASScore)
}
}

func TestRiskyOAuthGrant_NotTriggered_WrongOperation(t *testing.T) {
scopes := []string{"mail.readwrite", "files.readwrite.all"}
result := rules.RiskyOAuthGrant("auth.login.success", scopes, false)
if result.Triggered {
t.Errorf("expected no trigger for non-OAuth operation, got: %+v", result)
}
}

func TestRiskyOAuthGrant_ScoreCapped(t *testing.T) {
scopes := []string{
"mail.readwrite", "files.readwrite", "contacts.readwrite",
"calendars.readwrite", "user.read.all", "directory.readwrite.all",
"offline_access",
}
result := rules.RiskyOAuthGrant("oauth.app.consent", scopes, true)
if result.CASScore > 1.0 {
t.Errorf("CASScore must not exceed 1.0, got %f", result.CASScore)
}
}
