// Package cas implements the Composite Anomaly Score (CAS) engine.
// It orchestrates all CAS detection rules and emits RiskSignalV1 messages.
package cas

import (
"context"
"strings"
"time"

"github.com/google/uuid"
"go.uber.org/zap"
"google.golang.org/protobuf/types/known/timestamppb"

eventspb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/events"
riskpb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/risk"
"github.com/ethicaltomas/aitc/services/pipeline/internal/cas/rules"
"github.com/ethicaltomas/aitc/services/pipeline/internal/features"
)

// Engine orchestrates all CAS rules against normalized events.
type Engine struct {
logger *zap.Logger
}

// New creates a new CAS Engine.
func New(logger *zap.Logger) *Engine {
return &Engine{logger: logger}
}

// Score evaluates all applicable CAS rules for a normalized event and its
// extracted features. Returns zero or more RiskSignalV1 messages (one per
// triggered rule). All signals must be persisted and emitted by the caller.
func (e *Engine) Score(
ctx context.Context,
ev *eventspb.NormalizedEventV1,
feats *features.Features,
) ([]*riskpb.RiskSignalV1, error) {
_ = ctx
var signals []*riskpb.RiskSignalV1
now := time.Now().UTC()

// ── 1. Impossible Travel ─────────────────────────────────────────────────
if len(feats.GeoHistory) >= 2 {
prev, next, ok := featuresLastTwo(feats.GeoHistory)
if ok && (ev.GetGeoLat() != 0 || ev.GetGeoLon() != 0) {
// Use the latest geo from the event as "next"
currentGeo := rules.GeoPoint{
Lat:  ev.GetGeoLat(),
Lon:  ev.GetGeoLon(),
Source: ev.GetSource(),
}
if t := ev.GetOccurredAt(); t != nil {
currentGeo.Timestamp = t.AsTime()
} else {
currentGeo.Timestamp = now
}
_ = next // previous entry in history is our "prev"
result := rules.ImpossibleTravel(prev, currentGeo)
if result.Triggered {
signals = append(signals, e.buildSignal(
"impossible_travel", "Impossible Travel",
ev, result.CASScore, result.Confidence,
result.Description, now,
))
}
}
}

// ── 2. MFA Fatigue ───────────────────────────────────────────────────────
if feats.MFADenialCount > 0 {
mfaEvents := features.BuildMFAEvents(feats.MFADenialCount, now, features.WindowMFADenials)
result := rules.MFAFatigue(mfaEvents, features.WindowMFADenials)
if result.Triggered {
signals = append(signals, e.buildSignal(
"mfa_fatigue", "MFA Fatigue",
ev, result.CASScore, result.Confidence,
result.Description, now,
))
}
}

// ── 3. Mailbox Rule ──────────────────────────────────────────────────────
if ev.GetAction() == "mailbox_rule.created" || ev.GetAction() == "mailbox_rule.updated" {
// Build a MailboxRuleEvent from the normalized event.
// ForwardTo, DeleteMessage etc. are not available without raw payload,
// so we use a conservative signal based on action alone.
mre := rules.MailboxRuleEvent{
RuleName: ev.GetAction(),
}
// If targeting an external address (TargetId looks like an email), flag it.
if target := ev.GetTargetId(); strings.Contains(target, "@") {
mre.ForwardTo = []string{target}
}
result := rules.MailboxRule(mre)
if result.Triggered {
signals = append(signals, e.buildSignal(
"mailbox_rule", "Suspicious Mailbox Rule",
ev, result.CASScore, result.Confidence,
result.Description, now,
))
}
}

// ── 4. Mass Download ─────────────────────────────────────────────────────
if feats.FileDownloadCount > 0 {
result := rules.MassDownload(feats.FileDownloadCount, features.WindowFileDownload)
if result.Triggered {
signals = append(signals, e.buildSignal(
"mass_download", "Mass File Download",
ev, result.CASScore, result.Confidence,
result.Description, now,
))
}
}

// ── 5. Rare Admin Action ─────────────────────────────────────────────────
if feats.AdminActionCount >= 0 {
result := rules.RareAdminAction(ev.GetAction(), feats.AdminActionCount)
if result.Triggered {
signals = append(signals, e.buildSignal(
"rare_admin_action", "Rare Admin Action",
ev, result.CASScore, result.Confidence,
result.Description, now,
))
}
}

// ── 6. Risky OAuth Grant ─────────────────────────────────────────────────
if ev.GetCategory() == eventspb.EventCategory_OAUTH {
// Scopes are not directly modeled; use action as a signal.
// Grant by non-privileged user is automatically high-risk.
result := rules.RiskyOAuthGrant(
ev.GetAction(),
nil, // scopes not available at normalization level
!ev.GetActorIsPrivileged(),
)
if result.Triggered {
signals = append(signals, e.buildSignal(
"risky_oauth_grant", "Risky OAuth Grant",
ev, result.CASScore, result.Confidence,
result.Description, now,
))
}
}

if len(signals) > 0 {
e.logger.Info("cas: signals generated",
zap.String("event_id", ev.GetEventId()),
zap.String("actor_id", ev.GetActorId()),
zap.Int("signals", len(signals)),
)
}

return signals, nil
}

// buildSignal constructs a RiskSignalV1 for a triggered rule.
func (e *Engine) buildSignal(
ruleID, ruleName string,
ev *eventspb.NormalizedEventV1,
casScore, confidence float64,
description string,
now time.Time,
) *riskpb.RiskSignalV1 {
weighted := WeightedScore(casScore, confidence)
sev := SeverityFromScore(weighted)

return &riskpb.RiskSignalV1{
SignalId:         uuid.NewString(),
TenantId:         ev.GetTenantId(),
IdentityId:       ev.GetActorId(),
RuleId:           ruleID,
RuleName:         ruleName,
Severity:         sev,
CasScore:         casScore,
Confidence:       confidence,
Description:      description,
EvidenceEventIds: []string{ev.GetEventId()},
DetectedAt:       timestamppb.New(now),
}
}

// featuresLastTwo extracts the previous and current geo-points from the history.
func featuresLastTwo(history []features.GeoEntry) (prev, next rules.GeoPoint, ok bool) {
if len(history) < 2 {
return rules.GeoPoint{}, rules.GeoPoint{}, false
}
// History is stored newest-first (LPush), so [0] is most recent, [1] is previous.
toGeo := func(e features.GeoEntry) rules.GeoPoint {
return rules.GeoPoint{Lat: e.Lat, Lon: e.Lon, Timestamp: e.Timestamp, Source: e.Source}
}
return toGeo(history[1]), toGeo(history[0]), true
}
