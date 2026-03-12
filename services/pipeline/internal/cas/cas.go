// Package cas implements the Composite Anomaly Score (CAS) engine.
// It orchestrates individual detection rules, produces RiskSignalV1 protobuf
// payloads, and is the primary output stage before case creation.
package cas

import (
"context"
"time"

"github.com/google/uuid"
"go.uber.org/zap"
"google.golang.org/protobuf/types/known/timestamppb"

eventspb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/events"
riskpb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/risk"
"github.com/ethicaltomas/aitc/services/pipeline/internal/cas/rules"
"github.com/ethicaltomas/aitc/services/pipeline/internal/features"
)

// Engine orchestrates CAS rules and emits RiskSignalV1 messages.
type Engine struct {
logger *zap.Logger
}

// NewEngine creates a new CAS Engine.
func NewEngine(logger *zap.Logger) *Engine {
if logger == nil {
logger = zap.NewNop()
}
return &Engine{logger: logger}
}

// Score evaluates all applicable CAS rules for the given normalized event and
// extracted features. It returns zero or more RiskSignalV1 messages — one per
// triggered rule. Callers must persist each signal and emit it to Kafka.
func (e *Engine) Score(
ctx context.Context,
ev *eventspb.NormalizedEventV1,
feats *features.Features,
) ([]*riskpb.RiskSignalV1, error) {
_ = ctx
if ev == nil {
return nil, nil
}
if feats == nil {
feats = &features.Features{}
}

var signals []*riskpb.RiskSignalV1
now := timestamppb.New(time.Now().UTC())
identityID := ev.GetActorId()
if identityID == "" {
identityID = ev.GetActorEmail()
}

// ── 1. Impossible Travel ─────────────────────────────────────────────────
if feats.PrevGeoPoint != nil && (ev.GetGeoLat() != 0 || ev.GetGeoLon() != 0) {
prev := rules.GeoPoint{
Lat:       feats.PrevGeoPoint.Lat,
Lon:       feats.PrevGeoPoint.Lon,
Timestamp: feats.PrevGeoPoint.Timestamp,
Source:    feats.PrevGeoPoint.Source,
}
var occurredAt time.Time
if t := ev.GetOccurredAt(); t != nil {
occurredAt = t.AsTime()
} else {
occurredAt = time.Now().UTC()
}
next := rules.GeoPoint{
Lat:       ev.GetGeoLat(),
Lon:       ev.GetGeoLon(),
Timestamp: occurredAt,
Source:    ev.GetSource(),
}
if result := rules.ImpossibleTravel(prev, next); result.Triggered {
signals = append(signals, buildSignal(
"impossible_travel", "Impossible Travel",
ev, identityID, result.CASScore, result.Confidence,
result.Description, now,
))
}
}

// ── 2. MFA Fatigue ───────────────────────────────────────────────────────
if feats.MFAPushCount >= rules.MFAFatigueThreshold {
syntheticEvents := make([]rules.MFAFatigueEvent, feats.MFAPushCount)
base := time.Now().UTC()
for i := int64(0); i < feats.MFAPushCount; i++ {
syntheticEvents[i] = rules.MFAFatigueEvent{
Timestamp: base.Add(-time.Duration(feats.MFAPushCount-i) * time.Minute),
Outcome:   "deny",
}
}
if result := rules.MFAFatigue(syntheticEvents, features.WindowMFAPush); result.Triggered {
signals = append(signals, buildSignal(
"mfa_fatigue", "MFA Fatigue",
ev, identityID, result.CASScore, result.Confidence,
result.Description, now,
))
}
}

// ── 3. Mailbox Rule ──────────────────────────────────────────────────────
if ev.GetAction() == "mailbox_rule.created" || ev.GetAction() == "mailbox_rule.updated" ||
ev.GetAction() == "mailbox_rule.forward_created" {
mre := rules.MailboxRuleEvent{
RuleName: ev.GetAction(),
}
if ev.GetAction() == "mailbox_rule.forward_created" {
mre.ForwardTo = []string{"external"}
}
if result := rules.MailboxRule(mre); result.Triggered {
signals = append(signals, buildSignal(
"mailbox_rule", "Suspicious Mailbox Rule",
ev, identityID, result.CASScore, result.Confidence,
result.Description, now,
))
}
}

// ── 4. Mass Download ─────────────────────────────────────────────────────
if result := rules.MassDownload(int(feats.FileDownloadCount), features.WindowFileDownload); result.Triggered {
signals = append(signals, buildSignal(
"mass_download", "Mass File Download",
ev, identityID, result.CASScore, result.Confidence,
result.Description, now,
))
}

// ── 5. Rare Admin Action ─────────────────────────────────────────────────
if ev.GetActorIsPrivileged() || ev.GetCategory() == eventspb.EventCategory_ADMIN {
var afterHours bool
if t := ev.GetOccurredAt(); t != nil {
h := t.AsTime().UTC().Hour()
afterHours = h < 7 || h >= 20
}
adminEvent := rules.AdminActionEvent{
ActionType:        ev.GetAction(),
ActorIsPrivileged: ev.GetActorIsPrivileged(),
CountInWindow:     int(feats.AdminActionCount),
Window:            features.WindowAdminAction,
IsAfterHours:      afterHours,
}
if result := rules.RareAdminAction(adminEvent); result.Triggered {
signals = append(signals, buildSignal(
"rare_admin_action", "Rare Admin Action",
ev, identityID, result.CASScore, result.Confidence,
result.Description, now,
))
}
}

// ── 6. Risky OAuth Grant ─────────────────────────────────────────────────
if ev.GetCategory() == eventspb.EventCategory_OAUTH {
oauthEvent := rules.OAuthGrantEvent{
AppName:           ev.GetTargetId(),
GrantedByNonAdmin: !ev.GetActorIsPrivileged(),
IsFirstTimeApp:    true,
}
if result := rules.RiskyOAuthGrant(oauthEvent); result.Triggered {
signals = append(signals, buildSignal(
"risky_oauth_grant", "Risky OAuth Grant",
ev, identityID, result.CASScore, result.Confidence,
result.Description, now,
))
}
}

e.logger.Debug("cas.Score complete",
zap.String("event_id", ev.GetEventId()),
zap.Int("signals", len(signals)),
)
return signals, nil
}

// buildSignal constructs a RiskSignalV1 for a triggered rule.
func buildSignal(
ruleID, ruleName string,
ev *eventspb.NormalizedEventV1,
identityID string,
casScore, confidence float64,
description string,
detectedAt *timestamppb.Timestamp,
) *riskpb.RiskSignalV1 {
return &riskpb.RiskSignalV1{
SignalId:         uuid.New().String(),
TenantId:         ev.GetTenantId(),
IdentityId:       identityID,
RuleId:           ruleID,
RuleName:         ruleName,
Severity:         severityProto(casScore),
CasScore:         casScore,
Confidence:       confidence,
Description:      description,
EvidenceEventIds: []string{ev.GetEventId()},
DetectedAt:       detectedAt,
}
}

// severityProto maps a CAS score to a RiskSignalV1 Severity enum.
func severityProto(score float64) riskpb.Severity {
switch {
case score >= 0.85:
return riskpb.Severity_CRITICAL
case score >= 0.65:
return riskpb.Severity_HIGH
case score >= 0.40:
return riskpb.Severity_MEDIUM
default:
return riskpb.Severity_LOW
}
}
