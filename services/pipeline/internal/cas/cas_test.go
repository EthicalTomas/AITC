package cas_test

import (
"context"
"testing"
"time"

"go.uber.org/zap"
"google.golang.org/protobuf/types/known/timestamppb"

eventspb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/events"
riskpb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/risk"
"github.com/ethicaltomas/aitc/services/pipeline/internal/cas"
"github.com/ethicaltomas/aitc/services/pipeline/internal/features"
)

func newEngine() *cas.Engine {
return cas.New(zap.NewNop())
}

// ── Confidence helpers ────────────────────────────────────────────────────────

func TestSeverityFromScore(t *testing.T) {
tests := []struct {
score float64
want  riskpb.Severity
}{
{0.9, riskpb.Severity_CRITICAL},
{0.8, riskpb.Severity_CRITICAL},
{0.79, riskpb.Severity_HIGH},
{0.6, riskpb.Severity_HIGH},
{0.59, riskpb.Severity_MEDIUM},
{0.4, riskpb.Severity_MEDIUM},
{0.39, riskpb.Severity_LOW},
{0.01, riskpb.Severity_LOW},
{0.0, riskpb.Severity_SEVERITY_UNSPECIFIED},
}
for _, tt := range tests {
got := cas.SeverityFromScore(tt.score)
if got != tt.want {
t.Errorf("SeverityFromScore(%f) = %v, want %v", tt.score, got, tt.want)
}
}
}

func TestWeightedScore(t *testing.T) {
tests := []struct {
cas, conf, want float64
}{
{0.8, 1.0, 0.8},
{0.8, 0.5, 0.4},
{0.5, 0.0, 0.0},
{1.0, 1.0, 1.0},
{2.0, 1.0, 1.0}, // capped
}
for _, tt := range tests {
got := cas.WeightedScore(tt.cas, tt.conf)
if got != tt.want {
t.Errorf("WeightedScore(%f, %f) = %f, want %f", tt.cas, tt.conf, got, tt.want)
}
}
}

// ── Engine tests ──────────────────────────────────────────────────────────────

func baseEvent() *eventspb.NormalizedEventV1 {
return &eventspb.NormalizedEventV1{
EventId:    "evt-001",
TenantId:   "tenant-test",
ActorId:    "00u1abc",
Source:     "okta",
Action:     "auth.login.success",
Category:   eventspb.EventCategory_AUTHENTICATION,
Outcome:    "success",
OccurredAt: timestamppb.New(time.Now()),
}
}

func emptyFeats() *features.Features {
return &features.Features{AdminActionCount: -1}
}

func TestEngine_NoSignals_BenignLogin(t *testing.T) {
engine := newEngine()
ev := baseEvent()
feats := emptyFeats()

signals, err := engine.Score(context.Background(), ev, feats)
if err != nil {
t.Fatalf("Score: %v", err)
}
if len(signals) != 0 {
t.Errorf("expected no signals for benign login, got %d: %+v", len(signals), signals)
}
}

func TestEngine_MFAFatigue_Triggered(t *testing.T) {
engine := newEngine()
ev := baseEvent()
ev.Category = eventspb.EventCategory_MFA
ev.Action = "auth.mfa.push_denied"
ev.Outcome = "failure"

feats := emptyFeats()
feats.MFADenialCount = 10 // above MFAFatigueThreshold=5

signals, err := engine.Score(context.Background(), ev, feats)
if err != nil {
t.Fatalf("Score: %v", err)
}

var found bool
for _, s := range signals {
if s.GetRuleId() == "mfa_fatigue" {
found = true
}
}
if !found {
t.Errorf("expected mfa_fatigue signal, got: %+v", signals)
}
}

func TestEngine_ImpossibleTravel_Triggered(t *testing.T) {
engine := newEngine()
ev := baseEvent()
ev.GeoLat = 51.5074  // London
ev.GeoLon = -0.1278

// Previous geo: New York, now is 1 hour later
prevTime := time.Now().Add(-1 * time.Hour)
feats := emptyFeats()
feats.GeoHistory = []features.GeoEntry{
// Newest first (LPush order)
{Lat: 51.5074, Lon: -0.1278, Timestamp: time.Now(), Source: "okta"},
{Lat: 40.7128, Lon: -74.0060, Timestamp: prevTime, Source: "okta"},
}

signals, err := engine.Score(context.Background(), ev, feats)
if err != nil {
t.Fatalf("Score: %v", err)
}

var found bool
for _, s := range signals {
if s.GetRuleId() == "impossible_travel" {
found = true
if s.GetCasScore() <= 0 {
t.Error("impossible_travel signal CASScore should be > 0")
}
}
}
if !found {
t.Errorf("expected impossible_travel signal, got: %+v", signals)
}
}

func TestEngine_RareAdminAction_Triggered(t *testing.T) {
engine := newEngine()
ev := baseEvent()
ev.Action = "admin.user.created"
ev.Category = eventspb.EventCategory_ADMIN

feats := emptyFeats()
feats.AdminActionCount = 0 // no history → rare

signals, err := engine.Score(context.Background(), ev, feats)
if err != nil {
t.Fatalf("Score: %v", err)
}

var found bool
for _, s := range signals {
if s.GetRuleId() == "rare_admin_action" {
found = true
}
}
if !found {
t.Errorf("expected rare_admin_action signal, got: %+v", signals)
}
}

func TestEngine_MassDownload_Triggered(t *testing.T) {
engine := newEngine()
ev := baseEvent()
ev.Action = "file.downloaded"
ev.Category = eventspb.EventCategory_FILE

feats := emptyFeats()
feats.FileDownloadCount = 200 // well above threshold

signals, err := engine.Score(context.Background(), ev, feats)
if err != nil {
t.Fatalf("Score: %v", err)
}

var found bool
for _, s := range signals {
if s.GetRuleId() == "mass_download" {
found = true
}
}
if !found {
t.Errorf("expected mass_download signal, got: %+v", signals)
}
}

func TestEngine_SignalFields(t *testing.T) {
engine := newEngine()
ev := baseEvent()
ev.Action = "admin.user.created"
ev.Category = eventspb.EventCategory_ADMIN
feats := emptyFeats()
feats.AdminActionCount = 0

signals, _ := engine.Score(context.Background(), ev, feats)
if len(signals) == 0 {
t.Fatal("expected at least one signal")
}
sig := signals[0]

if sig.GetSignalId() == "" {
t.Error("SignalId must be set (UUID)")
}
if sig.GetTenantId() != "tenant-test" {
t.Errorf("TenantId: got %q, want tenant-test", sig.GetTenantId())
}
if sig.GetRuleId() == "" {
t.Error("RuleId must be set")
}
if sig.GetSeverity() == riskpb.Severity_SEVERITY_UNSPECIFIED {
t.Error("Severity must not be UNSPECIFIED for a triggered signal")
}
if len(sig.GetEvidenceEventIds()) == 0 {
t.Error("EvidenceEventIds must be populated")
}
if sig.GetDetectedAt() == nil {
t.Error("DetectedAt must be set")
}
}
