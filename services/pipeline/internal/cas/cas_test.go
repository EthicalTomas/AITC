package cas_test

import (
"context"
"testing"
"time"

"google.golang.org/protobuf/types/known/timestamppb"

eventspb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/events"
riskpb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/risk"
"github.com/ethicaltomas/aitc/services/pipeline/internal/cas"
"github.com/ethicaltomas/aitc/services/pipeline/internal/features"
"github.com/ethicaltomas/aitc/services/pipeline/internal/persistence"
)

func TestCASEngine_ImpossibleTravel(t *testing.T) {
engine := cas.NewEngine(nil)

// New York → London in 1 hour = physically impossible
prevTime := time.Now().UTC().Add(-1 * time.Hour)
nextTime := time.Now().UTC()

ev := &eventspb.NormalizedEventV1{
EventId:    "evt-001",
TenantId:   "tenant-abc",
ActorId:    "user-123",
Source:     "okta",
Action:     "auth.login.success",
GeoLat:     51.5074, // London
GeoLon:     -0.1278,
OccurredAt: timestamppb.New(nextTime),
}

feats := &features.Features{
PrevGeoPoint: &persistence.GeoPoint{
Lat:       40.7128, // New York
Lon:       -74.0060,
Timestamp: prevTime,
Source:    "okta",
},
}

signals, err := engine.Score(context.Background(), ev, feats)
if err != nil {
t.Fatalf("Score: %v", err)
}

found := findSignal(signals, "impossible_travel")
if found == nil {
t.Fatal("expected impossible_travel signal")
}
if found.GetCasScore() <= 0 {
t.Errorf("expected CASScore > 0, got %f", found.GetCasScore())
}
if found.GetTenantId() != "tenant-abc" {
t.Errorf("tenant_id = %q, want %q", found.GetTenantId(), "tenant-abc")
}
}

func TestCASEngine_MFAFatigue(t *testing.T) {
engine := cas.NewEngine(nil)

ev := &eventspb.NormalizedEventV1{
EventId:  "evt-002",
TenantId: "tenant-abc",
ActorId:  "user-456",
Action:   "auth.mfa.push_denied",
}

feats := &features.Features{
MFAPushCount: 8, // above threshold of 5
}

signals, err := engine.Score(context.Background(), ev, feats)
if err != nil {
t.Fatalf("Score: %v", err)
}

found := findSignal(signals, "mfa_fatigue")
if found == nil {
t.Fatal("expected mfa_fatigue signal")
}
if found.GetSeverity() == riskpb.Severity_SEVERITY_UNSPECIFIED {
t.Error("expected non-zero severity")
}
}

func TestCASEngine_MassDownload(t *testing.T) {
engine := cas.NewEngine(nil)

ev := &eventspb.NormalizedEventV1{
EventId:  "evt-003",
TenantId: "tenant-abc",
ActorId:  "user-789",
Action:   "file_access.downloaded",
Category: eventspb.EventCategory_FILE,
}

feats := &features.Features{
FileDownloadCount: 100, // well above threshold of 50
}

signals, err := engine.Score(context.Background(), ev, feats)
if err != nil {
t.Fatalf("Score: %v", err)
}

found := findSignal(signals, "mass_download")
if found == nil {
t.Fatal("expected mass_download signal")
}
}

func TestCASEngine_NilEvent(t *testing.T) {
engine := cas.NewEngine(nil)
signals, err := engine.Score(context.Background(), nil, nil)
if err != nil {
t.Errorf("unexpected error for nil event: %v", err)
}
if len(signals) != 0 {
t.Errorf("expected no signals for nil event, got %d", len(signals))
}
}

func TestCASEngine_NoSignals_NormalLogin(t *testing.T) {
engine := cas.NewEngine(nil)

ev := &eventspb.NormalizedEventV1{
EventId:  "evt-normal",
TenantId: "tenant-abc",
ActorId:  "user-normal",
Action:   "auth.login.success",
Category: eventspb.EventCategory_AUTHENTICATION,
}

// Normal features — no thresholds exceeded, no prior geo point
feats := &features.Features{
MFAPushCount:      0,
FileDownloadCount: 5,
AdminActionCount:  0,
}

signals, err := engine.Score(context.Background(), ev, feats)
if err != nil {
t.Fatalf("Score: %v", err)
}
if len(signals) > 0 {
t.Errorf("expected no signals for normal login, got %d: %v", len(signals), signalIDs(signals))
}
}

// ── Confidence helpers ────────────────────────────────────────────────────────

func TestCombineScores(t *testing.T) {
tests := []struct {
name   string
scores []float64
wantGT float64
wantLE float64
}{
{"empty", nil, -1, 0.001},
{"single", []float64{0.8}, 0.79, 1.01},
{"average", []float64{0.6, 0.4}, 0.49, 0.51},
{"cap at 1", []float64{0.9, 0.9, 0.9}, 0.89, 1.01},
}
for _, tc := range tests {
t.Run(tc.name, func(t *testing.T) {
got := cas.CombineScores(tc.scores)
if got <= tc.wantGT {
t.Errorf("CombineScores(%v) = %f, want > %f", tc.scores, got, tc.wantGT)
}
if got > tc.wantLE {
t.Errorf("CombineScores(%v) = %f, want <= %f", tc.scores, got, tc.wantLE)
}
})
}
}

func TestSeverityFromScore(t *testing.T) {
tests := []struct {
score float64
want  string
}{
{0.90, "critical"},
{0.70, "high"},
{0.50, "medium"},
{0.20, "low"},
{0.0, "none"},
}
for _, tc := range tests {
got := cas.SeverityFromScore(tc.score)
if got != tc.want {
t.Errorf("SeverityFromScore(%f) = %q, want %q", tc.score, got, tc.want)
}
}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func findSignal(signals []*riskpb.RiskSignalV1, ruleID string) *riskpb.RiskSignalV1 {
for _, s := range signals {
if s.GetRuleId() == ruleID {
return s
}
}
return nil
}

func signalIDs(signals []*riskpb.RiskSignalV1) []string {
ids := make([]string, len(signals))
for i, s := range signals {
ids[i] = s.GetRuleId()
}
return ids
}
