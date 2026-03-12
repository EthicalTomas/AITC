package normalizer_test

import (
"testing"
"time"

"google.golang.org/protobuf/proto"
"google.golang.org/protobuf/types/known/timestamppb"

commonpb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/common"
eventspb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/events"
"github.com/ethicaltomas/aitc/services/pipeline/internal/normalizer"
)

func TestNormalizeOkta_LoginSuccess(t *testing.T) {
okta := &eventspb.OktaSystemLogEventV1{
EventId:          "evt-001",
TenantId:         "tenant-abc",
EventType:        "user.session.start",
ActorId:          "actor-123",
ActorAlternateId: "user@example.com",
ActorDisplayName: "Test User",
OutcomeResult:    "SUCCESS",
ClientIpAddress:  "203.0.113.1",
GeoCity:          "New York",
GeoCountry:       "US",
GeoLat:           40.7128,
GeoLon:           -74.0060,
Published:        timestamppb.New(time.Now().UTC()),
}

payload, err := proto.Marshal(okta)
if err != nil {
t.Fatalf("marshal okta: %v", err)
}

env := &commonpb.EnvelopeV1{
TenantId:  "tenant-abc",
MessageId: "msg-001",
Source:    commonpb.Source_OKTA_SYSTEM_LOG,
Payload:   payload,
}

ev, err := normalizer.Normalize(env)
if err != nil {
t.Fatalf("normalize: %v", err)
}
if ev == nil {
t.Fatal("expected non-nil event")
}

if ev.GetSource() != "okta" {
t.Errorf("source = %q, want %q", ev.GetSource(), "okta")
}
if ev.GetAction() != "auth.login.success" {
t.Errorf("action = %q, want %q", ev.GetAction(), "auth.login.success")
}
if ev.GetOutcome() != "success" {
t.Errorf("outcome = %q, want %q", ev.GetOutcome(), "success")
}
if ev.GetCategory() != eventspb.EventCategory_AUTHENTICATION {
t.Errorf("category = %v, want AUTHENTICATION", ev.GetCategory())
}
if ev.GetTenantId() != "tenant-abc" {
t.Errorf("tenant_id = %q, want %q", ev.GetTenantId(), "tenant-abc")
}
if ev.GetSourceEventId() != "evt-001" {
t.Errorf("source_event_id = %q, want %q", ev.GetSourceEventId(), "evt-001")
}
if ev.GetActorEmail() != "user@example.com" {
t.Errorf("actor_email = %q, want %q", ev.GetActorEmail(), "user@example.com")
}
if ev.GetGeoLat() != 40.7128 {
t.Errorf("geo_lat = %f, want %f", ev.GetGeoLat(), 40.7128)
}
}

func TestNormalizeM365_FileDownload(t *testing.T) {
m365 := &eventspb.M365UALEventV1{
RecordId:     "rec-001",
TenantId:     "tenant-xyz",
Operation:    "FileDownloaded",
UserId:       "user@corp.com",
ResultStatus: "Succeeded",
ObjectId:     "/sites/shared/doc.xlsx",
Workload:     "SharePoint",
ClientIp:     "198.51.100.42",
CreationTime: timestamppb.New(time.Now().UTC()),
}

payload, err := proto.Marshal(m365)
if err != nil {
t.Fatalf("marshal m365: %v", err)
}

env := &commonpb.EnvelopeV1{
TenantId:  "tenant-xyz",
MessageId: "msg-002",
Source:    commonpb.Source_M365_UAL,
Payload:   payload,
}

ev, err := normalizer.Normalize(env)
if err != nil {
t.Fatalf("normalize: %v", err)
}
if ev == nil {
t.Fatal("expected non-nil event")
}

if ev.GetSource() != "m365" {
t.Errorf("source = %q, want %q", ev.GetSource(), "m365")
}
if ev.GetAction() != "file_access.downloaded" {
t.Errorf("action = %q, want %q", ev.GetAction(), "file_access.downloaded")
}
if ev.GetCategory() != eventspb.EventCategory_FILE {
t.Errorf("category = %v, want FILE", ev.GetCategory())
}
if ev.GetOutcome() != "success" {
t.Errorf("outcome = %q, want %q", ev.GetOutcome(), "success")
}
}

func TestNormalizeUnsupportedSource(t *testing.T) {
env := &commonpb.EnvelopeV1{
TenantId: "tenant-abc",
Source:   commonpb.Source_INTERNAL,
Payload:  []byte("{}"),
}
ev, err := normalizer.Normalize(env)
if err == nil {
t.Error("expected error for unsupported source")
}
if ev != nil {
t.Error("expected nil event for unsupported source")
}
}

// ── PII Minimization ─────────────────────────────────────────────────────────

func TestMinimizePII_MasksIPv4(t *testing.T) {
ev := &eventspb.NormalizedEventV1{
SourceIp:   "203.0.113.45",
ActorEmail: "alice@example.com",
}
out := normalizer.MinimizePII(ev)

if out.GetSourceIp() != "203.0.113.0" {
t.Errorf("source_ip = %q, want %q", out.GetSourceIp(), "203.0.113.0")
}
if out.GetActorEmail() == ev.GetActorEmail() {
t.Error("actor_email should be redacted")
}
// Ensure domain is preserved
if out.GetActorEmail() == "" {
t.Error("actor_email should not be empty after masking")
}
}

func TestMinimizePII_PreservesOriginal(t *testing.T) {
ev := &eventspb.NormalizedEventV1{
SourceIp:   "10.0.0.1",
ActorEmail: "bob@corp.io",
}
out := normalizer.MinimizePII(ev)

// Original must not be modified (shallow copy semantics).
if ev.GetSourceIp() != "10.0.0.1" {
t.Error("original event source_ip should not be modified")
}
if out == ev {
t.Error("MinimizePII should return a different pointer")
}
}

func TestMinimizePII_NilSafe(t *testing.T) {
out := normalizer.MinimizePII(nil)
if out != nil {
t.Error("expected nil output for nil input")
}
}
