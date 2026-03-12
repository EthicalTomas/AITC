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

// ── taxonomy tests ────────────────────────────────────────────────────────────

func TestOktaEventTypeToCategory(t *testing.T) {
tests := []struct {
eventType string
want      eventspb.EventCategory
}{
{"user.session.start", eventspb.EventCategory_AUTHENTICATION},
{"user.session.end", eventspb.EventCategory_AUTHENTICATION},
{"user.authentication.auth_via_mfa", eventspb.EventCategory_AUTHENTICATION},
{"user.mfa.okta_verify.deny", eventspb.EventCategory_MFA},
{"user.mfa.factor.activate", eventspb.EventCategory_MFA},
{"user.account.update_password", eventspb.EventCategory_AUTHENTICATION},
{"user.lifecycle.create", eventspb.EventCategory_ADMIN},
{"user.lifecycle.deactivate", eventspb.EventCategory_ADMIN},
{"group.user_membership.add", eventspb.EventCategory_ADMIN},
{"system.api_token.create", eventspb.EventCategory_ADMIN},
{"policy.lifecycle.create", eventspb.EventCategory_POLICY_CHANGE},
{"unknown.event.type", eventspb.EventCategory_OTHER},
}
for _, tt := range tests {
t.Run(tt.eventType, func(t *testing.T) {
got := normalizer.OktaEventTypeToCategory(tt.eventType)
if got != tt.want {
t.Errorf("OktaEventTypeToCategory(%q) = %v, want %v", tt.eventType, got, tt.want)
}
})
}
}

func TestM365OperationToCategory(t *testing.T) {
tests := []struct {
op   string
want eventspb.EventCategory
}{
{"UserLoggedIn", eventspb.EventCategory_AUTHENTICATION},
{"UserLoginFailed", eventspb.EventCategory_AUTHENTICATION},
{"MailboxLogin", eventspb.EventCategory_AUTHENTICATION},
{"New-InboxRule", eventspb.EventCategory_EMAIL},
{"Set-InboxRule", eventspb.EventCategory_EMAIL},
{"FileDownloaded", eventspb.EventCategory_FILE},
{"FileUploaded", eventspb.EventCategory_FILE},
{"Add member to role.", eventspb.EventCategory_ADMIN},
{"Add delegated permission grant.", eventspb.EventCategory_OAUTH},
{"Consent to application.", eventspb.EventCategory_OAUTH},
{"UnknownOperation", eventspb.EventCategory_OTHER},
}
for _, tt := range tests {
t.Run(tt.op, func(t *testing.T) {
got := normalizer.M365OperationToCategory(tt.op)
if got != tt.want {
t.Errorf("M365OperationToCategory(%q) = %v, want %v", tt.op, got, tt.want)
}
})
}
}

func TestOktaOutcomeToNormalized(t *testing.T) {
tests := []struct{ input, want string }{
{"SUCCESS", "success"},
{"ALLOW", "success"},
{"FAILURE", "failure"},
{"DENY", "failure"},
{"SKIPPED", "unknown"},
{"", "unknown"},
}
for _, tt := range tests {
got := normalizer.OktaOutcomeToNormalized(tt.input)
if got != tt.want {
t.Errorf("OktaOutcomeToNormalized(%q) = %q, want %q", tt.input, got, tt.want)
}
}
}

func TestM365ResultToNormalized(t *testing.T) {
tests := []struct{ input, want string }{
{"Succeeded", "success"},
{"True", "success"},
{"Failed", "failure"},
{"False", "failure"},
{"", "unknown"},
}
for _, tt := range tests {
got := normalizer.M365ResultToNormalized(tt.input)
if got != tt.want {
t.Errorf("M365ResultToNormalized(%q) = %q, want %q", tt.input, got, tt.want)
}
}
}

func TestIsPrivilegedOktaActor(t *testing.T) {
if !normalizer.IsPrivilegedOktaActor("SystemPrincipal") {
t.Error("SystemPrincipal should be privileged")
}
if normalizer.IsPrivilegedOktaActor("User") {
t.Error("User should not be privileged")
}
}

func TestIsPrivilegedM365User(t *testing.T) {
privileged := []string{"2", "3", "4", "5"}
for _, code := range privileged {
if !normalizer.IsPrivilegedM365User(code) {
t.Errorf("user_type_code %q should be privileged", code)
}
}
if normalizer.IsPrivilegedM365User("0") {
t.Error("user_type_code 0 (Regular) should not be privileged")
}
}

// ── normalize tests ───────────────────────────────────────────────────────────

func buildOktaEnvelope(t *testing.T, tenantID string, ev *eventspb.OktaSystemLogEventV1) *commonpb.EnvelopeV1 {
t.Helper()
payload, err := proto.Marshal(ev)
if err != nil {
t.Fatalf("marshal okta event: %v", err)
}
return &commonpb.EnvelopeV1{
TenantId:    tenantID,
MessageId:   "msg-001",
PayloadType: "aitc.events.OktaSystemLogEventV1",
Payload:     payload,
}
}

func buildM365Envelope(t *testing.T, tenantID string, ev *eventspb.M365UALEventV1) *commonpb.EnvelopeV1 {
t.Helper()
payload, err := proto.Marshal(ev)
if err != nil {
t.Fatalf("marshal m365 event: %v", err)
}
return &commonpb.EnvelopeV1{
TenantId:    tenantID,
MessageId:   "msg-002",
PayloadType: "aitc.events.M365UALEventV1",
Payload:     payload,
}
}

func TestNormalize_Okta_SessionStart(t *testing.T) {
raw := &eventspb.OktaSystemLogEventV1{
EventId:          "okta-evt-001",
TenantId:         "tenant-acme",
EventType:        "user.session.start",
Published:        timestamppb.New(time.Now()),
ActorId:          "00u1abc",
ActorAlternateId: "alice@acme.com",
ActorType:        "User",
OutcomeResult:    "SUCCESS",
ClientIpAddress:  "203.0.113.1",
GeoCountry:       "US",
GeoCity:          "New York",
GeoLat:           40.7128,
GeoLon:           -74.0060,
}
env := buildOktaEnvelope(t, "tenant-acme", raw)

ev, err := normalizer.Normalize(env)
if err != nil {
t.Fatalf("Normalize: %v", err)
}

if ev.GetTenantId() != "tenant-acme" {
t.Errorf("TenantId: got %q, want %q", ev.GetTenantId(), "tenant-acme")
}
if ev.GetSource() != "okta" {
t.Errorf("Source: got %q, want okta", ev.GetSource())
}
if ev.GetCategory() != eventspb.EventCategory_AUTHENTICATION {
t.Errorf("Category: got %v, want AUTHENTICATION", ev.GetCategory())
}
if ev.GetAction() != "auth.login.success" {
t.Errorf("Action: got %q, want auth.login.success", ev.GetAction())
}
if ev.GetOutcome() != "success" {
t.Errorf("Outcome: got %q, want success", ev.GetOutcome())
}
if ev.GetActorEmail() != "alice@acme.com" {
t.Errorf("ActorEmail: got %q, want alice@acme.com", ev.GetActorEmail())
}
if ev.GetSourceIp() != "203.0.113.1" {
t.Errorf("SourceIp: got %q, want 203.0.113.1", ev.GetSourceIp())
}
if ev.GetGeoLat() != 40.7128 {
t.Errorf("GeoLat: got %f, want 40.7128", ev.GetGeoLat())
}
if ev.GetEventId() == "" {
t.Error("EventId must be populated (UUID)")
}
}

func TestNormalize_Okta_MFADeny(t *testing.T) {
raw := &eventspb.OktaSystemLogEventV1{
EventId:       "okta-mfa-001",
EventType:     "user.mfa.okta_verify.deny",
OutcomeResult: "DENY",
ActorType:     "SystemPrincipal",
}
env := buildOktaEnvelope(t, "tenant-x", raw)
ev, err := normalizer.Normalize(env)
if err != nil {
t.Fatalf("Normalize: %v", err)
}
if ev.GetCategory() != eventspb.EventCategory_MFA {
t.Errorf("Category: got %v, want MFA", ev.GetCategory())
}
if ev.GetAction() != "auth.mfa.push_denied" {
t.Errorf("Action: got %q, want auth.mfa.push_denied", ev.GetAction())
}
if !ev.GetActorIsPrivileged() {
t.Error("ActorIsPrivileged: expected true for SystemPrincipal")
}
}

func TestNormalize_M365_FileDownload(t *testing.T) {
raw := &eventspb.M365UALEventV1{
RecordId:     "m365-rec-001",
TenantId:     "tenant-beta",
Operation:    "FileDownloaded",
CreationTime: timestamppb.New(time.Now()),
UserId:       "bob@beta.onmicrosoft.com",
UserTypeCode: "0",
ClientIp:     "198.51.100.5",
ResultStatus: "Succeeded",
}
env := buildM365Envelope(t, "tenant-beta", raw)
ev, err := normalizer.Normalize(env)
if err != nil {
t.Fatalf("Normalize: %v", err)
}
if ev.GetSource() != "m365" {
t.Errorf("Source: got %q, want m365", ev.GetSource())
}
if ev.GetCategory() != eventspb.EventCategory_FILE {
t.Errorf("Category: got %v, want FILE", ev.GetCategory())
}
if ev.GetAction() != "file.downloaded" {
t.Errorf("Action: got %q, want file.downloaded", ev.GetAction())
}
if ev.GetActorIsPrivileged() {
t.Error("ActorIsPrivileged: expected false for user_type_code=0")
}
}

func TestNormalize_UnsupportedPayloadType(t *testing.T) {
env := &commonpb.EnvelopeV1{
TenantId:    "tenant-x",
PayloadType: "aitc.events.UnknownEventV99",
Payload:     []byte("garbage"),
}
_, err := normalizer.Normalize(env)
if err == nil {
t.Error("expected error for unsupported payload type")
}
}

func TestNormalize_CorruptPayload(t *testing.T) {
env := &commonpb.EnvelopeV1{
TenantId:    "tenant-x",
PayloadType: "aitc.events.OktaSystemLogEventV1",
Payload:     []byte("not valid protobuf"),
}
_, err := normalizer.Normalize(env)
if err == nil {
t.Error("expected error for corrupt protobuf payload")
}
}

func TestNormalize_NilEnvelope(t *testing.T) {
_, err := normalizer.Normalize(nil)
if err == nil {
t.Error("expected error for nil envelope")
}
}

// ── PII minimization tests ────────────────────────────────────────────────────

func TestMinimizePII_RedactsEmailAndIP(t *testing.T) {
ev := &eventspb.NormalizedEventV1{
TenantId:   "tenant-x",
ActorEmail: "alice@example.com",
SourceIp:   "10.0.0.1",
GeoCity:    "Seattle",
GeoCountry: "US",
}

redacted := normalizer.MinimizePII(ev)

if redacted.GetActorEmail() == "alice@example.com" {
t.Error("ActorEmail should be redacted")
}
if redacted.GetSourceIp() == "10.0.0.1" {
t.Error("SourceIp should be redacted")
}
if redacted.GetGeoCity() != "" {
t.Errorf("GeoCity should be cleared, got %q", redacted.GetGeoCity())
}
if redacted.GetGeoCountry() != "US" {
t.Errorf("GeoCountry should be preserved, got %q", redacted.GetGeoCountry())
}
// Original should not be modified.
if ev.GetActorEmail() != "alice@example.com" {
t.Error("original event ActorEmail should not be modified")
}
}

func TestMinimizePII_NilSafe(t *testing.T) {
if got := normalizer.MinimizePII(nil); got != nil {
t.Errorf("MinimizePII(nil) = %v, want nil", got)
}
}
