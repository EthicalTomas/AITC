// Package normalizer converts raw event envelopes into canonical NormalizedEventV1.
// SECURITY: PII fields (email, IP) pass through here; see pii_minimize.go before logging.
package normalizer

import (
"fmt"
"time"

"github.com/google/uuid"
"google.golang.org/protobuf/proto"
"google.golang.org/protobuf/types/known/timestamppb"

commonpb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/common"
eventspb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/events"
)

// Normalize decodes the payload from an EnvelopeV1 and produces a NormalizedEventV1.
// Returns error for unsupported payload types or malformed payloads.
func Normalize(env *commonpb.EnvelopeV1) (*eventspb.NormalizedEventV1, error) {
if env == nil {
return nil, fmt.Errorf("normalizer: nil envelope")
}
switch env.GetPayloadType() {
case "aitc.events.OktaSystemLogEventV1":
return normalizeOkta(env)
case "aitc.events.M365UALEventV1":
return normalizeM365(env)
default:
return nil, fmt.Errorf("normalizer: unsupported payload_type %q", env.GetPayloadType())
}
}

func normalizeOkta(env *commonpb.EnvelopeV1) (*eventspb.NormalizedEventV1, error) {
var raw eventspb.OktaSystemLogEventV1
if err := proto.Unmarshal(env.GetPayload(), &raw); err != nil {
return nil, fmt.Errorf("normalizer: unmarshal okta event: %w", err)
}

category := OktaEventTypeToCategory(raw.GetEventType())
action := OktaEventTypeToAction(raw.GetEventType())
outcome := OktaOutcomeToNormalized(raw.GetOutcomeResult())
privileged := IsPrivilegedOktaActor(raw.GetActorType())

occurredAt := raw.GetPublished()
if occurredAt == nil {
occurredAt = timestamppb.New(time.Now().UTC())
}

ev := &eventspb.NormalizedEventV1{
EventId:           uuid.NewString(),
TenantId:          env.GetTenantId(),
SourceEventId:     raw.GetEventId(),
Source:            "okta",
Category:          category,
Action:            action,
Outcome:           outcome,
OccurredAt:        occurredAt,
IngestedAt:        timestamppb.New(time.Now().UTC()),
ActorId:           raw.GetActorId(),
ActorEmail:        raw.GetActorAlternateId(), // PII: email/login
ActorDisplayName:  raw.GetActorDisplayName(),
ActorIsPrivileged: privileged,
TargetId:          raw.GetTargetId(),
TargetType:        raw.GetTargetType(),
SourceIp:          raw.GetClientIpAddress(), // PII
UserAgent:         raw.GetClientUserAgent(),
GeoCountry:        raw.GetGeoCountry(),
GeoCity:           raw.GetGeoCity(),
GeoLat:            raw.GetGeoLat(),
GeoLon:            raw.GetGeoLon(),
AuthnMethod:       raw.GetCredentialType(),
}
return ev, nil
}

func normalizeM365(env *commonpb.EnvelopeV1) (*eventspb.NormalizedEventV1, error) {
var raw eventspb.M365UALEventV1
if err := proto.Unmarshal(env.GetPayload(), &raw); err != nil {
return nil, fmt.Errorf("normalizer: unmarshal m365 event: %w", err)
}

category := M365OperationToCategory(raw.GetOperation())
action := M365OperationToAction(raw.GetOperation())
outcome := M365ResultToNormalized(raw.GetResultStatus())
privileged := IsPrivilegedM365User(raw.GetUserTypeCode())

occurredAt := raw.GetCreationTime()
if occurredAt == nil {
occurredAt = timestamppb.New(time.Now().UTC())
}

ev := &eventspb.NormalizedEventV1{
EventId:           uuid.NewString(),
TenantId:          env.GetTenantId(),
SourceEventId:     raw.GetRecordId(),
Source:            "m365",
Category:          category,
Action:            action,
Outcome:           outcome,
OccurredAt:        occurredAt,
IngestedAt:        timestamppb.New(time.Now().UTC()),
ActorId:           raw.GetUserId(), // PII: UPN
ActorEmail:        raw.GetUserId(), // UPN serves as email in M365
ActorIsPrivileged: privileged,
TargetId:          raw.GetObjectId(),
SourceIp:          raw.GetClientIp(), // PII
}
return ev, nil
}
