// Package normalizer parses raw event payloads from Okta and M365 into
// the canonical NormalizedEventV1 protobuf format.
//
// PII note: actor_email and source_ip are PII fields. They are kept in the
// normalized event only for forensic purposes; call MinimizePII before
// writing to general-purpose storage or logs.
package normalizer

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	commonpb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/common"
	eventspb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/events"
)

// privilegedOktaRoles is the set of Okta actor types considered privileged.
var privilegedOktaRoles = map[string]bool{
	"SystemPrincipal": true,
}

// privilegedOktaActions are event types always considered admin/privileged.
var privilegedOktaActions = map[string]bool{
	"admin_change.policy.created":  true,
	"admin_change.policy.updated":  true,
	"admin_change.policy.deleted":  true,
	"admin_change.api_token.created": true,
	"admin_change.api_token.revoked": true,
}

// Normalize converts an EnvelopeV1 into a NormalizedEventV1.
// The envelope payload is decoded according to its source.
// Returns (nil, nil) for envelopes that should not produce a normalized event.
func Normalize(env *commonpb.EnvelopeV1) (*eventspb.NormalizedEventV1, error) {
	if env == nil {
		return nil, fmt.Errorf("nil envelope")
	}
	switch env.GetSource() {
	case commonpb.Source_OKTA_SYSTEM_LOG:
		okta := &eventspb.OktaSystemLogEventV1{}
		if err := proto.Unmarshal(env.GetPayload(), okta); err != nil {
			return nil, fmt.Errorf("unmarshal okta payload: %w", err)
		}
		return normalizeOkta(env, okta)
	case commonpb.Source_M365_UAL:
		m365 := &eventspb.M365UALEventV1{}
		if err := proto.Unmarshal(env.GetPayload(), m365); err != nil {
			return nil, fmt.Errorf("unmarshal m365 payload: %w", err)
		}
		return normalizeM365(env, m365)
	default:
		return nil, fmt.Errorf("unsupported source: %v", env.GetSource())
	}
}

// normalizeOkta maps an OktaSystemLogEventV1 to NormalizedEventV1.
func normalizeOkta(env *commonpb.EnvelopeV1, okta *eventspb.OktaSystemLogEventV1) (*eventspb.NormalizedEventV1, error) {
	cat, action := categoryForOktaEventType(okta.GetEventType())

	isPrivileged := privilegedOktaRoles[okta.GetActorType()] || privilegedOktaActions[action]

	occurredAt := env.GetOccurredAt()
	if ts := okta.GetPublished(); ts != nil {
		occurredAt = ts
	}

	ev := &eventspb.NormalizedEventV1{
		EventId:          uuid.New().String(),
		TenantId:         okta.GetTenantId(),
		SourceEventId:    okta.GetEventId(),
		Source:           "okta",
		Category:         cat,
		Action:           action,
		Outcome:          normalizeOktaOutcome(okta.GetOutcomeResult()),
		OccurredAt:       occurredAt,
		IngestedAt:       timestamppb.New(time.Now().UTC()),
		ActorId:          okta.GetActorId(),
		ActorEmail:       okta.GetActorAlternateId(),
		ActorDisplayName: okta.GetActorDisplayName(),
		ActorIsPrivileged: isPrivileged,
		TargetId:         okta.GetTargetId(),
		TargetType:       okta.GetTargetType(),
		SourceIp:         okta.GetClientIpAddress(),
		UserAgent:        okta.GetClientUserAgent(),
		GeoCountry:       okta.GetGeoCountry(),
		GeoCity:          okta.GetGeoCity(),
		GeoLat:           okta.GetGeoLat(),
		GeoLon:           okta.GetGeoLon(),
		AuthnMethod:      okta.GetCredentialType(),
		MfaUsed:          isMFAAction(action),
	}
	return ev, nil
}

// normalizeM365 maps an M365UALEventV1 to NormalizedEventV1.
func normalizeM365(env *commonpb.EnvelopeV1, m365 *eventspb.M365UALEventV1) (*eventspb.NormalizedEventV1, error) {
	cat, action := categoryForM365Operation(m365.GetOperation())

	isAdmin := m365.GetUserTypeCode() == "2" // 2 = Admin in M365 UAL

	occurredAt := env.GetOccurredAt()
	if ts := m365.GetCreationTime(); ts != nil {
		occurredAt = ts
	}

	ev := &eventspb.NormalizedEventV1{
		EventId:          uuid.New().String(),
		TenantId:         m365.GetTenantId(),
		SourceEventId:    m365.GetRecordId(),
		Source:           "m365",
		Category:         cat,
		Action:           action,
		Outcome:          normalizeM365Outcome(m365.GetResultStatus()),
		OccurredAt:       occurredAt,
		IngestedAt:       timestamppb.New(time.Now().UTC()),
		ActorId:          m365.GetUserId(),
		ActorEmail:       m365.GetUserId(), // M365 userId is the UPN (email)
		ActorDisplayName: m365.GetUserId(),
		ActorIsPrivileged: isAdmin,
		TargetId:         m365.GetObjectId(),
		TargetType:       m365.GetWorkload(),
		SourceIp:         m365.GetClientIp(),
		UserAgent:        m365.GetClientInfoString(),
	}
	return ev, nil
}

// normalizeOktaOutcome converts Okta outcome results to standard strings.
func normalizeOktaOutcome(result string) string {
	switch strings.ToUpper(result) {
	case "SUCCESS", "ALLOW":
		return "success"
	case "FAILURE", "DENY", "ERROR":
		return "failure"
	case "SKIPPED":
		return "skipped"
	default:
		return "unknown"
	}
}

// normalizeM365Outcome converts M365 result status to standard strings.
func normalizeM365Outcome(status string) string {
	switch strings.ToLower(status) {
	case "succeeded", "true", "success":
		return "success"
	case "failed", "false", "failure":
		return "failure"
	default:
		return "unknown"
	}
}

// isMFAAction returns true for event action names that indicate MFA usage.
func isMFAAction(action string) bool {
	return strings.HasPrefix(action, "auth.mfa.")
}

