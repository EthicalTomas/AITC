package okta

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	commonpb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/common"
	oktaclient "github.com/ethicaltomas/aitc/internal/okta"
)

const payloadTypeOkta = "aitc.events.OktaSystemLogEventV1"

// toEnvelope converts a raw Okta SystemLogEvent to an EnvelopeV1 for Kafka.
// The payload field contains the raw JSON bytes of the event so downstream
// consumers always have access to the original, unmodified record.
// SECURITY: The envelope payload must not contain auth tokens or secrets.
func toEnvelope(tenantID string, ev oktaclient.SystemLogEvent, rawJSON []byte) (*commonpb.EnvelopeV1, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("okta mapper: tenantID is required")
	}
	if ev.UUID == "" {
		return nil, fmt.Errorf("okta mapper: event UUID is required")
	}

	occurredAt := ev.Published
	if occurredAt.IsZero() {
		occurredAt = time.Now().UTC()
	}

	return &commonpb.EnvelopeV1{
		TenantId:      tenantID,
		MessageId:     uuid.New().String(),
		SchemaVersion: "v1",
		Source:        commonpb.Source_OKTA_SYSTEM_LOG,
		OccurredAt:    timestamppb.New(occurredAt),
		IngestedAt:    timestamppb.New(time.Now().UTC()),
		PayloadType:   payloadTypeOkta,
		Payload:       rawJSON,
	}, nil
}

// marshalEvent serialises a single SystemLogEvent to JSON.
// The result is stored as the EnvelopeV1 payload and archived to S3 verbatim.
func marshalEvent(ev oktaclient.SystemLogEvent) ([]byte, error) {
	data, err := json.Marshal(ev)
	if err != nil {
		return nil, fmt.Errorf("okta mapper: marshal event %s: %w", ev.UUID, err)
	}
	return data, nil
}

