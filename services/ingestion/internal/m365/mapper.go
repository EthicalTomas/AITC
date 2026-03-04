package m365

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	commonpb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/common"
	m365client "github.com/ethicaltomas/aitc/internal/m365"
)

const payloadTypeM365 = "aitc.events.M365UALEventV1"

// toEnvelope converts a raw M365 UALRecord to an EnvelopeV1 for Kafka.
// The raw JSON is stored verbatim in the payload field.
// SECURITY: The envelope payload must not contain auth tokens or secrets.
func toEnvelope(tenantID string, rec m365client.UALRecord, rawJSON []byte) (*commonpb.EnvelopeV1, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("m365 mapper: tenantID is required")
	}
	if rec.ID == "" {
		return nil, fmt.Errorf("m365 mapper: record ID is required")
	}

	occurredAt := rec.CreationTime
	if occurredAt.IsZero() {
		occurredAt = time.Now().UTC()
	}

	return &commonpb.EnvelopeV1{
		TenantId:      tenantID,
		MessageId:     uuid.New().String(),
		SchemaVersion: "v1",
		Source:        commonpb.Source_M365_UAL,
		OccurredAt:    timestamppb.New(occurredAt),
		IngestedAt:    timestamppb.New(time.Now().UTC()),
		PayloadType:   payloadTypeM365,
		Payload:       rawJSON,
	}, nil
}

// marshalRecord serialises a single UALRecord to JSON.
func marshalRecord(rec m365client.UALRecord) ([]byte, error) {
	data, err := json.Marshal(rec)
	if err != nil {
		return nil, fmt.Errorf("m365 mapper: marshal record %s: %w", rec.ID, err)
	}
	return data, nil
}

