package kafka

import (
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	commonpb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/common"
)

func TestEnvelopeV1RoundTrip(t *testing.T) {
	now := timestamppb.New(time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC))
	original := &commonpb.EnvelopeV1{
		TenantId:      "tenant-abc",
		MessageId:     "msg-001",
		SchemaVersion: "v1",
		Source:        commonpb.Source_OKTA_SYSTEM_LOG,
		OccurredAt:    now,
		IngestedAt:    now,
		PayloadType:   "aitc.events.OktaSystemLogEventV1",
		Payload:       []byte("test-payload"),
		TraceId:       "trace-xyz",
		SpanId:        "span-abc",
		RequestId:     "req-001",
	}

	data, err := proto.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	decoded, err := decodeEnvelope(data)
	if err != nil {
		t.Fatalf("decodeEnvelope: %v", err)
	}

	if decoded.GetTenantId() != original.GetTenantId() {
		t.Errorf("tenant_id: got %q, want %q", decoded.GetTenantId(), original.GetTenantId())
	}
	if decoded.GetMessageId() != original.GetMessageId() {
		t.Errorf("message_id: got %q, want %q", decoded.GetMessageId(), original.GetMessageId())
	}
	if decoded.GetPayloadType() != original.GetPayloadType() {
		t.Errorf("payload_type: got %q, want %q", decoded.GetPayloadType(), original.GetPayloadType())
	}
	if string(decoded.GetPayload()) != string(original.GetPayload()) {
		t.Errorf("payload: got %q, want %q", decoded.GetPayload(), original.GetPayload())
	}
	if decoded.GetSource() != original.GetSource() {
		t.Errorf("source: got %v, want %v", decoded.GetSource(), original.GetSource())
	}
}

func TestDecodeEnvelopeInvalidBytes(t *testing.T) {
	_, err := decodeEnvelope([]byte("not-valid-proto"))
	if err == nil {
		t.Fatal("expected error decoding invalid proto bytes, got nil")
	}
}

func TestTopicConstants(t *testing.T) {
	tests := []struct {
		topic string
		dlq   string
	}{
		{TopicRawEvents, TopicRawEventsDLQ},
		{TopicRiskSignals, TopicRiskSignalsDLQ},
		{TopicActionRecommendations, TopicActionRecommendationsDLQ},
		{TopicActionRequests, TopicActionRequestsDLQ},
	}
	for _, tt := range tests {
		if tt.topic == "" {
			t.Errorf("topic constant must not be empty")
		}
		want := tt.topic + DLQSuffix
		if tt.dlq != want {
			t.Errorf("DLQ for %q: got %q, want %q", tt.topic, tt.dlq, want)
		}
	}
}

func TestProducerRejectsMissingTenantID(t *testing.T) {
	// NewProducer requires brokers; we only test validation, so a fake address is fine.
	// We do not actually connect — the error happens before any write.
	p := NewProducer([]string{"localhost:9092"}, TopicRawEvents)
	defer p.Close() //nolint:errcheck

	err := p.Publish(t.Context(), &commonpb.EnvelopeV1{})
	if err == nil {
		t.Fatal("expected error for empty tenant_id, got nil")
	}
}

func TestProducerRejectsTooLargePayload(t *testing.T) {
	p := NewProducer([]string{"localhost:9092"}, TopicRawEvents)
	defer p.Close() //nolint:errcheck

	bigPayload := make([]byte, MaxMessageBytes+1)
	env := &commonpb.EnvelopeV1{
		TenantId: "tenant-x",
		Payload:  bigPayload,
	}

	// Marshal first; the size check is on the serialized envelope bytes.
	// The proto envelope itself may be smaller due to encoding, so we build an
	// envelope large enough that marshaling also exceeds the limit.
	data, _ := proto.Marshal(env)
	if len(data) <= MaxMessageBytes {
		// If the marshaled form is not large enough, skip — we only test the guard.
		t.Skip("marshaled size did not exceed limit; skipping oversized payload test")
	}

	err := p.Publish(t.Context(), env)
	if err == nil {
		t.Fatal("expected error for oversized payload, got nil")
	}
}
