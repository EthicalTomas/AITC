package kafka

import (
	"context"
	"fmt"
	"time"

	segkafka "github.com/segmentio/kafka-go"
	"google.golang.org/protobuf/proto"

	commonpb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/common"
)

// MaxMessageBytes caps Kafka message payload size (10 MB).
const MaxMessageBytes = 10 * 1024 * 1024

// Producer wraps kafka-go writer and encodes messages as EnvelopeV1 protobuf.
type Producer struct {
	writer *segkafka.Writer
}

// NewProducer creates a new Kafka producer with retries and write timeout.
func NewProducer(brokers []string, topic string) *Producer {
	w := &segkafka.Writer{
		Addr:         segkafka.TCP(brokers...),
		Topic:        topic,
		Balancer:     &segkafka.LeastBytes{},
		WriteTimeout: 10 * time.Second,
		ReadTimeout:  10 * time.Second,
		MaxAttempts:  5,
		RequiredAcks: segkafka.RequireOne,
	}
	return &Producer{writer: w}
}

// Publish serializes env as an EnvelopeV1 protobuf and writes it to Kafka.
// Returns an error if tenant_id is missing, the payload exceeds MaxMessageBytes,
// serialization fails, or the write times out / is cancelled.
func (p *Producer) Publish(ctx context.Context, env *commonpb.EnvelopeV1) error {
	if env.GetTenantId() == "" {
		return fmt.Errorf("kafka producer: envelope must have tenant_id")
	}

	data, err := proto.Marshal(env)
	if err != nil {
		return fmt.Errorf("kafka producer: marshal envelope: %w", err)
	}
	if len(data) > MaxMessageBytes {
		return fmt.Errorf("kafka producer: message too large (%d bytes)", len(data))
	}

	msg := segkafka.Message{
		Key:   []byte(env.GetTenantId() + "/" + env.GetMessageId()),
		Value: data,
		Headers: []segkafka.Header{
			{Key: "tenant_id", Value: []byte(env.GetTenantId())},
			{Key: "schema_version", Value: []byte(env.GetSchemaVersion())},
			{Key: "payload_type", Value: []byte(env.GetPayloadType())},
			{Key: "trace_id", Value: []byte(env.GetTraceId())},
			{Key: "span_id", Value: []byte(env.GetSpanId())},
			{Key: "request_id", Value: []byte(env.GetRequestId())},
		},
	}

	return p.writer.WriteMessages(ctx, msg)
}

// Close closes the underlying Kafka writer.
func (p *Producer) Close() error {
	return p.writer.Close()
}
