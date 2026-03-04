package kafka

import (
	"context"
	"fmt"
	"time"

	"github.com/segmentio/kafka-go"
)

// MaxMessageBytes caps Kafka message payload size (10 MB).
const MaxMessageBytes = 10 * 1024 * 1024

// Envelope is a simple wrapper for Kafka messages with metadata.
type Envelope struct {
	TenantID      string
	MessageID     string
	SchemaVersion string
	Source        string
	PayloadType   string
	Payload       []byte
	TraceID       string
	SpanID        string
	RequestID     string
}

// Producer wraps kafka-go writer.
type Producer struct {
	writer *kafka.Writer
}

// NewProducer creates a new Kafka producer.
func NewProducer(brokers []string, topic string) *Producer {
	w := &kafka.Writer{
		Addr:         kafka.TCP(brokers...),
		Topic:        topic,
		Balancer:     &kafka.LeastBytes{},
		WriteTimeout: 10 * time.Second,
		ReadTimeout:  10 * time.Second,
		MaxAttempts:  3,
		RequiredAcks: kafka.RequireOne,
	}
	return &Producer{writer: w}
}

// Publish sends an envelope to Kafka.
func (p *Producer) Publish(ctx context.Context, env Envelope) error {
	if env.TenantID == "" {
		return fmt.Errorf("kafka producer: envelope must have tenant_id")
	}
	if len(env.Payload) > MaxMessageBytes {
		return fmt.Errorf("kafka producer: message too large (%d bytes)", len(env.Payload))
	}

	msg := kafka.Message{
		Key:   []byte(env.TenantID + "/" + env.MessageID),
		Value: env.Payload,
		Headers: []kafka.Header{
			{Key: "tenant_id", Value: []byte(env.TenantID)},
			{Key: "schema_version", Value: []byte(env.SchemaVersion)},
			{Key: "payload_type", Value: []byte(env.PayloadType)},
			{Key: "trace_id", Value: []byte(env.TraceID)},
			{Key: "request_id", Value: []byte(env.RequestID)},
		},
	}

	return p.writer.WriteMessages(ctx, msg)
}

// Close closes the underlying Kafka writer.
func (p *Producer) Close() error {
	return p.writer.Close()
}
