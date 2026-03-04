package kafka

import (
	"context"
	"fmt"
	"time"

	segkafka "github.com/segmentio/kafka-go"
)

// DLQSuffix is the dead-letter queue topic suffix.
const DLQSuffix = ".dlq"

// Message is the deserialized Kafka message with envelope metadata.
type Message struct {
	TenantID    string
	MessageID   string
	PayloadType string
	TraceID     string
	RequestID   string
	Payload     []byte
	RawMsg      segkafka.Message
}

// Handler processes a Kafka message. Return error to trigger DLQ routing.
// Handlers MUST be idempotent.
type Handler func(ctx context.Context, msg Message) error

// Consumer wraps kafka-go reader with retry and DLQ support.
type Consumer struct {
	reader    *segkafka.Reader
	dlqWriter *segkafka.Writer
	topic     string
}

// NewConsumer creates a new Kafka consumer with DLQ support.
func NewConsumer(brokers []string, topic, groupID string) *Consumer {
	reader := segkafka.NewReader(segkafka.ReaderConfig{
		Brokers:        brokers,
		Topic:          topic,
		GroupID:        groupID,
		MinBytes:       1,
		MaxBytes:       MaxMessageBytes,
		MaxWait:        500 * time.Millisecond,
		CommitInterval: time.Second,
		StartOffset:    segkafka.FirstOffset,
	})

	dlqWriter := &segkafka.Writer{
		Addr:         segkafka.TCP(brokers...),
		Topic:        topic + DLQSuffix,
		WriteTimeout: 5 * time.Second,
		MaxAttempts:  3,
	}

	return &Consumer{
		reader:    reader,
		dlqWriter: dlqWriter,
		topic:     topic,
	}
}

// Consume reads messages and calls handler. Sends to DLQ on handler error.
// Handlers must be idempotent (message may be delivered more than once).
func (c *Consumer) Consume(ctx context.Context, handler Handler) error {
	for {
		rawMsg, err := c.reader.FetchMessage(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil // graceful shutdown
			}
			return fmt.Errorf("kafka consumer fetch: %w", err)
		}

		msg := parseMessage(rawMsg)

		if err := handler(ctx, msg); err != nil {
			_ = c.sendToDLQ(ctx, rawMsg, err.Error())
		}

		if err := c.reader.CommitMessages(ctx, rawMsg); err != nil {
			return fmt.Errorf("kafka consumer commit: %w", err)
		}
	}
}

func parseMessage(raw segkafka.Message) Message {
	msg := Message{
		Payload: raw.Value,
		RawMsg:  raw,
	}
	for _, h := range raw.Headers {
		switch h.Key {
		case "tenant_id":
			msg.TenantID = string(h.Value)
		case "payload_type":
			msg.PayloadType = string(h.Value)
		case "trace_id":
			msg.TraceID = string(h.Value)
		case "request_id":
			msg.RequestID = string(h.Value)
		}
	}
	return msg
}

func (c *Consumer) sendToDLQ(ctx context.Context, msg segkafka.Message, reason string) error {
	dlqMsg := segkafka.Message{
		Key:   msg.Key,
		Value: msg.Value,
		Headers: append(msg.Headers,
			segkafka.Header{Key: "dlq_reason", Value: []byte(reason)},
			segkafka.Header{Key: "original_topic", Value: []byte(c.topic)},
		),
	}
	return c.dlqWriter.WriteMessages(ctx, dlqMsg)
}

// Close closes the reader and DLQ writer.
func (c *Consumer) Close() error {
	if err := c.reader.Close(); err != nil {
		return err
	}
	return c.dlqWriter.Close()
}
