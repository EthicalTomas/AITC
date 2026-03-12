package executor

import (
	"context"
	"fmt"
	"time"

	segkafka "github.com/segmentio/kafka-go"
)

// DLQWriter sends failed messages to the dead-letter queue topic.
type DLQWriter struct {
	writer *segkafka.Writer
	topic  string
}

// NewDLQWriter creates a writer that sends messages to the given DLQ topic.
func NewDLQWriter(brokers []string, dlqTopic string) *DLQWriter {
	return &DLQWriter{
		topic: dlqTopic,
		writer: &segkafka.Writer{
			Addr:         segkafka.TCP(brokers...),
			Topic:        dlqTopic,
			WriteTimeout: 5 * time.Second,
			MaxAttempts:  3,
		},
	}
}

// Send routes a failed raw message to the DLQ with a failure reason header.
func (d *DLQWriter) Send(ctx context.Context, originalTopic string, msg segkafka.Message, reason string) error {
	dlqMsg := segkafka.Message{
		Key:   msg.Key,
		Value: msg.Value,
		Headers: append(msg.Headers,
			segkafka.Header{Key: "dlq_reason", Value: []byte(reason)},
			segkafka.Header{Key: "original_topic", Value: []byte(originalTopic)},
		),
	}
	if err := d.writer.WriteMessages(ctx, dlqMsg); err != nil {
		return fmt.Errorf("dlq send: %w", err)
	}
	return nil
}

// Close releases DLQ writer resources.
func (d *DLQWriter) Close() error {
	return d.writer.Close()
}

