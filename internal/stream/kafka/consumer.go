package kafka

import (
	"context"
	"fmt"
	"time"

	segkafka "github.com/segmentio/kafka-go"
	"google.golang.org/protobuf/proto"

	commonpb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/common"
)

// DLQSuffix is the dead-letter queue topic suffix.
const DLQSuffix = ".dlq"

// Handler processes a decoded EnvelopeV1 Kafka message. Return error to trigger DLQ routing.
// Handlers MUST be idempotent (messages may be delivered more than once).
type Handler func(ctx context.Context, env *commonpb.EnvelopeV1) error

// Consumer wraps kafka-go reader with retry and DLQ support.
type Consumer struct {
	reader    *segkafka.Reader
	dlqWriter *segkafka.Writer
	topic     string
}

// NewConsumer creates a new Kafka consumer group runner with DLQ support.
// The DLQ topic is derived as: {topic}.dlq.
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

// Consume reads messages, decodes them as EnvelopeV1 protobuf, and calls handler.
// On handler error the raw message is forwarded to the DLQ topic ({topic}.dlq).
// Returns nil on context cancellation (graceful shutdown).
func (c *Consumer) Consume(ctx context.Context, handler Handler) error {
	for {
		rawMsg, err := c.reader.FetchMessage(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil // graceful shutdown
			}
			return fmt.Errorf("kafka consumer fetch: %w", err)
		}

		env, decodeErr := decodeEnvelope(rawMsg.Value)
		if decodeErr != nil {
			_ = c.sendToDLQ(ctx, rawMsg, fmt.Sprintf("decode error: %s", decodeErr))
		} else if handlerErr := handler(ctx, env); handlerErr != nil {
			_ = c.sendToDLQ(ctx, rawMsg, handlerErr.Error())
		}

		if err := c.reader.CommitMessages(ctx, rawMsg); err != nil {
			return fmt.Errorf("kafka consumer commit: %w", err)
		}
	}
}

// decodeEnvelope unmarshals raw bytes into an EnvelopeV1 protobuf message.
func decodeEnvelope(data []byte) (*commonpb.EnvelopeV1, error) {
	env := &commonpb.EnvelopeV1{}
	if err := proto.Unmarshal(data, env); err != nil {
		return nil, fmt.Errorf("unmarshal EnvelopeV1: %w", err)
	}
	return env, nil
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
