package consumers

import (
	"context"

	"github.com/ethicaltomas/aitc/internal/stream/kafka"
	commonpb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/common"
)

// KafkaConsumer runs a consumer group loop for a given topic using the
// internal/stream/kafka package. Unprocessable messages are routed to the
// corresponding DLQ topic ({topic}.dlq).
type KafkaConsumer struct {
	consumer *kafka.Consumer
}

// NewKafkaConsumer creates a consumer for the given topic and group ID.
func NewKafkaConsumer(brokers []string, topic, groupID string) *KafkaConsumer {
	return &KafkaConsumer{
		consumer: kafka.NewConsumer(brokers, topic, groupID),
	}
}

// Run starts the consumer loop and calls handler for each decoded EnvelopeV1.
// It returns nil when ctx is cancelled (graceful shutdown).
func (c *KafkaConsumer) Run(ctx context.Context, handler func(ctx context.Context, env *commonpb.EnvelopeV1) error) error {
	return c.consumer.Consume(ctx, kafka.Handler(handler))
}

// Close releases consumer resources.
func (c *KafkaConsumer) Close() error {
	return c.consumer.Close()
}
