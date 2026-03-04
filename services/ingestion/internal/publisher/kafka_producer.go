package publisher

import (
	"context"

	"github.com/ethicaltomas/aitc/internal/stream/kafka"
	commonpb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/common"
)

// KafkaPublisher publishes raw ingestion events to the Kafka raw-events topic.
type KafkaPublisher struct {
	producer *kafka.Producer
}

// NewKafkaPublisher creates a KafkaPublisher that writes to the raw-events topic.
func NewKafkaPublisher(brokers []string) *KafkaPublisher {
	return &KafkaPublisher{
		producer: kafka.NewProducer(brokers, kafka.TopicRawEvents),
	}
}

// Publish sends an EnvelopeV1 to the raw-events Kafka topic.
func (p *KafkaPublisher) Publish(ctx context.Context, env *commonpb.EnvelopeV1) error {
	return p.producer.Publish(ctx, env)
}

// Close releases producer resources.
func (p *KafkaPublisher) Close() error {
	return p.producer.Close()
}
