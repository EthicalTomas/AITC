package kafka

// Topic name constants for all Kafka topics used in AITC.
// DLQ topics follow the pattern: {topic}.dlq (see DLQSuffix in consumer.go).
const (
	// TopicRawEvents receives raw, unprocessed events from ingestion pollers.
	TopicRawEvents = "raw-events"

	// TopicRiskSignals carries risk signal messages emitted by the pipeline CAS engine.
	TopicRiskSignals = "risk-signals"

	// TopicActionRecommendations carries action recommendations from the control plane.
	TopicActionRecommendations = "action-recommendations"

	// TopicActionRequests carries validated action requests destined for enforcement services.
	TopicActionRequests = "action-requests"

	// DLQ topic names derived from primary topics using DLQSuffix.
	TopicRawEventsDLQ            = TopicRawEvents + DLQSuffix
	TopicRiskSignalsDLQ          = TopicRiskSignals + DLQSuffix
	TopicActionRecommendationsDLQ = TopicActionRecommendations + DLQSuffix
	TopicActionRequestsDLQ       = TopicActionRequests + DLQSuffix
)
