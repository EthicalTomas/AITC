// Package recommendations generates ResponseActionV1 recommendations from RiskSignalV1 inputs.
// In learning mode, actions are emitted as RECOMMENDED (observe-only).
// After learning mode with autopilot enabled, actions may be AUTOPILOT_EXECUTED.
// Manual execution always goes through the analyst workflow.
package recommendations

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	casespb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/cases"
	commonpb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/common"
	riskpb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/risk"
	"github.com/ethicaltomas/aitc/internal/idempotency"
	"github.com/ethicaltomas/aitc/internal/stream/kafka"
	"github.com/ethicaltomas/aitc/services/controlplane/internal/autonomy"
	"github.com/ethicaltomas/aitc/services/controlplane/internal/policy"
)

// Generator produces ResponseActionV1 recommendations for a given risk signal.
type Generator struct {
	validator    *policy.Validator
	recProducer  *kafka.Producer // action-recommendations topic
	reqProducer  *kafka.Producer // action-requests topic (manual/autopilot only)
	stateRepo    *autonomy.TenantStateRepo
	circBreaker  *autonomy.CircuitBreaker
	logger       *zap.Logger
}

// NewGenerator creates a recommendation generator.
func NewGenerator(
	validator *policy.Validator,
	recProducer *kafka.Producer,
	reqProducer *kafka.Producer,
	stateRepo *autonomy.TenantStateRepo,
	cb *autonomy.CircuitBreaker,
	logger *zap.Logger,
) *Generator {
	return &Generator{
		validator:   validator,
		recProducer: recProducer,
		reqProducer: reqProducer,
		stateRepo:   stateRepo,
		circBreaker: cb,
		logger:      logger,
	}
}

// actionsForSignal returns the list of action types that are appropriate for the given signal.
// Only actions in the global allowlist are returned.
func actionsForSignal(signal *riskpb.RiskSignalV1) []string {
	switch signal.GetRuleId() {
	case "mfa_fatigue", "impossible_travel", "anomalous_auth":
		// Revoke sessions and require MFA step-up on high-risk identity events.
		return []string{"revoke_sessions", "mfa_stepup"}
	case "signon_policy_violation":
		return []string{"signon_policy_adjust"}
	default:
		// For any other signal, suggest session revocation as a safe default.
		return []string{"revoke_sessions"}
	}
}

// Generate processes a RiskSignalV1 and produces ResponseActionV1 messages.
// Learning mode → publishes to action-recommendations.
// Autopilot enabled + circuit closed → publishes to action-requests.
func (g *Generator) Generate(ctx context.Context, signal *riskpb.RiskSignalV1) error {
	tenantID := signal.GetTenantId()
	if tenantID == "" {
		return fmt.Errorf("recommendations.Generate: signal missing tenant_id")
	}

	// Load autonomy state for this tenant.
	state, err := g.stateRepo.Get(ctx, tenantID)
	if err != nil {
		// Degrade gracefully: emit recommended only when state is unknown.
		g.logger.Warn("autonomy state unavailable; defaulting to recommended mode",
			zap.String("tenant_id", tenantID),
			zap.Error(err),
		)
		state = autonomy.TenantAutonomyState{
			TenantID:            tenantID,
			OnboardingStartedAt: time.Now(), // treat as brand-new = learning mode
		}
	}

	actions := actionsForSignal(signal)
	now := timestamppb.Now()

	for _, actionType := range actions {
		idempKey := idempotency.ActionKey(tenantID, signal.GetCaseId(), actionType, signal.GetIdentityId())
		actionID := uuid.New().String()
		decisionID := uuid.New().String()

		// Determine the execution mode based on autonomy state.
		execMode := "recommended"
		if !autonomy.IsInLearningMode(state) && state.AutopilotEnabled {
			execMode = "autopilot_executed"
		}

		// Validate the action via policy validator.
		vReq := policy.ValidationRequest{
			TenantID:      tenantID,
			ActionID:      actionID,
			ActionType:    actionType,
			ExecutionMode: execMode,
			IdentityID:    signal.GetIdentityId(),
			CaseID:        signal.GetCaseId(),
			AutonomyState: state,
		}
		decision := g.validator.Validate(ctx, vReq)
		decision.DecisionID = decisionID

		g.logger.Info("policy decision",
			zap.String("tenant_id", tenantID),
			zap.String("action_type", actionType),
			zap.String("exec_mode", execMode),
			zap.String("decision_id", decision.DecisionID),
			zap.Bool("allowed", decision.Allowed),
			zap.Strings("reasons", decision.RejectionReasons),
		)

		if !decision.Allowed {
			// Log rejection but continue to next action type.
			continue
		}

		// Build the ResponseActionV1 protobuf.
		mode := casespb.ActionMode_RECOMMENDED
		if execMode == "autopilot_executed" {
			mode = casespb.ActionMode_AUTOPILOT_EXECUTED
		}

		ra := &casespb.ResponseActionV1{
			ActionId:           actionID,
			TenantId:           tenantID,
			CaseId:             signal.GetCaseId(),
			IdentityId:         signal.GetIdentityId(),
			ActionType:         actionType,
			Mode:               mode,
			Status:             casespb.ActionStatus_PROPOSED,
			IdempotencyKey:     idempKey,
			ValidatorDecisionId: decisionID,
			ProposedAt:         now,
			ExecutedBy:         "controlplane",
			TraceId:            signal.GetTraceId(),
			RequestId:          signal.GetRequestId(),
		}

		// Emit to appropriate Kafka topic.
		if execMode == "recommended" {
			if err := g.publishEnvelope(ctx, g.recProducer, ra, signal, "aitc.cases.ResponseActionV1"); err != nil {
				g.logger.Error("publish recommendation failed",
					zap.String("action_type", actionType),
					zap.Error(err),
				)
				continue
			}
			g.logger.Info("recommendation emitted",
				zap.String("action_id", actionID),
				zap.String("action_type", actionType),
			)
		} else {
			// Check circuit breaker before autopilot execution.
			if err := g.circBreaker.Allow(); err != nil {
				g.logger.Warn("circuit breaker open; skipping autopilot action",
					zap.String("action_type", actionType),
					zap.Error(err),
				)
				continue
			}
			if err := g.publishEnvelope(ctx, g.reqProducer, ra, signal, "aitc.cases.ResponseActionV1"); err != nil {
				g.circBreaker.RecordFailure()
				g.logger.Error("publish action-request failed",
					zap.String("action_type", actionType),
					zap.Error(err),
				)
				continue
			}
			g.circBreaker.RecordSuccess()
			g.logger.Info("action-request emitted",
				zap.String("action_id", actionID),
				zap.String("action_type", actionType),
			)
		}
	}

	return nil
}

// publishEnvelope wraps a ResponseActionV1 in an EnvelopeV1 and publishes it.
func (g *Generator) publishEnvelope(
	ctx context.Context,
	producer *kafka.Producer,
	ra *casespb.ResponseActionV1,
	srcSignal *riskpb.RiskSignalV1,
	payloadType string,
) error {
	payload, err := proto.Marshal(ra)
	if err != nil {
		return fmt.Errorf("marshal ResponseActionV1: %w", err)
	}
	env := &commonpb.EnvelopeV1{
		TenantId:      ra.GetTenantId(),
		MessageId:     uuid.New().String(),
		SchemaVersion: "v1",
		Source:        commonpb.Source_INTERNAL,
		OccurredAt:    timestamppb.Now(),
		IngestedAt:    timestamppb.Now(),
		PayloadType:   payloadType,
		Payload:       payload,
		TraceId:       srcSignal.GetTraceId(),
		RequestId:     srcSignal.GetRequestId(),
	}
	return producer.Publish(ctx, env)
}

