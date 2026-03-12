// Package cases — case-to-signal correlation.
package cases

import (
"context"
"fmt"

"github.com/jackc/pgx/v5/pgxpool"
"go.uber.org/zap"

riskpb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/risk"
)

// Correlator links risk signals to their parent case in Postgres.
type Correlator struct {
db     *pgxpool.Pool
logger *zap.Logger
}

// NewCorrelator creates a Correlator backed by db.
func NewCorrelator(db *pgxpool.Pool, logger *zap.Logger) *Correlator {
return &Correlator{db: db, logger: logger}
}

// LinkSignals persists each signal to the risk_signals table and sets its case_id.
// It also appends the signal UUIDs to cases.signal_ids[].
// SECURITY: sets RLS tenant context before every write.
func (c *Correlator) LinkSignals(
ctx context.Context,
tenantID string,
caseID string,
signals []*riskpb.RiskSignalV1,
) error {
if len(signals) == 0 {
return nil
}

conn, err := c.db.Acquire(ctx)
if err != nil {
return fmt.Errorf("correlator: acquire conn: %w", err)
}
defer conn.Release()

if _, err := conn.Exec(ctx,
"SELECT set_config('app.tenant_id', $1, TRUE)", tenantID); err != nil {
return fmt.Errorf("correlator: set rls tenant: %w", err)
}

signalIDs := make([]string, 0, len(signals))
for _, sig := range signals {
_, err := conn.Exec(ctx, `
INSERT INTO risk_signals (
tenant_id, rule_id, rule_name, severity, cas_score, confidence,
description, evidence_event_ids, case_id, trace_id, request_id, detected_at
) VALUES (
$1, $2, $3, $4, $5, $6,
$7, $8, $9::uuid, $10, $11, NOW()
)`,
tenantID,
sig.GetRuleId(),
sig.GetRuleName(),
severityToStr(sig.GetSeverity()),
sig.GetCasScore(),
sig.GetConfidence(),
sig.GetDescription(),
sig.GetEvidenceEventIds(),
caseID,
sig.GetTraceId(),
sig.GetRequestId(),
)
if err != nil {
c.logger.Warn("correlator: insert risk_signal failed",
zap.String("rule_id", sig.GetRuleId()),
zap.Error(err),
)
continue
}
signalIDs = append(signalIDs, sig.GetSignalId())
}

// Append signal IDs to the case.
if len(signalIDs) > 0 {
_, err = conn.Exec(ctx, `
UPDATE cases
SET signal_ids = signal_ids || $2::uuid[],
    updated_at = NOW()
WHERE id = $1::uuid`,
caseID, signalIDs,
)
if err != nil {
return fmt.Errorf("correlator: update case signal_ids: %w", err)
}
}
return nil
}

func severityToStr(sev riskpb.Severity) string {
switch sev {
case riskpb.Severity_CRITICAL:
return "critical"
case riskpb.Severity_HIGH:
return "high"
case riskpb.Severity_MEDIUM:
return "medium"
case riskpb.Severity_LOW:
return "low"
default:
return "unspecified"
}
}
