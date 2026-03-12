// Package cases provides case creation and management for the pipeline service.
package cases

import (
"context"
"fmt"
"time"

"github.com/jackc/pgx/v5/pgxpool"
"go.uber.org/zap"
"google.golang.org/protobuf/types/known/timestamppb"

casespb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/cases"
riskpb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/risk"
"github.com/ethicaltomas/aitc/services/pipeline/internal/cas"
)

// CaseLookbackWindow is the time window within which signals for the same identity
// will be grouped into a single open case.
const CaseLookbackWindow = 24 * time.Hour

// Creator creates or retrieves cases in Postgres.
type Creator struct {
db     *pgxpool.Pool
logger *zap.Logger
}

// NewCreator creates a Creator backed by db.
func NewCreator(db *pgxpool.Pool, logger *zap.Logger) *Creator {
return &Creator{db: db, logger: logger}
}

// EnsureCase finds an existing open case for the identity within the lookback
// window, or creates a new one. Returns the case ID.
// SECURITY: sets RLS tenant context before every operation.
func (c *Creator) EnsureCase(
ctx context.Context,
tenantID string,
signals []*riskpb.RiskSignalV1,
) (string, error) {
if len(signals) == 0 {
return "", fmt.Errorf("cases: no signals provided")
}

identityID := signals[0].GetIdentityId()
// Pick highest severity from signals.
topSev := pickTopSeverity(signals)
title := fmt.Sprintf("Risk alert for identity %s [%s]", identityID, topSev)
desc := buildDescription(signals)

conn, err := c.db.Acquire(ctx)
if err != nil {
return "", fmt.Errorf("cases: acquire conn: %w", err)
}
defer conn.Release()

if _, err := conn.Exec(ctx,
"SELECT set_config('app.tenant_id', $1, TRUE)", tenantID); err != nil {
return "", fmt.Errorf("cases: set rls tenant: %w", err)
}

// Try to find existing open case for this identity within lookback window.
var caseID string
err = conn.QueryRow(ctx, `
SELECT id::text FROM cases
WHERE tenant_id = $1
  AND identity_id::text = $2
  AND status = 'open'
  AND created_at > NOW() - $3::interval
ORDER BY created_at DESC
LIMIT 1`,
tenantID, identityID, CaseLookbackWindow.String(),
).Scan(&caseID)

if err == nil {
// Existing case found — update severity if the new signals are more severe.
_, _ = conn.Exec(ctx, `
UPDATE cases
SET severity = CASE WHEN $2 > severity THEN $2 ELSE severity END,
    updated_at = NOW()
WHERE id = $1::uuid`,
caseID, topSev,
)
c.logger.Debug("cases: attached to existing case",
zap.String("case_id", caseID),
zap.String("identity_id", identityID),
)
return caseID, nil
}

// Create new case.
err = conn.QueryRow(ctx, `
INSERT INTO cases (tenant_id, identity_id, title, description, status, severity, trace_id)
VALUES ($1, $2::uuid, $3, $4, 'open', $5, $6)
RETURNING id::text`,
tenantID, identityID, title, desc, topSev, signals[0].GetTraceId(),
).Scan(&caseID)
if err != nil {
return "", fmt.Errorf("cases: insert case: %w", err)
}

c.logger.Info("cases: new case created",
zap.String("case_id", caseID),
zap.String("identity_id", identityID),
zap.String("severity", topSev),
)
return caseID, nil
}

// CaseProto builds a CaseV1 proto for the given case record (used in Kafka messages).
func CaseProto(caseID, tenantID, identityID, severity string, signalIDs []string) *casespb.CaseV1 {
return &casespb.CaseV1{
CaseId:     caseID,
TenantId:   tenantID,
IdentityId: identityID,
Status:     casespb.CaseStatus_OPEN,
Severity:   severity,
SignalIds:  signalIDs,
CreatedAt:  timestamppb.New(time.Now().UTC()),
UpdatedAt:  timestamppb.New(time.Now().UTC()),
}
}

func pickTopSeverity(signals []*riskpb.RiskSignalV1) string {
top := riskpb.Severity_SEVERITY_UNSPECIFIED
for _, s := range signals {
if s.GetSeverity() > top {
top = s.GetSeverity()
}
}
return cas.SeverityString(top)
}

func buildDescription(signals []*riskpb.RiskSignalV1) string {
desc := fmt.Sprintf("Triggered by %d risk signal(s):", len(signals))
for _, s := range signals {
desc += fmt.Sprintf("\n- [%s] %s: %s", cas.SeverityString(s.GetSeverity()), s.GetRuleName(), s.GetDescription())
}
return desc
}
