// Package generator orchestrates evidence pack generation for a single report.
// It queries each control pack, combines the artifacts into a bundle, marshals
// to JSON, uploads to S3/MinIO, and marks the evidence_reports row complete.
package generator

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/ethicaltomas/aitc/internal/tenant"
	"github.com/ethicaltomas/aitc/services/evidence/internal/archive"
	"github.com/ethicaltomas/aitc/services/evidence/internal/export"
	"github.com/ethicaltomas/aitc/services/evidence/internal/packs/iso27001"
	"github.com/ethicaltomas/aitc/services/evidence/internal/packs/soc2"
)

// ReportRow holds the columns we read from evidence_reports.
type ReportRow struct {
	ID          string
	TenantID    string
	ReportType  string
	PeriodStart time.Time
	PeriodEnd   time.Time
}

// Bundle is the top-level JSON object written to S3.
type Bundle struct {
	ReportID    string             `json:"report_id"`
	TenantID    string             `json:"tenant_id"`
	ReportType  string             `json:"report_type"`
	PeriodStart string             `json:"period_start"`
	PeriodEnd   string             `json:"period_end"`
	GeneratedAt string             `json:"generated_at"`
	Artifacts   []*export.Artifact `json:"artifacts"`
}

// packFunc is the signature of each evidence pack generator.
type packFunc func(ctx context.Context, db *pgxpool.Pool, tenantID string, start, end time.Time) (*export.Artifact, error)

// Generator ties together the DB, archiver, and pack generators.
type Generator struct {
	db       *pgxpool.Pool
	uploader *archive.Uploader
	logger   *zap.Logger
}

// New creates a Generator.
func New(db *pgxpool.Pool, uploader *archive.Uploader, logger *zap.Logger) *Generator {
	return &Generator{db: db, uploader: uploader, logger: logger}
}

// Generate produces the evidence bundle for a single report row.
func (g *Generator) Generate(ctx context.Context, rep ReportRow) error {
	g.logger.Info("generating evidence report",
		zap.String("report_id", rep.ID),
		zap.String("tenant_id", rep.TenantID),
		zap.String("report_type", rep.ReportType),
	)

	packs := packsFor(rep.ReportType)
	bundle := &Bundle{
		ReportID:    rep.ID,
		TenantID:    rep.TenantID,
		ReportType:  rep.ReportType,
		PeriodStart: rep.PeriodStart.UTC().Format(time.RFC3339),
		PeriodEnd:   rep.PeriodEnd.UTC().Format(time.RFC3339),
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}

	for _, fn := range packs {
		artifact, err := fn(ctx, g.db, rep.TenantID, rep.PeriodStart, rep.PeriodEnd)
		if err != nil {
			// Log but continue: partial evidence is still valuable.
			g.logger.Error("pack generator failed",
				zap.String("report_id", rep.ID),
				zap.Error(err),
			)
			continue
		}
		bundle.Artifacts = append(bundle.Artifacts, artifact)
	}

	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal bundle: %w", err)
	}

	key := archive.BuildKey(rep.TenantID, rep.ReportType, rep.ID)
	if err := g.uploader.Upload(ctx, rep.TenantID, rep.ID, key, data); err != nil {
		return fmt.Errorf("upload bundle: %w", err)
	}

	g.logger.Info("evidence report complete",
		zap.String("report_id", rep.ID),
		zap.String("s3_key", key),
		zap.Int("artifacts", len(bundle.Artifacts)),
	)
	return nil
}

// ProcessPending fetches all evidence_reports rows with status='generating' across
// all tenants and generates each one.  Individual pack generators set RLS per tenant.
func (g *Generator) ProcessPending(ctx context.Context) error {
	if g.db == nil {
		return fmt.Errorf("database not configured")
	}
	rows, err := g.db.Query(ctx,
		`SELECT id, tenant_id, report_type, period_start, period_end
		   FROM evidence_reports
		  WHERE status = 'generating'
		  ORDER BY created_at
		  LIMIT 100`)
	if err != nil {
		return fmt.Errorf("query pending reports: %w", err)
	}
	defer rows.Close()

	var reports []ReportRow
	for rows.Next() {
		var r ReportRow
		if err := rows.Scan(&r.ID, &r.TenantID, &r.ReportType, &r.PeriodStart, &r.PeriodEnd); err != nil {
			return fmt.Errorf("scan report row: %w", err)
		}
		reports = append(reports, r)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate reports: %w", err)
	}

	for _, rep := range reports {
		if err := g.Generate(ctx, rep); err != nil {
			g.logger.Error("generate report failed",
				zap.String("report_id", rep.ID),
				zap.Error(err),
			)
			g.markFailed(ctx, rep.TenantID, rep.ID, err.Error())
		}
	}
	return nil
}

// ProcessByID generates a single evidence report identified by reportID + tenantID.
func (g *Generator) ProcessByID(ctx context.Context, tenantID, reportID string) error {
	if g.db == nil {
		return fmt.Errorf("database not configured")
	}
	tx, err := g.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if err := tenant.SetRLS(ctx, tx, tenantID); err != nil {
		return fmt.Errorf("set rls: %w", err)
	}

	var rep ReportRow
	err = tx.QueryRow(ctx,
		`SELECT id, tenant_id, report_type, period_start, period_end
		   FROM evidence_reports
		  WHERE id = $1 AND tenant_id = $2`,
		reportID, tenantID).Scan(&rep.ID, &rep.TenantID, &rep.ReportType, &rep.PeriodStart, &rep.PeriodEnd)
	if err != nil {
		return fmt.Errorf("fetch report %s: %w", reportID, err)
	}
	_ = tx.Commit(ctx)

	return g.Generate(ctx, rep)
}

// markFailed updates an evidence_reports row to status=failed.
func (g *Generator) markFailed(ctx context.Context, tenantID, reportID, reason string) {
	tx, err := g.db.Begin(ctx)
	if err != nil {
		g.logger.Error("markFailed begin tx", zap.Error(err))
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if err := tenant.SetRLS(ctx, tx, tenantID); err != nil {
		g.logger.Error("markFailed set rls", zap.Error(err))
		return
	}

	_, err = tx.Exec(ctx,
		`UPDATE evidence_reports SET status='failed', updated_at=NOW()
		  WHERE id=$1 AND tenant_id=$2`,
		reportID, tenantID)
	if err != nil {
		g.logger.Error("markFailed update", zap.Error(err))
		return
	}
	_ = tx.Commit(ctx)
	g.logger.Warn("evidence report marked failed",
		zap.String("report_id", reportID),
		zap.String("reason", reason),
	)
}

// packsFor returns the set of pack generators for the given report type.
func packsFor(reportType string) []packFunc {
	switch reportType {
	case "iso27001":
		return []packFunc{
			iso27001.GenerateAccessControl,
			iso27001.GenerateIncidentManagement,
			iso27001.GenerateLoggingMonitoring,
		}
	default: // "soc2"
		return []packFunc{
			soc2.GenerateAccessControlRoster,
			soc2.GenerateMFACoverage,
			soc2.GeneratePrivilegedInventory,
			soc2.GenerateAdminActivity,
			soc2.GenerateIncidentTimelines,
		}
	}
}
