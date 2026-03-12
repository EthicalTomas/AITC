package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/ethicaltomas/aitc/internal/tenant"
	"github.com/ethicaltomas/aitc/services/api/internal/auth"
)

type createReportRequest struct {
	ReportType  string `json:"report_type"`
	PeriodStart string `json:"period_start"`
	PeriodEnd   string `json:"period_end"`
}

type reportRow struct {
	ID          string      `json:"id"`
	TenantID    string      `json:"tenant_id"`
	ReportType  string      `json:"report_type"`
	Status      string      `json:"status"`
	PeriodStart interface{} `json:"period_start"`
	PeriodEnd   interface{} `json:"period_end"`
	S3Bucket    *string     `json:"s3_bucket,omitempty"`
	S3Key       *string     `json:"s3_key,omitempty"`
	CreatedAt   interface{} `json:"created_at"`
}

// CreateReport handles POST /v1/reports.
func (h *Handler) CreateReport(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenant.TenantFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing tenant_id"})
		return
	}

	claims, hasClaims := auth.ClaimsFromContext(r.Context())
	if !hasClaims {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	var req createReportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.ReportType != "soc2" && req.ReportType != "iso27001" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "report_type must be 'soc2' or 'iso27001'"})
		return
	}
	if req.PeriodStart == "" || req.PeriodEnd == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "period_start and period_end are required"})
		return
	}

	if h.db == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "database unavailable"})
		return
	}

	tx, err := h.db.Begin(r.Context())
	if err != nil {
		h.logger.Error("begin tx", zap.Error(err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	defer tx.Rollback(r.Context()) //nolint:errcheck

	if err := tenant.SetRLS(r.Context(), tx, tenantID); err != nil {
		h.logger.Error("set rls", zap.Error(err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	reportID := uuid.New().String()
	_, err = tx.Exec(r.Context(),
		`INSERT INTO evidence_reports (id, tenant_id, report_type, status, period_start, period_end, requested_by, created_at)
		 VALUES ($1, $2, $3, 'generating', $4, $5, $6, NOW())`,
		reportID, tenantID, req.ReportType, req.PeriodStart, req.PeriodEnd, claims.Email)
	if err != nil {
		h.logger.Error("insert report", zap.Error(err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		h.logger.Error("commit tx", zap.Error(err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"id":          reportID,
		"status":      "generating",
		"report_type": req.ReportType,
	})
}

// DownloadReport handles GET /v1/reports/{id}/download.
func (h *Handler) DownloadReport(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenant.TenantFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing tenant_id"})
		return
	}

	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing id"})
		return
	}

	if h.db == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "database unavailable"})
		return
	}

	tx, err := h.db.Begin(r.Context())
	if err != nil {
		h.logger.Error("begin tx", zap.Error(err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	defer tx.Rollback(r.Context()) //nolint:errcheck

	if err := tenant.SetRLS(r.Context(), tx, tenantID); err != nil {
		h.logger.Error("set rls", zap.Error(err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	var rep reportRow
	err = tx.QueryRow(r.Context(),
		`SELECT id, tenant_id, report_type, status, period_start, period_end, s3_bucket, s3_key, created_at
		 FROM evidence_reports WHERE id=$1 AND tenant_id=$2`,
		id, tenantID).Scan(
		&rep.ID, &rep.TenantID, &rep.ReportType, &rep.Status,
		&rep.PeriodStart, &rep.PeriodEnd, &rep.S3Bucket, &rep.S3Key, &rep.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "report not found"})
			return
		}
		h.logger.Error("get report", zap.Error(err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	if rep.Status != "complete" {
		writeJSON(w, http.StatusAccepted, map[string]interface{}{
			"id":     rep.ID,
			"status": rep.Status,
		})
		return
	}

	writeJSON(w, http.StatusOK, rep)
}
