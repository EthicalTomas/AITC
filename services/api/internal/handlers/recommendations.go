package handlers

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	globalaudit "github.com/ethicaltomas/aitc/internal/audit"
	"github.com/ethicaltomas/aitc/internal/tenant"
	"github.com/ethicaltomas/aitc/services/api/internal/auth"
)

// learningModeDuration is the mandatory learning period before manual execution is allowed.
// Mirrors services/controlplane/internal/autonomy.LearningModeDuration.
const learningModeDuration = 7 * 24 * time.Hour

func isInLearningMode(onboardingStartedAt time.Time) bool {
	return time.Since(onboardingStartedAt) < learningModeDuration
}

// recommendationRow represents a row from the response_actions table.
type recommendationRow struct {
	ID          string      `json:"id"`
	TenantID    string      `json:"tenant_id"`
	CaseID      string      `json:"case_id"`
	ActionType  string      `json:"action_type"`
	Mode        string      `json:"mode"`
	Status      string      `json:"status"`
	ExecutedBy  *string     `json:"executed_by,omitempty"`
	CreatedAt   interface{} `json:"created_at"`
	UpdatedAt   interface{} `json:"updated_at"`
}

// ListRecommendations handles GET /v1/recommendations.
// Query params: case_id (filter), status (filter), page/page_size.
func (h *Handler) ListRecommendations(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenant.TenantFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing tenant_id"})
		return
	}

	caseIDFilter := r.URL.Query().Get("case_id")
	statusFilter := r.URL.Query().Get("status")
	page, pageSize := parsePagination(r)

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

	offset := (page - 1) * pageSize

	// Build parameterized query with optional filters.
	args := []interface{}{tenantID}
	where := "tenant_id=$1 AND mode='recommended'"
	argIdx := 2
	if caseIDFilter != "" {
		where += " AND case_id=$" + itoa(argIdx)
		args = append(args, caseIDFilter)
		argIdx++
	}
	if statusFilter != "" {
		where += " AND status=$" + itoa(argIdx)
		args = append(args, statusFilter)
		argIdx++
	}

	var total int
	if err := tx.QueryRow(r.Context(),
		"SELECT COUNT(*) FROM response_actions WHERE "+where,
		args...).Scan(&total); err != nil {
		h.logger.Error("count recommendations", zap.Error(err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	limitArgs := append(args, pageSize, offset)
	pgxRows, err := tx.Query(r.Context(),
		"SELECT id, tenant_id, case_id, action_type, mode, status, executed_by, created_at, updated_at"+
			" FROM response_actions WHERE "+where+
			" ORDER BY created_at DESC LIMIT $"+itoa(argIdx)+" OFFSET $"+itoa(argIdx+1),
		limitArgs...)
	if err != nil {
		h.logger.Error("list recommendations", zap.Error(err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	recs, err := collectRecommendations(pgxRows)
	if err != nil {
		h.logger.Error("scan recommendations", zap.Error(err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data":      recs,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	})
}

// ExecuteRecommendation handles POST /v1/recommendations/{id}/execute.
func (h *Handler) ExecuteRecommendation(w http.ResponseWriter, r *http.Request) {
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

	// Check learning mode by querying tenants table.
	var onboardingStartedAt time.Time
	err = tx.QueryRow(r.Context(),
		`SELECT onboarding_started_at FROM tenants WHERE id=$1`,
		tenantID).Scan(&onboardingStartedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tenant not found"})
			return
		}
		h.logger.Error("query tenant", zap.Error(err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	if isInLearningMode(onboardingStartedAt) {
		writeJSON(w, http.StatusConflict, map[string]string{
			"error": "tenant is in learning mode; manual execution is not permitted until learning period completes",
		})
		return
	}

	// Fetch the recommendation.
	var rec recommendationRow
	err = tx.QueryRow(r.Context(),
		`SELECT id, tenant_id, case_id, action_type, mode, status, executed_by, created_at, updated_at
		 FROM response_actions WHERE id=$1 AND tenant_id=$2`,
		id, tenantID).Scan(
		&rec.ID, &rec.TenantID, &rec.CaseID, &rec.ActionType,
		&rec.Mode, &rec.Status, &rec.ExecutedBy, &rec.CreatedAt, &rec.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "recommendation not found"})
			return
		}
		h.logger.Error("get recommendation", zap.Error(err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	// Update status to 'executing' and set executed_by.
	email := claims.Email
	_, err = tx.Exec(r.Context(),
		`UPDATE response_actions SET status='executing', executed_by=$1, updated_at=NOW()
		 WHERE id=$2 AND tenant_id=$3`,
		email, id, tenantID)
	if err != nil {
		h.logger.Error("update recommendation", zap.Error(err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		h.logger.Error("commit tx", zap.Error(err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	// Write audit log.
	if h.audit != nil {
		if auditErr := h.audit.Write(r.Context(), globalaudit.Entry{
			TenantID:    tenantID,
			EventType:   globalaudit.EventActionExecuted,
			Actor:       claims.Email,
			SubjectType: "response_action",
			SubjectID:   id,
			Description: "recommendation executed by " + claims.Email,
			AfterState:  map[string]string{"status": "executing", "executed_by": email},
		}); auditErr != nil {
			h.logger.Warn("audit write failed", zap.Error(auditErr))
		}
	}

	rec.Status = "executing"
	rec.ExecutedBy = &email
	writeJSON(w, http.StatusOK, rec)
}

func collectRecommendations(rows pgx.Rows) ([]recommendationRow, error) {
	defer rows.Close()
	var result []recommendationRow
	for rows.Next() {
		var rec recommendationRow
		if err := rows.Scan(
			&rec.ID, &rec.TenantID, &rec.CaseID, &rec.ActionType,
			&rec.Mode, &rec.Status, &rec.ExecutedBy, &rec.CreatedAt, &rec.UpdatedAt); err != nil {
			return nil, err
		}
		result = append(result, rec)
	}
	if result == nil {
		result = []recommendationRow{}
	}
	return result, rows.Err()
}

func itoa(n int) string {
	return strconv.Itoa(n)
}
