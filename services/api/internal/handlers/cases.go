// Package handlers implements the HTTP handlers for the AITC API service.
package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	globalaudit "github.com/ethicaltomas/aitc/internal/audit"
	"github.com/ethicaltomas/aitc/internal/tenant"
)

// Handler holds shared dependencies for all API handlers.
type Handler struct {
	db     *pgxpool.Pool
	audit  *globalaudit.Writer
	logger *zap.Logger
}

// New creates a new Handler with the provided dependencies.
func New(db *pgxpool.Pool, audit *globalaudit.Writer, logger *zap.Logger) *Handler {
	return &Handler{db: db, audit: audit, logger: logger}
}

// ListCases handles GET /v1/cases.
// Query params: status (filter), page (default 1), page_size (default 20, max 100).
func (h *Handler) ListCases(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenant.TenantFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing tenant_id"})
		return
	}

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
	args := []interface{}{tenantID}
	where := "WHERE tenant_id=$1"
	if statusFilter != "" {
		where += " AND status=$2"
		args = append(args, statusFilter)
	}

	var total int
	if err := tx.QueryRow(r.Context(),
		"SELECT COUNT(*) FROM cases "+where, args...).Scan(&total); err != nil {
		h.logger.Error("count cases", zap.Error(err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	limitIdx := len(args) + 1
	offsetIdx := len(args) + 2
	listArgs := append(args, pageSize, offset)
	pgxRows, err := tx.Query(r.Context(),
		"SELECT id, tenant_id, status, severity, title, created_at, updated_at FROM cases "+
			where+" ORDER BY created_at DESC"+
			" LIMIT $"+strconv.Itoa(limitIdx)+" OFFSET $"+strconv.Itoa(offsetIdx),
		listArgs...)
	if err != nil {
		h.logger.Error("list cases", zap.Error(err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	cases, err := collectCases(pgxRows)
	if err != nil {
		h.logger.Error("scan cases", zap.Error(err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data":      cases,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	})
}

// GetCase handles GET /v1/cases/{id}.
func (h *Handler) GetCase(w http.ResponseWriter, r *http.Request) {
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

	var c caseRow
	err = tx.QueryRow(r.Context(),
		`SELECT id, tenant_id, status, severity, title, created_at, updated_at
		 FROM cases WHERE id=$1 AND tenant_id=$2`,
		id, tenantID).Scan(&c.ID, &c.TenantID, &c.Status, &c.Severity, &c.Title, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "case not found"})
			return
		}
		h.logger.Error("get case", zap.Error(err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	writeJSON(w, http.StatusOK, c)
}

// caseRow represents a row from the cases table.
type caseRow struct {
	ID        string      `json:"id"`
	TenantID  string      `json:"tenant_id"`
	Status    string      `json:"status"`
	Severity  string      `json:"severity"`
	Title     string      `json:"title"`
	CreatedAt interface{} `json:"created_at"`
	UpdatedAt interface{} `json:"updated_at"`
}

func collectCases(rows pgx.Rows) ([]caseRow, error) {
	defer rows.Close()
	var result []caseRow
	for rows.Next() {
		var c caseRow
		if err := rows.Scan(&c.ID, &c.TenantID, &c.Status, &c.Severity, &c.Title, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		result = append(result, c)
	}
	if result == nil {
		result = []caseRow{}
	}
	return result, rows.Err()
}

// parsePagination parses page and page_size query params with safe defaults.
func parsePagination(r *http.Request) (page, pageSize int) {
	page = 1
	pageSize = 20
	if v := r.URL.Query().Get("page"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			page = n
		}
	}
	if v := r.URL.Query().Get("page_size"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			if n > 100 {
				n = 100
			}
			pageSize = n
		}
	}
	return
}

func writeJSON(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
