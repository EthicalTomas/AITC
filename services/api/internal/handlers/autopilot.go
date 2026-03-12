package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	globalaudit "github.com/ethicaltomas/aitc/internal/audit"
	"github.com/ethicaltomas/aitc/internal/tenant"
	"github.com/ethicaltomas/aitc/services/api/internal/auth"
)

// canEnableAutopilot returns nil if autopilot may be enabled, or an error.
// Mirrors services/controlplane/internal/autonomy.CanEnableAutopilot.
func canEnableAutopilot(onboardingStartedAt time.Time) error {
	elapsed := time.Since(onboardingStartedAt)
	if elapsed < learningModeDuration {
		remaining := learningModeDuration - elapsed
		return fmt.Errorf(
			"autopilot cannot be enabled: learning mode requires %s more (%.1f days remaining)",
			remaining.Round(time.Minute),
			remaining.Hours()/24,
		)
	}
	return nil
}

type enableAutopilotRequest struct {
	Confirm bool `json:"confirm"`
}

// EnableAutopilot handles POST /v1/autopilot/enable.
func (h *Handler) EnableAutopilot(w http.ResponseWriter, r *http.Request) {
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

	var req enableAutopilotRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if !req.Confirm {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "confirm must be true to enable autopilot"})
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

	if err := canEnableAutopilot(onboardingStartedAt); err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}

	_, err = tx.Exec(r.Context(),
		`UPDATE tenants SET autopilot_enabled=true, autopilot_enabled_at=NOW() WHERE id=$1`,
		tenantID)
	if err != nil {
		h.logger.Error("enable autopilot", zap.Error(err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		h.logger.Error("commit tx", zap.Error(err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	if h.audit != nil {
		if auditErr := h.audit.Write(r.Context(), globalaudit.Entry{
			TenantID:    tenantID,
			EventType:   globalaudit.EventAutonomyStateChanged,
			Actor:       claims.Email,
			SubjectType: "tenant",
			SubjectID:   tenantID,
			Description: "autopilot enabled by " + claims.Email,
			BeforeState: map[string]interface{}{"autopilot_enabled": false},
			AfterState:  map[string]interface{}{"autopilot_enabled": true},
		}); auditErr != nil {
			h.logger.Warn("audit write failed", zap.Error(auditErr))
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"autopilot_enabled": true,
		"tenant_id":         tenantID,
	})
}
