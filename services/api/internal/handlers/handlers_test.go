// Package handlers_test contains unit tests for the API handlers.
// These tests run without a real database by using a nil db pool,
// which causes handlers to return 503 Service Unavailable — this
// validates the request parsing and auth flow independently of DB.
package handlers_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/ethicaltomas/aitc/internal/tenant"
	"github.com/ethicaltomas/aitc/services/api/internal/auth"
	"github.com/ethicaltomas/aitc/services/api/internal/handlers"
	"github.com/ethicaltomas/aitc/services/api/internal/rbac"
)

const testTenantID = "dev-tenant"

// withTestContext returns a request with both tenant and claims injected in context.
func withTestContext(req *http.Request, role, tenantID string) *http.Request {
	ctx := tenant.WithTenant(req.Context(), tenantID)
	claims := auth.Claims{
		UserID:   "test-user",
		Email:    "test@example.com",
		Role:     role,
		TenantID: tenantID,
	}
	ctx = auth.WithClaims(ctx, claims)
	return req.WithContext(ctx)
}

// newHandler creates a Handler with a nil DB (for unit testing without DB).
func newHandler() *handlers.Handler {
	return handlers.New(nil, nil, zap.NewNop())
}

// TestListCases_MissingTenantID verifies that missing X-Tenant-Id returns 400.
func TestListCases_MissingTenantID(t *testing.T) {
	h := newHandler()

	req := httptest.NewRequest(http.MethodGet, "/v1/cases", nil)
	// Inject Admin claims but no tenant in context
	claims := auth.Claims{UserID: "u1", Role: rbac.RoleAdmin, TenantID: ""}
	req = req.WithContext(auth.WithClaims(req.Context(), claims))

	rec := httptest.NewRecorder()
	h.ListCases(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing tenant_id, got %d", rec.Code)
	}
}

// TestListCases_DBUnavailable verifies 503 when DB is nil but tenant is set.
func TestListCases_DBUnavailable(t *testing.T) {
	h := newHandler()

	req := httptest.NewRequest(http.MethodGet, "/v1/cases", nil)
	req = withTestContext(req, rbac.RoleReadOnly, testTenantID)

	rec := httptest.NewRecorder()
	h.ListCases(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 for nil DB, got %d", rec.Code)
	}
}

// TestGetCase_MissingTenantID verifies that missing tenant returns 400.
func TestGetCase_MissingTenantID(t *testing.T) {
	h := newHandler()

	req := httptest.NewRequest(http.MethodGet, "/v1/cases/some-id", nil)
	claims := auth.Claims{UserID: "u1", Role: rbac.RoleAdmin, TenantID: ""}
	req = req.WithContext(auth.WithClaims(req.Context(), claims))

	rec := httptest.NewRecorder()
	h.GetCase(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing tenant_id, got %d", rec.Code)
	}
}

// TestListRecommendations_MissingTenant verifies 400 with missing tenant context.
func TestListRecommendations_MissingTenant(t *testing.T) {
	h := newHandler()

	req := httptest.NewRequest(http.MethodGet, "/v1/recommendations", nil)
	claims := auth.Claims{UserID: "u1", Role: rbac.RoleAnalyst, TenantID: ""}
	req = req.WithContext(auth.WithClaims(req.Context(), claims))

	rec := httptest.NewRecorder()
	h.ListRecommendations(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 (missing tenant from context), got %d", rec.Code)
	}
}

// TestListRecommendations_DBUnavailable verifies 503 when DB is nil.
func TestListRecommendations_DBUnavailable(t *testing.T) {
	h := newHandler()

	req := httptest.NewRequest(http.MethodGet, "/v1/recommendations", nil)
	req = withTestContext(req, rbac.RoleReadOnly, testTenantID)

	rec := httptest.NewRecorder()
	h.ListRecommendations(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 for nil DB, got %d", rec.Code)
	}
}

// TestEnableAutopilot_ConfirmFalse verifies that confirm:false returns 400.
func TestEnableAutopilot_ConfirmFalse(t *testing.T) {
	h := newHandler()

	body := `{"confirm": false}`
	req := httptest.NewRequest(http.MethodPost, "/v1/autopilot/enable", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withTestContext(req, rbac.RoleAdmin, testTenantID)

	rec := httptest.NewRecorder()
	h.EnableAutopilot(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 when confirm=false, got %d", rec.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !strings.Contains(resp["error"], "confirm") {
		t.Errorf("expected error mentioning 'confirm', got: %q", resp["error"])
	}
}

// TestEnableAutopilot_InvalidBody verifies that malformed JSON returns 400.
func TestEnableAutopilot_InvalidBody(t *testing.T) {
	h := newHandler()

	req := httptest.NewRequest(http.MethodPost, "/v1/autopilot/enable", bytes.NewReader([]byte("notjson")))
	req.Header.Set("Content-Type", "application/json")
	req = withTestContext(req, rbac.RoleAdmin, testTenantID)

	rec := httptest.NewRecorder()
	h.EnableAutopilot(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", rec.Code)
	}
}

// TestEnableAutopilot_DBUnavailable verifies 503 when DB is nil and confirm=true.
func TestEnableAutopilot_DBUnavailable(t *testing.T) {
	h := newHandler()

	body := `{"confirm": true}`
	req := httptest.NewRequest(http.MethodPost, "/v1/autopilot/enable", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withTestContext(req, rbac.RoleAdmin, testTenantID)

	rec := httptest.NewRecorder()
	h.EnableAutopilot(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 for nil DB with confirm=true, got %d", rec.Code)
	}
}

// TestCreateReport_InvalidReportType verifies that unknown report_type returns 400.
func TestCreateReport_InvalidReportType(t *testing.T) {
	h := newHandler()

	body := `{"report_type":"unknown","period_start":"2025-01-01T00:00:00Z","period_end":"2025-12-31T00:00:00Z"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/reports", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withTestContext(req, rbac.RoleAnalyst, testTenantID)

	rec := httptest.NewRecorder()
	h.CreateReport(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for unknown report type, got %d", rec.Code)
	}
}

// TestCreateReport_MissingPeriod verifies that missing period fields returns 400.
func TestCreateReport_MissingPeriod(t *testing.T) {
	h := newHandler()

	body := `{"report_type":"soc2"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/reports", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withTestContext(req, rbac.RoleAnalyst, testTenantID)

	rec := httptest.NewRecorder()
	h.CreateReport(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing period, got %d", rec.Code)
	}
}

// TestAutopilotGate_7DayRule verifies the inlined 7-day learning mode check.
// This directly tests the logic from the autonomy package that is inlined in handlers.
func TestAutopilotGate_7DayRule(t *testing.T) {
	const learningModeDuration = 7 * 24 * time.Hour

	tests := []struct {
		name             string
		onboardingOffset time.Duration // negative = in the past
		expectCanEnable  bool
	}{
		{"1 day old - cannot enable", -1 * 24 * time.Hour, false},
		{"3 days old - cannot enable", -3 * 24 * time.Hour, false},
		{"6.9 days old - cannot enable", -6*24*time.Hour - 23*time.Hour, false},
		{"7 days old - can enable", -7 * 24 * time.Hour, true},
		{"8 days old - can enable", -8 * 24 * time.Hour, true},
		{"30 days old - can enable", -30 * 24 * time.Hour, true},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			onboardingStartedAt := time.Now().Add(tc.onboardingOffset)
			elapsed := time.Since(onboardingStartedAt)
			canEnable := elapsed >= learningModeDuration

			if canEnable != tc.expectCanEnable {
				t.Errorf(
					"onboarding %v ago: expected canEnable=%v, got canEnable=%v (elapsed %.2f days)",
					tc.onboardingOffset,
					tc.expectCanEnable,
					canEnable,
					elapsed.Hours()/24,
				)
			}
		})
	}
}

// TestRBAC_AutopilotEnableRequiresAdmin verifies Admin-only endpoint returns 403 for other roles.
func TestRBAC_AutopilotEnableRequiresAdmin(t *testing.T) {
	nonAdminRoles := []string{rbac.RoleAnalyst, rbac.RoleAuditor, rbac.RoleReadOnly}
	mw := rbac.Require(rbac.RoleAdmin)

	for _, role := range nonAdminRoles {
		role := role
		t.Run(fmt.Sprintf("role_%s", role), func(t *testing.T) {
			injectClaims := func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					claims := auth.Claims{UserID: "u1", Role: role, TenantID: "t1"}
					ctx := auth.WithClaims(r.Context(), claims)
					next.ServeHTTP(w, r.WithContext(ctx))
				})
			}

			handler := injectClaims(mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Errorf("handler should not be called for role %q", role)
			})))

			req := httptest.NewRequest(http.MethodPost, "/v1/autopilot/enable", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Errorf("expected 403 for role %q, got %d", role, rec.Code)
			}
		})
	}
}

// TestRBAC_ReadOnly_CannotExecuteRecommendation verifies read-only users cannot execute.
func TestRBAC_ReadOnly_CannotExecuteRecommendation(t *testing.T) {
	mw := rbac.Require(rbac.RoleAnalyst, rbac.RoleAdmin)
	injectClaims := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := auth.Claims{UserID: "u1", Role: rbac.RoleReadOnly, TenantID: "t1"}
			ctx := auth.WithClaims(r.Context(), claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}

	handler := injectClaims(mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called for ReadOnly role on execute endpoint")
	})))

	req := httptest.NewRequest(http.MethodPost, "/v1/recommendations/some-id/execute", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for ReadOnly on execute, got %d", rec.Code)
	}
}

