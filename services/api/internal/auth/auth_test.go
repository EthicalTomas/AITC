package auth_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ethicaltomas/aitc/services/api/internal/auth"
)

// makeJWT creates a minimal JWT with the given payload (no signature verification in dev).
func makeJWT(t *testing.T, payload map[string]interface{}) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	p := base64.RawURLEncoding.EncodeToString(payloadBytes)
	return header + "." + p + ".fakesig"
}

func TestDevStubMode_AlwaysAuthenticated(t *testing.T) {
	cfg := auth.OktaConfig{DevMode: true}
	mw := auth.Middleware(cfg)

	var gotClaims auth.Claims
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, ok := auth.ClaimsFromContext(r.Context())
		if !ok {
			t.Error("expected claims in dev stub mode")
		}
		gotClaims = c
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/cases", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if gotClaims.Role != "Admin" {
		t.Errorf("expected Admin role in dev mode, got %q", gotClaims.Role)
	}
	if gotClaims.TenantID != "dev-tenant" {
		t.Errorf("expected dev-tenant, got %q", gotClaims.TenantID)
	}
}

func TestProductionMode_MissingAuthHeader_Returns401(t *testing.T) {
	cfg := auth.OktaConfig{BaseURL: "https://example.okta.com", DevMode: false}
	mw := auth.Middleware(cfg)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called when auth fails")
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/cases", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestProductionMode_ValidJWT_ExtractsClaims(t *testing.T) {
	cfg := auth.OktaConfig{BaseURL: "https://example.okta.com", DevMode: false}
	mw := auth.Middleware(cfg)

	token := makeJWT(t, map[string]interface{}{
		"sub":             "user-123",
		"email":           "analyst@example.com",
		"aitc_role":       "Analyst",
		"aitc_tenant_id":  "tenant-abc",
	})

	var gotClaims auth.Claims
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, ok := auth.ClaimsFromContext(r.Context())
		if !ok {
			t.Error("expected claims in context")
		}
		gotClaims = c
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/cases", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if gotClaims.UserID != "user-123" {
		t.Errorf("expected user-123, got %q", gotClaims.UserID)
	}
	if gotClaims.Email != "analyst@example.com" {
		t.Errorf("expected analyst@example.com, got %q", gotClaims.Email)
	}
	if gotClaims.Role != "Analyst" {
		t.Errorf("expected Analyst role, got %q", gotClaims.Role)
	}
	if gotClaims.TenantID != "tenant-abc" {
		t.Errorf("expected tenant-abc, got %q", gotClaims.TenantID)
	}
}

func TestProductionMode_MissingSubClaim_Returns401(t *testing.T) {
	cfg := auth.OktaConfig{BaseURL: "https://example.okta.com", DevMode: false}
	mw := auth.Middleware(cfg)

	// JWT missing "sub" claim
	token := makeJWT(t, map[string]interface{}{
		"email":          "test@example.com",
		"aitc_role":      "Analyst",
		"aitc_tenant_id": "tenant-abc",
	})

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/cases", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for missing sub, got %d", rec.Code)
	}
}

func TestProductionMode_MalformedToken_Returns401(t *testing.T) {
	cfg := auth.OktaConfig{BaseURL: "https://example.okta.com", DevMode: false}
	mw := auth.Middleware(cfg)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/cases", nil)
	req.Header.Set("Authorization", "Bearer notavalidjwt")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for malformed token, got %d", rec.Code)
	}
}
