package rbac_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ethicaltomas/aitc/services/api/internal/auth"
	"github.com/ethicaltomas/aitc/services/api/internal/rbac"
)

func handlerWithClaims(claims auth.Claims) http.Handler {
	return auth.Middleware(auth.OktaConfig{DevMode: true})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Override claims in context via WithClaims (dev stub puts Admin/dev-tenant)
		}),
	)
}

// injectClaims returns a middleware that sets fixed claims in context.
func injectClaims(c auth.Claims) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := auth.WithClaims(r.Context(), c)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func TestRequire_AllowedRole_Passes(t *testing.T) {
	roles := []string{rbac.RoleAdmin, rbac.RoleAnalyst}

	for _, role := range roles {
		role := role
		t.Run(role, func(t *testing.T) {
			mw := rbac.Require(rbac.RoleAdmin, rbac.RoleAnalyst)
			inject := injectClaims(auth.Claims{UserID: "u1", Role: role, TenantID: "t1"})

			handler := inject(mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})))

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("role %q should be allowed, got %d", role, rec.Code)
			}
		})
	}
}

func TestRequire_ForbiddenRole_Returns403(t *testing.T) {
	mw := rbac.Require(rbac.RoleAdmin)
	inject := injectClaims(auth.Claims{UserID: "u1", Role: rbac.RoleReadOnly, TenantID: "t1"})

	handler := inject(mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called for forbidden role")
	})))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for ReadOnly on Admin-only endpoint, got %d", rec.Code)
	}
}

func TestRequire_NoClaims_Returns401(t *testing.T) {
	mw := rbac.Require(rbac.RoleReadOnly)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called without claims")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 when no claims, got %d", rec.Code)
	}
}

func TestCanWrite(t *testing.T) {
	if !rbac.CanWrite(rbac.RoleAdmin) {
		t.Error("Admin must be able to write")
	}
	if !rbac.CanWrite(rbac.RoleAnalyst) {
		t.Error("Analyst must be able to write")
	}
	if rbac.CanWrite(rbac.RoleAuditor) {
		t.Error("Auditor must NOT be able to write")
	}
	if rbac.CanWrite(rbac.RoleReadOnly) {
		t.Error("ReadOnly must NOT be able to write")
	}
}

func TestCanRead(t *testing.T) {
	for _, role := range []string{rbac.RoleAdmin, rbac.RoleAnalyst, rbac.RoleAuditor, rbac.RoleReadOnly} {
		if !rbac.CanRead(role) {
			t.Errorf("role %q should be able to read", role)
		}
	}
}

func TestCanAdmin(t *testing.T) {
	if !rbac.CanAdmin(rbac.RoleAdmin) {
		t.Error("Admin must be able to perform admin actions")
	}
	for _, role := range []string{rbac.RoleAnalyst, rbac.RoleAuditor, rbac.RoleReadOnly} {
		if rbac.CanAdmin(role) {
			t.Errorf("role %q must NOT be able to perform admin actions", role)
		}
	}
}
