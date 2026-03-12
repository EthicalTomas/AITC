// Package rbac provides role-based access control middleware for the API service.
package rbac

import (
	"encoding/json"
	"net/http"

	"github.com/ethicaltomas/aitc/services/api/internal/auth"
)

// Role constants for AITC users.
const (
	RoleAdmin    = "Admin"
	RoleAnalyst  = "Analyst"
	RoleAuditor  = "Auditor"
	RoleReadOnly = "ReadOnly"
)

// Require returns a middleware that enforces the user has one of the allowed roles.
// Returns 401 if no claims are found, 403 if the role is not allowed.
func Require(roles ...string) func(http.Handler) http.Handler {
	allowed := make(map[string]struct{}, len(roles))
	for _, r := range roles {
		allowed[r] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := auth.ClaimsFromContext(r.Context())
			if !ok {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
				return
			}
			if _, permitted := allowed[claims.Role]; !permitted {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden: insufficient role"})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// CanWrite returns true if the role can mutate data (Admin, Analyst).
func CanWrite(role string) bool {
	return role == RoleAdmin || role == RoleAnalyst
}

// CanRead returns true if the role can read data (all roles).
func CanRead(role string) bool {
	switch role {
	case RoleAdmin, RoleAnalyst, RoleAuditor, RoleReadOnly:
		return true
	}
	return false
}

// CanAdmin returns true if the role can perform admin actions (Admin only).
func CanAdmin(role string) bool {
	return role == RoleAdmin
}

func writeJSON(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
