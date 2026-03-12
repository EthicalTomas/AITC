// Package auth provides Okta OIDC authentication middleware with dev stub mode.
// In dev stub mode (DEV_AUTH_STUB=true or empty Okta config) every request is
// accepted as an Admin user belonging to the "dev-tenant" tenant.
package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
)

type contextKey int

const claimsKey contextKey = 1

// Claims holds the authenticated user information extracted from the JWT.
type Claims struct {
	UserID   string
	Email    string
	Role     string
	TenantID string
}

// OktaConfig holds the Okta OIDC configuration.
type OktaConfig struct {
	BaseURL string
	DevMode bool
}

// WithClaims stores Claims in the context.
func WithClaims(ctx context.Context, c Claims) context.Context {
	return context.WithValue(ctx, claimsKey, c)
}

// ClaimsFromContext retrieves Claims from the context.
// Returns (Claims{}, false) if not present.
func ClaimsFromContext(ctx context.Context) (Claims, bool) {
	c, ok := ctx.Value(claimsKey).(Claims)
	return c, ok
}

// Middleware returns an HTTP middleware that authenticates requests.
// In dev stub mode all requests are accepted as Admin / dev-tenant.
// In production mode the Authorization: Bearer token is parsed for claims.
func Middleware(cfg OktaConfig) func(http.Handler) http.Handler {
	devMode := cfg.DevMode || os.Getenv("DEV_AUTH_STUB") == "true"

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if devMode {
				ctx := WithClaims(r.Context(), Claims{
					UserID:   "dev-user",
					Email:    "dev@aitc.local",
					Role:     "Admin",
					TenantID: "dev-tenant",
				})
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			claims, err := extractClaims(r)
			if err != nil {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized: " + err.Error()})
				return
			}

			ctx := WithClaims(r.Context(), claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// extractClaims parses the Bearer token and extracts AITC-specific claims.
// SECURITY: This performs minimal JWT claim extraction without signature verification.
// In production, replace this with full OIDC verification (e.g., validate the token
// against Okta's JWKS endpoint). Until that is implemented, ensure DEV_AUTH_STUB is
// never false in an internet-facing deployment without proper network controls.
func extractClaims(r *http.Request) (Claims, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return Claims{}, fmt.Errorf("missing Authorization header")
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return Claims{}, fmt.Errorf("invalid Authorization header format")
	}

	token := strings.TrimSpace(parts[1])
	payload, err := jwtPayload(token)
	if err != nil {
		return Claims{}, fmt.Errorf("invalid token: %w", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(payload, &raw); err != nil {
		return Claims{}, fmt.Errorf("malformed token payload")
	}

	c := Claims{
		UserID:   stringClaim(raw, "sub"),
		Email:    stringClaim(raw, "email"),
		Role:     stringClaim(raw, "aitc_role"),
		TenantID: stringClaim(raw, "aitc_tenant_id"),
	}

	if c.UserID == "" {
		return Claims{}, fmt.Errorf("token missing sub claim")
	}
	if c.TenantID == "" {
		return Claims{}, fmt.Errorf("token missing aitc_tenant_id claim")
	}

	return c, nil
}

// jwtPayload extracts and base64-decodes the payload segment of a JWT.
func jwtPayload(token string) ([]byte, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("not a valid JWT structure")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	return payload, nil
}

func stringClaim(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
