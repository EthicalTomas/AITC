package middleware

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/ethicaltomas/aitc/internal/logging"
	"github.com/ethicaltomas/aitc/internal/tenant"
)

type contextKey int

const requestIDKey contextKey = 1

// RequestID injects a unique request ID into the context and response headers.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := r.Header.Get("X-Request-Id")
		if reqID == "" {
			reqID = uuid.New().String()
		}
		ctx := context.WithValue(r.Context(), requestIDKey, reqID)
		w.Header().Set("X-Request-Id", reqID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequestIDFromContext retrieves the request ID from context.
func RequestIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDKey).(string); ok {
		return v
	}
	return ""
}

// Logger injects structured logging into request context and logs each request.
func Logger(logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			reqID := RequestIDFromContext(r.Context())

			// Use the chi route pattern (e.g. "/api/v1/users/{id}") rather than
			// r.URL.Path to avoid logging a user-controlled value (CWE-117).
			// The route pattern is defined by application code, not the caller.
			path := "/"
			if rctx := chi.RouteContext(r.Context()); rctx != nil && rctx.RoutePattern() != "" {
				path = rctx.RoutePattern()
			}

			// Sanitize the remaining user-controlled fields before logging (CWE-117).
			reqLogger := logger.With(
				zap.String("request_id", logging.Sanitize(reqID)),
				zap.String("method", logging.Sanitize(r.Method)),
				zap.String("path", path),
				zap.String("remote_addr", logging.Sanitize(r.RemoteAddr)),
			)

			ctx := logging.WithLogger(r.Context(), reqLogger)
			wrapped := &responseWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(wrapped, r.WithContext(ctx))

			reqLogger.Info("request",
				zap.Int("status", wrapped.status),
				zap.Duration("duration", time.Since(start)),
			)
		})
	}
}

// TenantContext extracts tenant_id from a header (X-Tenant-Id) and injects it into context.
// In production this would be extracted from a validated JWT.
func TenantContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenantID := r.Header.Get("X-Tenant-Id")
		if tenantID != "" {
			ctx := tenant.WithTenant(r.Context(), tenantID)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		next.ServeHTTP(w, r)
	})
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(status int) {
	rw.status = status
	rw.ResponseWriter.WriteHeader(status)
}
