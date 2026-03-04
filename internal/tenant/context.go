package tenant

import "context"

type contextKey int

const tenantKey contextKey = 0

// WithTenant stores the tenant ID in the context.
func WithTenant(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, tenantKey, tenantID)
}

// TenantFromContext retrieves the tenant ID from the context.
// Returns ("", false) if not set.
func TenantFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(tenantKey).(string)
	return v, ok && v != ""
}

// MustTenantFromContext retrieves the tenant ID or panics.
// Use only in handlers where tenant is guaranteed to be set.
func MustTenantFromContext(ctx context.Context) string {
	v, ok := TenantFromContext(ctx)
	if !ok {
		panic("tenant ID not in context")
	}
	return v
}

