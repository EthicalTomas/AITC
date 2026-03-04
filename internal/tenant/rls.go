package tenant

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// SetRLS sets the app.tenant_id Postgres session variable for Row Level Security.
// Must be called at the start of every DB transaction or connection that queries tenant-scoped tables.
func SetRLS(ctx context.Context, tx pgx.Tx, tenantID string) error {
	if tenantID == "" {
		return fmt.Errorf("tenant ID must not be empty for RLS")
	}
	_, err := tx.Exec(ctx, "SELECT set_tenant_context($1)", tenantID)
	return err
}

