// Package policy contains tenant-override helpers for the controlplane service.
// Tenant overrides allow specific tenants to expand or restrict the global allowlist
// within the bounds of the Step 0.1 disallowed list.
package policy

import (
	"encoding/json"
	"fmt"
	"os"
)

// TenantOverrides holds per-tenant allowlist additions (loaded from config).
type TenantOverrides struct {
	// Overrides maps tenant_id → list of additionally allowed action types.
	// These supplement (not replace) the global allowlist.
	Overrides map[string][]string `json:"overrides"`
}

// LoadTenantOverrides loads per-tenant overrides from a JSON file.
// The file is optional; if path is empty, an empty TenantOverrides is returned.
func LoadTenantOverrides(path string) (*TenantOverrides, error) {
	if path == "" {
		return &TenantOverrides{Overrides: map[string][]string{}}, nil
	}
	data, err := os.ReadFile(path) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("load tenant overrides: %w", err)
	}
	var to TenantOverrides
	if err := json.Unmarshal(data, &to); err != nil {
		return nil, fmt.Errorf("parse tenant overrides: %w", err)
	}
	if to.Overrides == nil {
		to.Overrides = map[string][]string{}
	}
	return &to, nil
}

// For returns additional allowed action types for the given tenant.
// Returns nil if the tenant has no overrides.
func (to *TenantOverrides) For(tenantID string) []string {
	if to == nil {
		return nil
	}
	return to.Overrides[tenantID]
}

