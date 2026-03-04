package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
)

// Loader loads and validates policy files.
type Loader struct {
	allowlist  *Allowlist
	disallowed *DisallowedActions
}

// LoadPolicies loads allowlist and disallowed actions from JSON files.
func LoadPolicies(allowlistPath, disallowedPath string) (*Loader, error) {
	al, err := loadAllowlist(allowlistPath)
	if err != nil {
		return nil, fmt.Errorf("load allowlist: %w", err)
	}
	da, err := loadDisallowed(disallowedPath)
	if err != nil {
		return nil, fmt.Errorf("load disallowed: %w", err)
	}
	return &Loader{allowlist: al, disallowed: da}, nil
}

func loadAllowlist(path string) (*Allowlist, error) {
	data, err := os.ReadFile(path) // #nosec G304
	if err != nil {
		return nil, err
	}
	var al Allowlist
	if err := json.Unmarshal(data, &al); err != nil {
		return nil, err
	}
	return &al, nil
}

func loadDisallowed(path string) (*DisallowedActions, error) {
	data, err := os.ReadFile(path) // #nosec G304
	if err != nil {
		return nil, err
	}
	var da DisallowedActions
	if err := json.Unmarshal(data, &da); err != nil {
		return nil, err
	}
	return &da, nil
}

// IsAllowed returns true if the action is permitted for the given tenant.
func (l *Loader) IsAllowed(tenantID, actionType string) bool {
	// Check disallowed first (hard stop)
	if slices.Contains(l.disallowed.Disallowed, actionType) {
		return false
	}
	// Check tenant override
	if overrides, ok := l.allowlist.TenantOverrides[tenantID]; ok {
		return slices.Contains(overrides, actionType)
	}
	// Fall back to global
	return slices.Contains(l.allowlist.GlobalAllowed, actionType)
}

// IsDisallowed returns true if the action is in the permanent disallow list.
func (l *Loader) IsDisallowed(actionType string) bool {
	return slices.Contains(l.disallowed.Disallowed, actionType)
}
