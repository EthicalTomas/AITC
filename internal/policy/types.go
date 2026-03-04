package policy

// Allowlist holds the permitted action types.
type Allowlist struct {
	Version         string              `json:"version"`
	GlobalAllowed   []string            `json:"global_allowed"`
	TenantOverrides map[string][]string `json:"tenant_overrides"`
}

// DisallowedActions holds action types that are permanently forbidden.
// These represent guardrails that can never be bypassed.
type DisallowedActions struct {
	Version    string   `json:"version"`
	Disallowed []string `json:"disallowed"`
}
