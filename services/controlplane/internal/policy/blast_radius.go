// Package policy contains the blast radius scorer for the controlplane service.
// Blast radius quantifies the potential impact of an action to bound risk (Step 0.1/0.2).
package policy

// BlastRadiusScore returns an integer 0-100 representing the potential blast radius of an action.
// Higher score = more impactful / riskier.
// This is used for monitoring and future throttling; it does NOT gate actions alone
// (disallowed list and learning mode are the primary gates).
func BlastRadiusScore(actionType string, numAffectedIdentities int) int {
	// Base score by action type
	base := baseScore(actionType)

	// Scale by breadth (each additional identity adds marginal risk)
	breadthBonus := numAffectedIdentities * 5
	if breadthBonus > 50 {
		breadthBonus = 50
	}

	score := base + breadthBonus
	if score > 100 {
		score = 100
	}
	return score
}

// baseScore returns the base blast radius for a given action type.
// Disallowed actions are assigned maximum score even though they should
// never reach this function (blocked before scoring).
func baseScore(actionType string) int {
	switch actionType {
	// Safe, targeted actions
	case "revoke_sessions":
		return 10
	case "mfa_stepup":
		return 15
	case "signon_policy_adjust":
		return 20

	// Disallowed (guardrail — should never be called, but assign max for safety)
	case "delete_account", "disable_account", "isolate_device",
		"change_firewall_rule", "change_network_rule",
		"shutdown_production", "bulk_user_policy_mutation",
		"bulk_disable_users", "bulk_delete_users":
		return 100

	default:
		// Unknown actions are treated as moderate risk
		return 50
	}
}

