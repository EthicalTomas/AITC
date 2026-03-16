"""Action allowlist for the LLM Reasoner safety layer.

Step 0.3: The LLM may only suggest actions that are in the AITC action allowlist.
Any recommended_action outside this set is rejected before returning to the caller.
The policy validator in the controlplane is the authoritative gate — this is a
defence-in-depth check to prevent prompt-injection attacks from suggesting
disallowed actions.
"""

from __future__ import annotations

# Mirror of contracts/json/policy/action_allowlist.v1.json — keep in sync.
ALLOWED_ACTIONS: frozenset[str] = frozenset({
    "revoke_sessions",
    "mfa_stepup",
    "signon_policy_adjust",
})

# Mirror of contracts/json/policy/disallowed_actions.v1.json (Step 0.1 guardrails).
DISALLOWED_ACTIONS: frozenset[str] = frozenset({
    "delete_account",
    "disable_account",
    "isolate_device",
    "change_firewall_rule",
    "change_network_rule",
    "shutdown_production",
    "bulk_user_policy_mutation",
    "bulk_disable_users",
    "bulk_delete_users",
})


def is_allowed(action: str) -> bool:
    """Return True if the action is in the LLM-visible allowlist."""
    return action in ALLOWED_ACTIONS


def is_disallowed(action: str) -> bool:
    """Return True if the action is on the Step 0.1 permanent disallow list."""
    return action in DISALLOWED_ACTIONS


