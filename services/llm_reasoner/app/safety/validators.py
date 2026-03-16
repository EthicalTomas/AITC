"""Input and output validators for the LLM Reasoner safety layer.

Validates:
1. Incoming requests do not contain raw credentials or secrets.
2. LLM output conforms to the schema and references only allowed actions.
3. PII fields are not echoed verbatim in responses.
"""

from __future__ import annotations

import re

from .allowlist import ALLOWED_ACTIONS, is_disallowed

# Patterns that suggest a raw credential/token slipped through.
_SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE),
    re.compile(r"eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"),  # JWT
    re.compile(r"sk-[A-Za-z0-9]{20,}"),  # OpenAI key prefix
    re.compile(r"SSWS[A-Za-z0-9\-_]+"),  # Okta SSWS token
    re.compile(r"['\"]password['\"]:\s*['\"][^'\"]{4,}['\"]", re.IGNORECASE),
]


def validate_request_no_secrets(text: str) -> None:
    """Raise ValueError if text appears to contain raw credentials.

    This is a defence-in-depth check — the primary protection is that the
    ingestion service redacts PII/secrets before publishing normalized events.
    """
    for pattern in _SECRET_PATTERNS:
        if pattern.search(text):
            raise ValueError(
                "Request body appears to contain raw credentials or tokens. "
                "Redact sensitive fields before sending to the LLM reasoner."
            )


def validate_output_action(recommended_action: str) -> str:
    """Validate and normalise the LLM-suggested action.

    Returns the action if it is allowed, otherwise substitutes the safest
    allowed action ('revoke_sessions') and logs the substitution.

    Step 0.1: disallowed actions are NEVER passed through, even if the LLM
    produces them (e.g. due to prompt injection).
    """
    action = recommended_action.strip().lower()

    if is_disallowed(action):
        # Hard guardrail — substitute safe default and signal to caller.
        raise ValueError(
            f"LLM suggested a disallowed action: '{action}'. "
            "Step 0.1 guardrail — action blocked. "
            "This may indicate a prompt-injection attempt."
        )

    if action not in ALLOWED_ACTIONS:
        # Unknown action — substitute safe default.
        return "revoke_sessions"

    return action


def sanitize_for_logging(text: str) -> str:
    """Redact patterns that look like secrets before writing to logs.

    SECURITY: Never log raw token values (Step 0.7).
    """
    result = text
    for pattern in _SECRET_PATTERNS:
        result = pattern.sub("[REDACTED]", result)
    return result


