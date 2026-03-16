"""Tests for the LLM Reasoner input/output validators.

Covers:
- validate_request_no_secrets: blocks credential patterns
- validate_output_action: enforces allowed-action allowlist and disallowed-action list
- sanitize_for_logging: redacts secrets from log strings
"""

from __future__ import annotations

import pytest

from app.safety.validators import (
    sanitize_for_logging,
    validate_output_action,
    validate_request_no_secrets,
)


# ── validate_request_no_secrets ──────────────────────────────────────────────

class TestValidateRequestNoSecrets:
    def test_clean_text_passes(self) -> None:
        validate_request_no_secrets("The user logged in from an unusual location.")

    def test_empty_string_passes(self) -> None:
        validate_request_no_secrets("")

    def test_bearer_token_raises(self) -> None:
        with pytest.raises(ValueError, match="credentials or tokens"):
            validate_request_no_secrets("Authorization: Bearer abc123xyz456==")

    def test_jwt_raises(self) -> None:
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        with pytest.raises(ValueError, match="credentials or tokens"):
            validate_request_no_secrets(jwt)

    def test_openai_key_raises(self) -> None:
        with pytest.raises(ValueError, match="credentials or tokens"):
            validate_request_no_secrets("sk-abcdefghijklmnopqrstuvwx1234567890")

    def test_okta_ssws_raises(self) -> None:
        with pytest.raises(ValueError, match="credentials or tokens"):
            validate_request_no_secrets("SSWSABCxyz_token_value_long")

    def test_password_json_raises(self) -> None:
        with pytest.raises(ValueError, match="credentials or tokens"):
            validate_request_no_secrets('"password": "supersecret"')


# ── validate_output_action ───────────────────────────────────────────────────

class TestValidateOutputAction:
    def test_allowed_revoke_sessions(self) -> None:
        assert validate_output_action("revoke_sessions") == "revoke_sessions"

    def test_allowed_mfa_stepup(self) -> None:
        assert validate_output_action("mfa_stepup") == "mfa_stepup"

    def test_allowed_signon_policy_adjust(self) -> None:
        assert validate_output_action("signon_policy_adjust") == "signon_policy_adjust"

    def test_whitespace_stripped(self) -> None:
        assert validate_output_action("  revoke_sessions  ") == "revoke_sessions"

    def test_case_insensitive(self) -> None:
        assert validate_output_action("REVOKE_SESSIONS") == "revoke_sessions"

    def test_unknown_action_falls_back_to_safe_default(self) -> None:
        result = validate_output_action("some_unknown_action")
        assert result == "revoke_sessions"

    def test_disallowed_delete_account_raises(self) -> None:
        with pytest.raises(ValueError, match="disallowed action"):
            validate_output_action("delete_account")

    def test_disallowed_disable_account_raises(self) -> None:
        with pytest.raises(ValueError, match="disallowed action"):
            validate_output_action("disable_account")

    def test_disallowed_isolate_device_raises(self) -> None:
        with pytest.raises(ValueError, match="disallowed action"):
            validate_output_action("isolate_device")

    def test_disallowed_bulk_disable_users_raises(self) -> None:
        with pytest.raises(ValueError, match="disallowed action"):
            validate_output_action("bulk_disable_users")

    def test_disallowed_shutdown_production_raises(self) -> None:
        with pytest.raises(ValueError, match="disallowed action"):
            validate_output_action("shutdown_production")

    def test_empty_action_falls_back_to_safe_default(self) -> None:
        result = validate_output_action("")
        assert result == "revoke_sessions"


# ── sanitize_for_logging ─────────────────────────────────────────────────────

class TestSanitizeForLogging:
    def test_clean_text_unchanged(self) -> None:
        text = "User accessed the dashboard."
        assert sanitize_for_logging(text) == text

    def test_bearer_token_redacted(self) -> None:
        result = sanitize_for_logging("Authorization: Bearer abc123xyz456==")
        assert "Bearer" not in result or "[REDACTED]" in result

    def test_jwt_redacted(self) -> None:
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        result = sanitize_for_logging(jwt)
        assert "[REDACTED]" in result

    def test_openai_key_redacted(self) -> None:
        result = sanitize_for_logging("key=sk-abcdefghijklmnopqrstuvwx1234567890")
        assert "[REDACTED]" in result

    def test_empty_string(self) -> None:
        assert sanitize_for_logging("") == ""
