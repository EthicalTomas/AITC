"""Tests for the LLM Reasoner FastAPI endpoints.

Uses httpx.AsyncClient with the FastAPI app in ASGI test mode.
All tests run against the StubProvider so no LLM API key is required.
"""

from __future__ import annotations

import json
import os
import sys

import pytest
import pytest_asyncio

# Ensure the llm_reasoner root is importable (services/llm_reasoner is the package root).
_SERVICE_ROOT = os.path.join(os.path.dirname(__file__), "..")
if _SERVICE_ROOT not in sys.path:
    sys.path.insert(0, _SERVICE_ROOT)

# Force stub provider so tests never call an external LLM API.
os.environ.setdefault("LLM_PROVIDER", "stub")

from httpx import ASGITransport, AsyncClient  # noqa: E402

from app.api import app  # noqa: E402

# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def valid_case_payload() -> dict:
    return {
        "tenant_id": "test-tenant",
        "case_id": "case-001",
        "identity_display": "user@example.com (display only)",
        "signals": [
            {
                "signal_id": "sig-001",
                "rule_id": "impossible_travel",
                "severity": "HIGH",
                "cas_score": 0.85,
                "description": "User logged in from two countries within 1 hour.",
            }
        ],
        "recent_events_summary": "Multiple failed MFA attempts followed by success.",
        "request_id": "req-test-001",
    }


@pytest_asyncio.fixture
async def client():
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as ac:
        yield ac


# ── /healthz ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_healthz_returns_ok(client: AsyncClient) -> None:
    response = await client.get("/healthz")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"


# ── /readyz ──────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_readyz_returns_ready(client: AsyncClient) -> None:
    response = await client.get("/readyz")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ready"
    assert "provider" in body.get("detail", {})


# ── /reason/case-summary (StubProvider) ──────────────────────────────────────

@pytest.mark.asyncio
async def test_case_summary_stub_returns_advisory_only(
    client: AsyncClient, valid_case_payload: dict
) -> None:
    response = await client.post("/reason/case-summary", json=valid_case_payload)
    assert response.status_code == 200
    body = response.json()
    assert body["advisory_only"] is True
    assert body["case_id"] == "case-001"
    assert body["recommended_action"] in {"revoke_sessions", "mfa_stepup", "signon_policy_adjust"}
    assert isinstance(body["confidence"], float)
    assert 0.0 <= body["confidence"] <= 1.0


@pytest.mark.asyncio
async def test_case_summary_injects_request_id_header(
    client: AsyncClient, valid_case_payload: dict
) -> None:
    response = await client.post(
        "/reason/case-summary",
        json=valid_case_payload,
        headers={"X-Request-ID": "trace-abc"},
    )
    assert response.status_code == 200
    assert response.headers.get("X-Request-ID") == "trace-abc"


@pytest.mark.asyncio
async def test_case_summary_missing_signals_returns_422(client: AsyncClient) -> None:
    payload = {
        "tenant_id": "test-tenant",
        "case_id": "case-002",
        "identity_display": "someone",
        "signals": [],  # empty list — validation should reject
    }
    response = await client.post("/reason/case-summary", json=payload)
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_case_summary_rejects_bearer_token_in_summary(
    client: AsyncClient, valid_case_payload: dict
) -> None:
    payload = dict(valid_case_payload)
    payload["recent_events_summary"] = "Authorization: Bearer abc123xyz456=="
    response = await client.post("/reason/case-summary", json=payload)
    assert response.status_code == 400
    assert "credentials" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_case_summary_rejects_jwt_in_identity(
    client: AsyncClient, valid_case_payload: dict
) -> None:
    payload = dict(valid_case_payload)
    payload["identity_display"] = (
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    response = await client.post("/reason/case-summary", json=payload)
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_case_summary_multiple_signals(client: AsyncClient) -> None:
    payload = {
        "tenant_id": "test-tenant",
        "case_id": "case-003",
        "identity_display": "Alice (analyst display)",
        "signals": [
            {
                "signal_id": "sig-a",
                "rule_id": "impossible_travel",
                "severity": "HIGH",
                "cas_score": 0.9,
                "description": "Impossible travel detected.",
            },
            {
                "signal_id": "sig-b",
                "rule_id": "mfa_fatigue",
                "severity": "MEDIUM",
                "cas_score": 0.6,
                "description": "MFA fatigue pattern.",
            },
        ],
    }
    response = await client.post("/reason/case-summary", json=payload)
    assert response.status_code == 200
    body = response.json()
    assert body["advisory_only"] is True
