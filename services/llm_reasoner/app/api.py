"""LLM Reasoner FastAPI service.

Step 0.3 guardrails (enforced here):
- No Okta/M365 credentials accepted or forwarded.
- Cannot call internal AITC services other than its own endpoint.
- Output is strict JSON matching CaseSummaryResponse schema.
- Validator (controlplane) decides if the suggested action is executed.
- All LLM output is marked advisory_only=True.

Step 0.7:
- Incoming request text is scanned for credential patterns before LLM call.
- Logs are sanitized to prevent token leakage.

SECURITY: This service has no persistent state and no outbound connections
other than to the configured LLM provider API.
"""

from __future__ import annotations

import json
import logging
import os
import time
import uuid
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from .providers.base import BaseLLMProvider
from .providers.openai import OpenAIProvider, StubProvider
from .safety.validators import (
    sanitize_for_logging,
    validate_output_action,
    validate_request_no_secrets,
)
from .schemas import CaseSummaryRequest, CaseSummaryResponse, HealthResponse

# Structured JSON logging (Step 1.3)
logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s","level":"%(levelname)s","service":"llm-reasoner","msg":%(message)s}',
)
logger = logging.getLogger("llm-reasoner")


def _log(level: str, msg: str, **fields: Any) -> None:
    """Emit a structured JSON log line. SECURITY: sanitize before logging."""
    sanitized = {k: sanitize_for_logging(str(v)) for k, v in fields.items()}
    record = json.dumps({"msg": sanitize_for_logging(msg), **sanitized})
    getattr(logger, level)(record)


def _build_provider() -> BaseLLMProvider:
    """Instantiate the LLM provider from environment configuration.

    SECURITY: API keys are read from environment variables only.
    Set LLM_PROVIDER=openai and OPENAI_API_KEY=<key> in your secrets manager.
    Default is stub (safe for local dev, never for production).
    """
    provider_name = os.environ.get("LLM_PROVIDER", "stub").lower()
    if provider_name == "openai":
        model = os.environ.get("LLM_MODEL", "gpt-4o-mini")
        return OpenAIProvider(model=model)
    _log("warning", "LLM provider not configured; using stub (advisory output only)",
         provider=provider_name)
    return StubProvider()


_SYSTEM_PROMPT = """\
You are an AI security analyst assistant for the AITC (Autonomous Identity Threat Containment) platform.
Your job is to analyse risk signals for an identity and produce a structured case summary.

RULES (non-negotiable):
1. Output ONLY valid JSON matching the schema described in the user message.
2. The "recommended_action" field MUST be one of: revoke_sessions, mfa_stepup, signon_policy_adjust.
3. Never suggest: delete_account, disable_account, isolate_device, firewall changes, or bulk mutations.
4. Do NOT include PII (email, IP addresses, phone numbers) in your output.
5. Your output is advisory only. A human analyst or policy validator will decide whether to act.
6. Do not reference or request any API credentials, tokens, or passwords.
"""


def _build_user_prompt(req: CaseSummaryRequest) -> str:
    """Construct the user-facing prompt from the request, without including raw PII."""
    signals_text = "\n".join(
        f"- [{s.severity}] {s.rule_id}: {s.description} (CAS score: {s.cas_score:.2f})"
        for s in req.signals
    )
    return (
        f"Case ID: {req.case_id}\n"
        f"Identity: {req.identity_display}\n"
        f"Recent activity summary: {req.recent_events_summary or '(none provided)'}\n\n"
        f"Risk signals:\n{signals_text}\n\n"
        'Respond with JSON in this exact format:\n'
        '{\n'
        '  "summary": "<plain-English explanation of why this case is high-risk>",\n'
        '  "recommended_action": "<one of: revoke_sessions | mfa_stepup | signon_policy_adjust>",\n'
        '  "confidence": <float 0.0-1.0>,\n'
        '  "reasoning_notes": ["<step 1>", "<step 2>", ...],\n'
        '  "model_version": "<model identifier>",\n'
        '  "advisory_only": true\n'
        '}'
    )


_provider: BaseLLMProvider = _build_provider()

app = FastAPI(
    title="AITC LLM Reasoner",
    version="1.0.0",
    description=(
        "Advisory-only LLM reasoning service. "
        "Output is never executed without analyst or policy-validator approval (Step 0.3)."
    ),
)


@app.middleware("http")
async def add_request_id(request: Request, call_next):  # type: ignore[no-untyped-def]
    """Inject X-Request-ID header for distributed tracing."""
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response


@app.get("/healthz", response_model=HealthResponse, tags=["ops"])
async def healthz() -> HealthResponse:
    """Liveness probe."""
    return HealthResponse(status="ok")


@app.get("/readyz", response_model=HealthResponse, tags=["ops"])
async def readyz() -> HealthResponse:
    """Readiness probe."""
    provider_type = type(_provider).__name__
    return HealthResponse(status="ready", detail={"provider": provider_type})


@app.post(
    "/reason/case-summary",
    response_model=CaseSummaryResponse,
    tags=["reasoning"],
    summary="Generate an advisory case summary (Step 0.3 — advisory only)",
)
async def case_summary(req: CaseSummaryRequest, request: Request) -> CaseSummaryResponse:
    """Analyse risk signals for a case and return an advisory JSON summary.

    SECURITY:
    - Request text is scanned for credential patterns before sending to the LLM.
    - LLM output is validated against the allowlist before being returned.
    - Response is always marked advisory_only=True.
    - No action is taken by this service; the controlplane validator decides.
    """
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    start = time.monotonic()

    _log("info", "case-summary request received",
         case_id=req.case_id,
         tenant_id=req.tenant_id,
         num_signals=len(req.signals),
         request_id=request_id)

    # Step 0.7: scan for leaked secrets before sending to LLM
    try:
        validate_request_no_secrets(req.recent_events_summary)
        validate_request_no_secrets(req.identity_display)
    except ValueError as exc:
        _log("warning", "secret pattern detected in request; rejecting",
             case_id=req.case_id, request_id=request_id)
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    user_prompt = _build_user_prompt(req)

    try:
        raw_output = await _provider.complete(_SYSTEM_PROMPT, user_prompt)
    except Exception as exc:  # noqa: BLE001
        _log("error", "LLM provider error",
             case_id=req.case_id, request_id=request_id, error=str(exc))
        raise HTTPException(status_code=502, detail="LLM provider error") from exc

    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError as exc:
        _log("error", "LLM returned non-JSON output",
             case_id=req.case_id, request_id=request_id)
        raise HTTPException(status_code=502, detail="LLM returned non-JSON output") from exc

    # Step 0.1 guardrail: validate recommended action
    try:
        safe_action = validate_output_action(data.get("recommended_action", ""))
    except ValueError as exc:
        _log("warning", "LLM suggested disallowed action — blocked",
             case_id=req.case_id, action=data.get("recommended_action"), request_id=request_id)
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    elapsed = time.monotonic() - start
    _log("info", "case-summary response generated",
         case_id=req.case_id,
         action=safe_action,
         confidence=data.get("confidence", 0.0),
         elapsed_s=f"{elapsed:.3f}",
         request_id=request_id)

    return CaseSummaryResponse(
        case_id=req.case_id,
        summary=data.get("summary", ""),
        recommended_action=safe_action,
        confidence=float(data.get("confidence", 0.5)),
        reasoning_notes=data.get("reasoning_notes", []),
        model_version=data.get("model_version", ""),
        advisory_only=True,
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Return a structured error without leaking internals."""
    _log("error", "unhandled exception", path=str(request.url.path), error=type(exc).__name__)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )
