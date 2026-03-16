"""Input/Output schemas for the LLM Reasoner service.

Step 0.3: All LLM output is advisory only. The validator in the controlplane
decides actions; this service only produces summaries and notes.
SECURITY: No Okta/M365 credentials are accepted or returned.
"""

from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field


class RiskSignalSummary(BaseModel):
    """Summarised risk signal passed as context to the LLM."""

    signal_id: str = Field(..., description="UUID of the risk signal")
    rule_id: str = Field(..., description="e.g. 'impossible_travel'")
    severity: str = Field(..., description="LOW | MEDIUM | HIGH | CRITICAL")
    cas_score: float = Field(..., ge=0.0, le=1.0, description="Composite Anomaly Score")
    description: str = Field(..., description="Human-readable description of the signal")


class CaseSummaryRequest(BaseModel):
    """Request payload for POST /reason/case-summary.

    SECURITY: Must not contain auth tokens, session tokens, or OAuth secrets.
    PII: email and IP are accepted but must not be echoed verbatim in the response.
    """

    tenant_id: str = Field(..., description="Tenant identifier — used for audit logging only")
    case_id: str = Field(..., description="UUID of the case being summarised")
    identity_display: str = Field(
        ...,
        description="Display label for the affected identity (NOT the raw email/UPN)",
    )
    signals: list[RiskSignalSummary] = Field(
        ...,
        min_length=1,
        description="Risk signals associated with this case",
    )
    recent_events_summary: str = Field(
        default="",
        description="Short free-text summary of recent activity (pre-redacted by caller)",
    )
    request_id: str = Field(default="", description="Correlation ID for distributed tracing")


class CaseSummaryResponse(BaseModel):
    """Response from POST /reason/case-summary.

    Step 0.3: Output is strict JSON. The caller (controlplane validator) decides
    whether to act on the recommendation — this service never triggers actions.
    """

    case_id: str
    summary: str = Field(..., description="Plain-English explanation of why this case is high-risk")
    recommended_action: str = Field(
        ...,
        description="Advisory action label (e.g. 'revoke_sessions'). Validator decides if executed.",
    )
    confidence: float = Field(..., ge=0.0, le=1.0, description="Model confidence in 0-1 range")
    reasoning_notes: list[str] = Field(
        default_factory=list,
        description="Bullet-point reasoning steps for analyst review",
    )
    model_version: str = Field(default="", description="Model identifier used to generate this output")
    # SECURITY: no action will be taken without analyst or policy-validator approval
    advisory_only: bool = Field(
        default=True,
        description="Always true — output is advisory; controlplane validator decides execution",
    )


class HealthResponse(BaseModel):
    """Health check response."""

    status: str
    detail: dict[str, Any] = Field(default_factory=dict)


