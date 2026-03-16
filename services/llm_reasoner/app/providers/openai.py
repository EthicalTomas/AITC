"""OpenAI provider for the LLM Reasoner.

Step 0.3: This provider holds no Okta/M365 credentials and cannot call internal
AITC services. It only calls the OpenAI API using the key from the environment.
SECURITY: API key is read from environment — never hard-coded or logged.
"""

from __future__ import annotations

import json
import os

from .base import BaseLLMProvider

try:
    import openai  # type: ignore[import-untyped]
    _OPENAI_AVAILABLE = True
except ImportError:
    _OPENAI_AVAILABLE = False


class OpenAIProvider(BaseLLMProvider):
    """Calls OpenAI chat completions API with JSON mode enabled."""

    def __init__(self, model: str = "gpt-4o-mini") -> None:
        if not _OPENAI_AVAILABLE:
            raise RuntimeError(
                "openai package is not installed. "
                "Add it to services/llm_reasoner/requirements.txt and rebuild."
            )
        api_key = os.environ.get("OPENAI_API_KEY", "")
        if not api_key:
            raise RuntimeError(
                "OPENAI_API_KEY environment variable is not set. "
                "The LLM reasoner cannot function without a valid API key. "
                "Set the key via your secrets manager (never hard-code it)."
            )
        self._client = openai.AsyncOpenAI(api_key=api_key)
        self._model = model

    async def complete(self, system_prompt: str, user_prompt: str) -> str:
        """Send chat completion request with JSON response format enforced."""
        response = await self._client.chat.completions.create(
            model=self._model,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.2,   # low temperature for deterministic, structured output
            max_tokens=1024,
        )
        content = response.choices[0].message.content or "{}"
        # Validate it is parseable JSON before returning
        json.loads(content)
        return content


class StubProvider(BaseLLMProvider):
    """Stub provider for testing and dev environments without a real LLM key.

    Returns a deterministic JSON response that satisfies the CaseSummaryResponse schema.
    NEVER use in production — set OPENAI_API_KEY and use OpenAIProvider instead.
    """

    async def complete(self, system_prompt: str, user_prompt: str) -> str:  # noqa: ARG002
        return json.dumps({
            "summary": "Stub: LLM provider not configured. This is a placeholder summary.",
            "recommended_action": "revoke_sessions",
            "confidence": 0.5,
            "reasoning_notes": [
                "No real LLM provider is configured.",
                "Set OPENAI_API_KEY and LLM_PROVIDER=openai to enable real reasoning.",
            ],
            "model_version": "stub-v0",
            "advisory_only": True,
        })


