"""Base LLM provider interface.

Step 0.3: providers have no Okta/M365 credentials and cannot call internal services.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class BaseLLMProvider(ABC):
    """Abstract base class for LLM providers used by the reasoner service."""

    @abstractmethod
    async def complete(self, system_prompt: str, user_prompt: str) -> str:
        """Send a completion request and return the raw response text.

        Args:
            system_prompt: Instruction context for the model.
            user_prompt: The case data to reason about.

        Returns:
            Raw text from the model (must be valid JSON matching the response schema).
        """


