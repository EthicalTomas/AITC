"""LLM Reasoner service entry point.

Starts the FastAPI app using uvicorn. Configuration is via environment variables:
- LLM_PROVIDER: 'openai' or 'stub' (default: stub for dev)
- LLM_MODEL: OpenAI model name (default: gpt-4o-mini)
- OPENAI_API_KEY: Required when LLM_PROVIDER=openai (load from secrets manager)
- PORT: HTTP listen port (default: 8086)
- HOST: HTTP listen host (default: 0.0.0.0)

SECURITY: Never set OPENAI_API_KEY in docker-compose for production.
Load it from AWS Secrets Manager / GCP Secret Manager / Vault at runtime.
"""

import os
import sys

# Allow running as: python cmd/llm-reasoner/main.py from repo root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

try:
    import uvicorn
except ImportError:
    print("uvicorn is not installed. Add it to services/llm_reasoner/requirements.txt.", file=sys.stderr)
    sys.exit(1)

from services.llm_reasoner.app.api import app  # noqa: E402

if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")  # nosec B104
    port = int(os.environ.get("PORT", "8086"))
    log_level = os.environ.get("LOG_LEVEL", "info").lower()

    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level=log_level,
        access_log=True,
    )
