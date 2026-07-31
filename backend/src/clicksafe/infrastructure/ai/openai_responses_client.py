from typing import Any

from openai import AsyncOpenAI

from clicksafe.core.config import Settings, get_settings


class OpenAIResponsesClient:
    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()
        self._client = AsyncOpenAI(api_key=self._settings.openai_api_key or None)

    async def assess(self, evidence: dict[str, Any]) -> dict[str, Any]:
        _ = evidence
        raise NotImplementedError("OpenAI Responses API assessment will be implemented in Phase 6.")

