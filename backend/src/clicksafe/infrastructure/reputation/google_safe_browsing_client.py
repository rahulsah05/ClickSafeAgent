from typing import Any

import httpx

from clicksafe.core.config import Settings, get_settings


class GoogleSafeBrowsingClient:
    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    def __init__(
        self,
        settings: Settings | None = None,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._transport = transport

    async def lookup_url(self, url: str) -> dict[str, Any]:
        if not self._settings.google_safe_browsing_api_key:
            return {"enabled": False, "reason": "missing_api_key"}

        request_body = {
            "client": {
                "clientId": "clicksafe",
                "clientVersion": self._settings.app_version,
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        async with httpx.AsyncClient(
            timeout=self._settings.reputation_timeout_seconds,
            transport=self._transport,
        ) as client:
            response = await client.post(
                self.endpoint,
                params={"key": self._settings.google_safe_browsing_api_key},
                json=request_body,
            )

        response.raise_for_status()
        body = self._json_object(response)
        matches = body.get("matches", []) if body is not None else None
        if not isinstance(matches, list):
            return {
                "enabled": True,
                "listed": None,
                "error": "invalid_response",
            }
        return {
            "enabled": True,
            "match_count": len(matches),
            "matches": matches,
            "listed": bool(matches),
        }

    def _json_object(self, response: httpx.Response) -> dict[str, Any] | None:
        try:
            body = response.json()
        except ValueError:
            return None
        return body if isinstance(body, dict) else None
