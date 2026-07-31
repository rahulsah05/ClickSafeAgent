import base64
from typing import Any

import httpx

from clicksafe.core.config import Settings, get_settings


class VirusTotalClient:
    base_url = "https://www.virustotal.com/api/v3"

    def __init__(
        self,
        settings: Settings | None = None,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._transport = transport

    async def lookup_url(self, url: str) -> dict[str, Any]:
        if not self._settings.virustotal_api_key:
            return {"enabled": False, "reason": "missing_api_key"}

        url_id = self._url_identifier(url)
        headers = {"x-apikey": self._settings.virustotal_api_key}
        async with httpx.AsyncClient(
            timeout=self._settings.reputation_timeout_seconds,
            transport=self._transport,
        ) as client:
            response = await client.get(f"{self.base_url}/urls/{url_id}", headers=headers)

        if response.status_code == 404:
            return {
                "enabled": True,
                "found": False,
                "url_id": url_id,
                "summary": "URL was not found in VirusTotal URL reports.",
            }

        response.raise_for_status()
        body = self._json_object(response)
        data = body.get("data") if body is not None else None
        attributes = data.get("attributes") if isinstance(data, dict) else None
        if not isinstance(attributes, dict):
            return {
                "enabled": True,
                "found": None,
                "url_id": url_id,
                "error": "invalid_response",
            }

        stats = attributes.get("last_analysis_stats")
        if not isinstance(stats, dict):
            stats = {}
        return {
            "enabled": True,
            "found": True,
            "url_id": url_id,
            "reputation": attributes.get("reputation"),
            "last_analysis_date": attributes.get("last_analysis_date"),
            "last_analysis_stats": stats,
            "malicious": self._stat_count(stats, "malicious"),
            "suspicious": self._stat_count(stats, "suspicious"),
            "harmless": self._stat_count(stats, "harmless"),
            "undetected": self._stat_count(stats, "undetected"),
        }

    def _url_identifier(self, url: str) -> str:
        return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")

    def _json_object(self, response: httpx.Response) -> dict[str, Any] | None:
        try:
            body = response.json()
        except ValueError:
            return None
        return body if isinstance(body, dict) else None

    def _stat_count(self, stats: dict[str, Any], key: str) -> int:
        value = stats.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            return value
        return 0
