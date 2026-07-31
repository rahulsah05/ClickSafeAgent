import base64
from typing import Any

import httpx

from clicksafe.core.config import Settings, get_settings


class VirusTotalClient:
    base_url = "https://www.virustotal.com/api/v3"

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()

    async def lookup_url(self, url: str) -> dict[str, Any]:
        if not self._settings.virustotal_api_key:
            return {"enabled": False, "reason": "missing_api_key"}

        url_id = self._url_identifier(url)
        headers = {"x-apikey": self._settings.virustotal_api_key}
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(f"{self.base_url}/urls/{url_id}", headers=headers)

        if response.status_code == 404:
            return {
                "enabled": True,
                "found": False,
                "url_id": url_id,
                "summary": "URL was not found in VirusTotal URL reports.",
            }

        response.raise_for_status()
        body = response.json()
        attributes = body.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        return {
            "enabled": True,
            "found": True,
            "url_id": url_id,
            "reputation": attributes.get("reputation"),
            "last_analysis_date": attributes.get("last_analysis_date"),
            "last_analysis_stats": stats,
            "malicious": int(stats.get("malicious") or 0),
            "suspicious": int(stats.get("suspicious") or 0),
            "harmless": int(stats.get("harmless") or 0),
            "undetected": int(stats.get("undetected") or 0),
        }

    def _url_identifier(self, url: str) -> str:
        return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")
