import asyncio
from typing import Any, Protocol

import httpx

from clicksafe.core.config import Settings, get_settings
from clicksafe.domain.analysis import UrlAnalysisContext
from clicksafe.domain.enums import EvidenceSeverity
from clicksafe.domain.evidence import EvidenceCategory, EvidenceItem
from clicksafe.infrastructure.reputation.google_safe_browsing_client import GoogleSafeBrowsingClient
from clicksafe.infrastructure.reputation.virustotal_client import VirusTotalClient


class ReputationClient(Protocol):
    async def lookup_url(self, url: str) -> dict[str, Any]:
        ...


class ReputationAnalyzer:
    evidence_category = EvidenceCategory.REPUTATION

    def __init__(
        self,
        virustotal_client: ReputationClient | None = None,
        google_safe_browsing_client: ReputationClient | None = None,
        settings: Settings | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._virustotal_client = virustotal_client or VirusTotalClient(self._settings)
        self._google_safe_browsing_client = (
            google_safe_browsing_client or GoogleSafeBrowsingClient(self._settings)
        )

    @property
    def name(self) -> str:
        return "reputation"

    async def analyze(self, context: UrlAnalysisContext) -> list[EvidenceItem]:
        url = context.final_url or context.normalized_url or context.submitted_url
        virustotal_result, safe_browsing_result = await asyncio.gather(
            self._lookup(self._virustotal_client, url),
            self._lookup(self._google_safe_browsing_client, url),
        )

        vt_malicious = self._positive_count(virustotal_result, "malicious")
        vt_suspicious = self._positive_count(virustotal_result, "suspicious")
        google_listed = bool(safe_browsing_result.get("listed"))
        severity = EvidenceSeverity.INFO
        if google_listed or vt_malicious:
            severity = EvidenceSeverity.CRITICAL
        elif vt_suspicious:
            severity = EvidenceSeverity.HIGH

        return [
            EvidenceItem(
                source=self.name,
                category=EvidenceCategory.REPUTATION,
                severity=severity,
                title="Reputation services checked",
                description=(
                    "VirusTotal and Google Safe Browsing were checked when API keys were "
                    "configured."
                ),
                data={
                    "url": url,
                    "virustotal": virustotal_result,
                    "google_safe_browsing": safe_browsing_result,
                },
            )
        ]

    async def _lookup(self, client: ReputationClient, url: str) -> dict[str, Any]:
        try:
            return await client.lookup_url(url)
        except httpx.TimeoutException:
            return {
                "enabled": True,
                "error": "timeout",
            }
        except httpx.HTTPStatusError as exc:
            return {
                "enabled": True,
                "error": "http_status_error",
                "status_code": exc.response.status_code,
            }
        except httpx.HTTPError as exc:
            return {
                "enabled": True,
                "error": "http_error",
                "reason": type(exc).__name__,
            }
        except Exception as exc:
            return {
                "enabled": True,
                "error": "unexpected_error",
                "reason": type(exc).__name__,
            }

    def _positive_count(self, result: dict[str, Any], key: str) -> int:
        value = result.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and value > 0:
            return value
        return 0
