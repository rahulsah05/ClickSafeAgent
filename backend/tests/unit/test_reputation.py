from typing import Any

from clicksafe.analyzers.reputation import ReputationAnalyzer
from clicksafe.core.config import Settings
from clicksafe.domain.analysis import UrlAnalysisContext
from clicksafe.domain.enums import EvidenceSeverity
from clicksafe.infrastructure.reputation.google_safe_browsing_client import GoogleSafeBrowsingClient
from clicksafe.infrastructure.reputation.virustotal_client import VirusTotalClient


class FakeReputationClient:
    def __init__(self, result: dict[str, Any]) -> None:
        self._result = result

    async def lookup_url(self, url: str) -> dict[str, Any]:
        _ = url
        return self._result


async def test_reputation_analyzer_flags_listed_urls() -> None:
    analyzer = ReputationAnalyzer(
        virustotal_client=FakeReputationClient({"enabled": True, "malicious": 1}),
        google_safe_browsing_client=FakeReputationClient({"enabled": True, "listed": True}),
    )

    evidence = await analyzer.analyze(
        UrlAnalysisContext(
            submitted_url="https://example.com",
            normalized_url="https://example.com/",
            final_url="https://example.com/",
        )
    )

    assert evidence[0].severity == EvidenceSeverity.CRITICAL
    assert evidence[0].data["virustotal"]["malicious"] == 1
    assert evidence[0].data["google_safe_browsing"]["listed"] is True


def test_virustotal_url_identifier_uses_unpadded_urlsafe_base64() -> None:
    client = VirusTotalClient(Settings(virustotal_api_key="test-key"))

    assert client._url_identifier("https://example.com/") == "aHR0cHM6Ly9leGFtcGxlLmNvbS8"


async def test_virustotal_missing_key_skips_lookup() -> None:
    client = VirusTotalClient(Settings(virustotal_api_key=""))

    assert await client.lookup_url("https://example.com/") == {
        "enabled": False,
        "reason": "missing_api_key",
    }


async def test_google_safe_browsing_missing_key_skips_lookup() -> None:
    client = GoogleSafeBrowsingClient(Settings(google_safe_browsing_api_key=""))

    assert await client.lookup_url("https://example.com/") == {
        "enabled": False,
        "reason": "missing_api_key",
    }
