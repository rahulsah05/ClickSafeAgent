import json
from typing import Any

import httpx
import pytest

from clicksafe.analyzers.reputation import ReputationAnalyzer
from clicksafe.application.services.analysis_service import create_default_analyzers
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


class FailingReputationClient:
    def __init__(self, error: Exception) -> None:
        self._error = error

    async def lookup_url(self, url: str) -> dict[str, Any]:
        _ = url
        raise self._error


def analysis_context(*, final_url: str = "https://example.com/") -> UrlAnalysisContext:
    return UrlAnalysisContext(
        submitted_url="https://example.com",
        normalized_url="https://example.com/",
        final_url=final_url,
    )


async def test_reputation_analyzer_flags_listed_urls() -> None:
    analyzer = ReputationAnalyzer(
        virustotal_client=FakeReputationClient({"enabled": True, "malicious": 1}),
        google_safe_browsing_client=FakeReputationClient({"enabled": True, "listed": True}),
    )

    evidence = await analyzer.analyze(
        analysis_context()
    )

    assert evidence[0].severity == EvidenceSeverity.CRITICAL
    assert evidence[0].data["virustotal"]["malicious"] == 1
    assert evidence[0].data["google_safe_browsing"]["listed"] is True


@pytest.mark.parametrize(
    ("virustotal_result", "safe_browsing_result", "expected_severity"),
    [
        ({"enabled": True}, {"enabled": True, "listed": False}, EvidenceSeverity.INFO),
        ({"enabled": True, "suspicious": 2}, {"enabled": True}, EvidenceSeverity.HIGH),
        ({"enabled": True, "malicious": 1}, {"enabled": True}, EvidenceSeverity.CRITICAL),
    ],
)
async def test_reputation_analyzer_assigns_severity_from_provider_results(
    virustotal_result: dict[str, Any],
    safe_browsing_result: dict[str, Any],
    expected_severity: EvidenceSeverity,
) -> None:
    analyzer = ReputationAnalyzer(
        virustotal_client=FakeReputationClient(virustotal_result),
        google_safe_browsing_client=FakeReputationClient(safe_browsing_result),
    )

    evidence = await analyzer.analyze(analysis_context(final_url="https://final.example/path"))

    assert evidence[0].severity == expected_severity
    assert evidence[0].data["url"] == "https://final.example/path"


async def test_reputation_analyzer_keeps_available_provider_result_on_timeout() -> None:
    analyzer = ReputationAnalyzer(
        virustotal_client=FailingReputationClient(httpx.ReadTimeout("timed out")),
        google_safe_browsing_client=FakeReputationClient({"enabled": True, "listed": True}),
    )

    evidence = await analyzer.analyze(analysis_context())

    assert evidence[0].severity == EvidenceSeverity.CRITICAL
    assert evidence[0].data["virustotal"] == {"enabled": True, "error": "timeout"}
    assert evidence[0].data["google_safe_browsing"]["listed"] is True


async def test_reputation_analyzer_isolates_unexpected_provider_errors() -> None:
    analyzer = ReputationAnalyzer(
        virustotal_client=FailingReputationClient(RuntimeError("unexpected")),
        google_safe_browsing_client=FakeReputationClient({"enabled": True, "listed": False}),
    )

    evidence = await analyzer.analyze(analysis_context())

    assert evidence[0].severity == EvidenceSeverity.INFO
    assert evidence[0].data["virustotal"] == {
        "enabled": True,
        "error": "unexpected_error",
        "reason": "RuntimeError",
    }


async def test_reputation_analyzer_records_provider_http_status_errors() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, request=request)

    analyzer = ReputationAnalyzer(
        virustotal_client=VirusTotalClient(
            Settings(virustotal_api_key="test-key"),
            transport=httpx.MockTransport(handler),
        ),
        google_safe_browsing_client=FakeReputationClient({"enabled": True, "listed": False}),
    )

    evidence = await analyzer.analyze(analysis_context())

    assert evidence[0].data["virustotal"] == {
        "enabled": True,
        "error": "http_status_error",
        "status_code": 429,
    }


def test_virustotal_url_identifier_uses_unpadded_urlsafe_base64() -> None:
    client = VirusTotalClient(Settings(virustotal_api_key="test-key"))

    assert client._url_identifier("https://example.com/") == "aHR0cHM6Ly9leGFtcGxlLmNvbS8"


async def test_virustotal_missing_key_skips_lookup() -> None:
    client = VirusTotalClient(Settings(virustotal_api_key=""))

    assert await client.lookup_url("https://example.com/") == {
        "enabled": False,
        "reason": "missing_api_key",
    }


async def test_virustotal_requests_url_report_and_parses_statistics() -> None:
    observed: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        observed["url"] = str(request.url)
        observed["api_key"] = request.headers["x-apikey"]
        observed["timeout"] = request.extensions["timeout"]
        return httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "reputation": -5,
                        "last_analysis_date": 1_700_000_000,
                        "last_analysis_stats": {
                            "malicious": 2,
                            "suspicious": 1,
                            "harmless": 3,
                            "undetected": 4,
                        },
                    }
                }
            },
            request=request,
        )

    client = VirusTotalClient(
        Settings(virustotal_api_key="test-key", reputation_timeout_seconds=7.5),
        transport=httpx.MockTransport(handler),
    )

    result = await client.lookup_url("https://example.com/")

    assert observed["url"].endswith("/api/v3/urls/aHR0cHM6Ly9leGFtcGxlLmNvbS8")
    assert observed["api_key"] == "test-key"
    assert observed["timeout"]["read"] == 7.5
    assert result == {
        "enabled": True,
        "found": True,
        "url_id": "aHR0cHM6Ly9leGFtcGxlLmNvbS8",
        "reputation": -5,
        "last_analysis_date": 1_700_000_000,
        "last_analysis_stats": {
            "malicious": 2,
            "suspicious": 1,
            "harmless": 3,
            "undetected": 4,
        },
        "malicious": 2,
        "suspicious": 1,
        "harmless": 3,
        "undetected": 4,
    }


async def test_virustotal_reports_missing_url_without_raising() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, request=request)

    client = VirusTotalClient(
        Settings(virustotal_api_key="test-key"),
        transport=httpx.MockTransport(handler),
    )

    result = await client.lookup_url("https://example.com/")

    assert result["enabled"] is True
    assert result["found"] is False
    assert result["summary"] == "URL was not found in VirusTotal URL reports."


async def test_virustotal_returns_structured_result_for_malformed_success_response() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"not-json", request=request)

    client = VirusTotalClient(
        Settings(virustotal_api_key="test-key"),
        transport=httpx.MockTransport(handler),
    )

    result = await client.lookup_url("https://example.com/")

    assert result["enabled"] is True
    assert result["found"] is None
    assert result["error"] == "invalid_response"


async def test_virustotal_ignores_invalid_analysis_stat_values() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": "not-a-number",
                            "suspicious": True,
                            "harmless": -1,
                            "undetected": 4,
                        }
                    }
                }
            },
            request=request,
        )

    client = VirusTotalClient(
        Settings(virustotal_api_key="test-key"),
        transport=httpx.MockTransport(handler),
    )

    result = await client.lookup_url("https://example.com/")

    assert result["malicious"] == 0
    assert result["suspicious"] == 0
    assert result["harmless"] == 0
    assert result["undetected"] == 4


async def test_google_safe_browsing_missing_key_skips_lookup() -> None:
    client = GoogleSafeBrowsingClient(Settings(google_safe_browsing_api_key=""))

    assert await client.lookup_url("https://example.com/") == {
        "enabled": False,
        "reason": "missing_api_key",
    }


async def test_google_safe_browsing_posts_lookup_request_and_parses_matches() -> None:
    observed: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        observed["method"] = request.method
        observed["api_key"] = request.url.params["key"]
        observed["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "matches": [
                    {
                        "threatType": "SOCIAL_ENGINEERING",
                        "platformType": "ANY_PLATFORM",
                        "threatEntryType": "URL",
                        "threat": {"url": "https://example.com/"},
                        "cacheDuration": "300s",
                    }
                ]
            },
            request=request,
        )

    client = GoogleSafeBrowsingClient(
        Settings(google_safe_browsing_api_key="google-key", app_version="1.2.3"),
        transport=httpx.MockTransport(handler),
    )

    result = await client.lookup_url("https://example.com/")

    assert observed["method"] == "POST"
    assert observed["api_key"] == "google-key"
    assert observed["body"]["client"] == {
        "clientId": "clicksafe",
        "clientVersion": "1.2.3",
    }
    assert observed["body"]["threatInfo"]["threatEntries"] == [
        {"url": "https://example.com/"}
    ]
    assert result["enabled"] is True
    assert result["listed"] is True
    assert result["match_count"] == 1
    assert result["matches"][0]["threatType"] == "SOCIAL_ENGINEERING"


async def test_google_safe_browsing_returns_safe_result_for_empty_response() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={}, request=request)

    client = GoogleSafeBrowsingClient(
        Settings(google_safe_browsing_api_key="google-key"),
        transport=httpx.MockTransport(handler),
    )

    assert await client.lookup_url("https://example.com/") == {
        "enabled": True,
        "match_count": 0,
        "matches": [],
        "listed": False,
    }


async def test_google_safe_browsing_returns_structured_result_for_malformed_response() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"matches": "unexpected"}, request=request)

    client = GoogleSafeBrowsingClient(
        Settings(google_safe_browsing_api_key="google-key"),
        transport=httpx.MockTransport(handler),
    )

    assert await client.lookup_url("https://example.com/") == {
        "enabled": True,
        "listed": None,
        "error": "invalid_response",
    }


def test_default_analyzers_include_reputation_analyzer() -> None:
    assert any(isinstance(analyzer, ReputationAnalyzer) for analyzer in create_default_analyzers())
