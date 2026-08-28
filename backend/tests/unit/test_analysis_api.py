import pytest
from fastapi.testclient import TestClient

from clicksafe.core.config import get_settings
from clicksafe.domain.analysis import UrlAnalysisContext
from clicksafe.domain.enums import EvidenceSeverity
from clicksafe.domain.evidence import EvidenceCategory, EvidenceItem
from clicksafe.infrastructure.browser.playwright_client import (
    BrowserCapture,
    BrowserNavigationError,
    BrowserRedirect,
    PlaywrightClient,
)


class FakeTechnicalAnalyzer:
    @property
    def name(self) -> str:
        return "fake_technical"

    async def analyze(self, context: UrlAnalysisContext) -> list[EvidenceItem]:
        return [
            EvidenceItem(
                source=self.name,
                category=EvidenceCategory.TECHNICAL,
                severity=EvidenceSeverity.INFO,
                title="Fake technical evidence",
                description="Fake technical analyzer ran.",
                data={"final_url": context.final_url},
            )
        ]


class FakeReputationAnalyzer:
    @property
    def name(self) -> str:
        return "fake_reputation"

    async def analyze(self, context: UrlAnalysisContext) -> list[EvidenceItem]:
        return [
            EvidenceItem(
                source=self.name,
                category=EvidenceCategory.REPUTATION,
                severity=EvidenceSeverity.INFO,
                title="Fake reputation evidence",
                description="Fake reputation analyzer ran.",
                data={"final_url": context.final_url},
            )
        ]


class ExplodingReputationAnalyzer:
    evidence_category = EvidenceCategory.REPUTATION

    @property
    def name(self) -> str:
        return "exploding_reputation"

    async def analyze(self, context: UrlAnalysisContext) -> list[EvidenceItem]:
        _ = context
        raise RuntimeError("provider integration failed")


@pytest.fixture(autouse=True)
def fake_browser_capture(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.setenv("SCREENSHOT_DIR", str(tmp_path))
    get_settings.cache_clear()

    async def capture(
        self: PlaywrightClient,
        url: str,
        *,
        analysis_id: str | None = None,
    ) -> BrowserCapture:
        _ = self
        artifact_id = analysis_id or "test-analysis"
        html_path = tmp_path / f"{artifact_id}.html"
        screenshot_path = tmp_path / f"{artifact_id}.png"
        html_path.write_text("<html><title>Example</title></html>", encoding="utf-8")
        screenshot_path.write_bytes(b"fake-png")
        return BrowserCapture(
            final_url=url,
            redirects=[
                BrowserRedirect(
                    url="http://example.com/",
                    status_code=301,
                    location="https://example.com/",
                )
            ],
            status_code=200,
            html_path=str(html_path),
            html_size_bytes=34,
            html_truncated=False,
            screenshot_path=str(screenshot_path),
        )

    monkeypatch.setattr(PlaywrightClient, "capture", capture)
    monkeypatch.setattr(
        "clicksafe.application.services.analysis_service.create_default_analyzers",
        lambda: [FakeTechnicalAnalyzer(), FakeReputationAnalyzer()],
    )


def test_analyze_creates_completed_phase_six_job(client: TestClient) -> None:
    response = client.post("/api/v1/analyze", json={"url": "HTTPS://Example.COM:443/a#frag"})

    assert response.status_code == 200
    payload = response.json()
    assert payload["id"]
    assert payload["status"] == "completed"
    assert payload["submitted_url"] == "HTTPS://Example.COM:443/a#frag"
    assert payload["normalized_url"] == "https://example.com/a"
    assert payload["verdict"] == "Safe"
    assert payload["risk_score"] == 8
    assert payload["evidence"]["validation"]["valid"] is True
    assert payload["evidence"]["browser"]["captured"] is True
    assert payload["evidence"]["browser"]["final_url"] == "https://example.com/a"
    assert payload["evidence"]["browser"]["redirect_count"] == 1
    assert payload["evidence"]["technical_analysis"][0]["source"] == "fake_technical"
    assert payload["evidence"]["reputation"][0]["source"] == "fake_reputation"
    assert payload["evidence"]["ai"]["provider"] == "openai_responses"
    assert payload["evidence"]["ai"]["fallback_used"] is True
    assert payload["evidence"]["ai"]["reason"] == "missing_api_key"
    assert payload["evidence"]["pending_capabilities"] == []
    assert payload["evidence"]["lifecycle"]["phase"] == 8
    assert payload["evidence"]["lifecycle"]["transitions"] == [
        "requested",
        "running",
        "completed",
    ]


def test_analyze_keeps_unexpected_reputation_failures_in_reputation_evidence(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "clicksafe.application.services.analysis_service.create_default_analyzers",
        lambda: [ExplodingReputationAnalyzer()],
    )

    response = client.post("/api/v1/analyze", json={"url": "example.com"})

    assert response.status_code == 200
    evidence = response.json()["evidence"]
    assert evidence["technical_analysis"] == []
    assert evidence["reputation"][0]["source"] == "exploding_reputation"
    assert evidence["reputation"][0]["category"] == "reputation"


def test_analyze_persists_failed_policy_validation(client: TestClient) -> None:
    response = client.post("/api/v1/analyze", json={"url": "ftp://example.com"})

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "failed"
    assert payload["normalized_url"] is None
    assert payload["error_message"] == "Only HTTP and HTTPS URLs can be analyzed."


def test_analyze_persists_failed_browser_capture(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def capture(
        self: PlaywrightClient,
        url: str,
        *,
        analysis_id: str | None = None,
    ) -> BrowserCapture:
        _ = self, url, analysis_id
        raise BrowserNavigationError("Browser navigation failed.", error_code="navigation_failed")

    monkeypatch.setattr(PlaywrightClient, "capture", capture)

    response = client.post("/api/v1/analyze", json={"url": "example.com"})

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "failed"
    assert payload["normalized_url"] == "https://example.com/"
    assert payload["evidence"]["browser"]["captured"] is False
    assert payload["evidence"]["browser"]["error_code"] == "navigation_failed"


def test_get_analysis_by_id(client: TestClient) -> None:
    created_response = client.post("/api/v1/analyze", json={"url": "example.com"})
    analysis_id = created_response.json()["id"]

    response = client.get(f"/api/v1/analyses/{analysis_id}")

    assert response.status_code == 200
    assert response.json()["id"] == analysis_id
    assert response.json()["normalized_url"] == "https://example.com/"


def test_get_analysis_returns_404_for_missing_job(client: TestClient) -> None:
    response = client.get("/api/v1/analyses/not-a-real-id")

    assert response.status_code == 404


def test_get_analysis_screenshot_returns_the_captured_png(client: TestClient) -> None:
    created_response = client.post("/api/v1/analyze", json={"url": "example.com"})
    analysis_id = created_response.json()["id"]

    response = client.get(f"/api/v1/analyses/{analysis_id}/screenshot")

    assert response.status_code == 200
    assert response.headers["content-type"] == "image/png"
    assert response.content == b"fake-png"


def test_get_analysis_screenshot_rejects_a_mismatched_artifact_path(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    async def capture(
        self: PlaywrightClient,
        url: str,
        *,
        analysis_id: str | None = None,
    ) -> BrowserCapture:
        _ = self
        artifact_id = analysis_id or "test-analysis"
        html_path = tmp_path / f"{artifact_id}.html"
        unrelated_screenshot_path = tmp_path / "unrelated.png"
        html_path.write_text("<html><title>Example</title></html>", encoding="utf-8")
        unrelated_screenshot_path.write_bytes(b"unrelated-png")
        return BrowserCapture(
            final_url=url,
            redirects=[],
            status_code=200,
            html_path=str(html_path),
            html_size_bytes=34,
            html_truncated=False,
            screenshot_path=str(unrelated_screenshot_path),
        )

    monkeypatch.setattr(PlaywrightClient, "capture", capture)

    created_response = client.post("/api/v1/analyze", json={"url": "example.com"})
    analysis_id = created_response.json()["id"]

    response = client.get(f"/api/v1/analyses/{analysis_id}/screenshot")

    assert response.status_code == 404


def test_list_recent_analyses(client: TestClient) -> None:
    client.post("/api/v1/analyze", json={"url": "example.com"})

    response = client.get("/api/v1/analyses")

    assert response.status_code == 200
    assert len(response.json()) == 1


def test_analyze_rate_limit_rejects_excess_requests(client: TestClient) -> None:
    from clicksafe.api.rate_limiting import InMemorySlidingWindowRateLimiter

    client.app.state.analysis_rate_limiter = InMemorySlidingWindowRateLimiter(
        max_requests=1,
        window_seconds=60,
    )

    first_response = client.post("/api/v1/analyze", json={"url": "ftp://example.com"})
    second_response = client.post("/api/v1/analyze", json={"url": "ftp://example.com"})

    assert first_response.status_code == 200
    assert second_response.status_code == 429
    assert second_response.headers["retry-after"] == "60"


def test_rejects_request_bodies_over_the_configured_limit(client: TestClient) -> None:
    response = client.post(
        "/api/v1/analyze",
        content=b"x" * 9_000,
        headers={"content-type": "application/json", "content-length": "9000"},
    )

    assert response.status_code == 413
    assert response.json()["detail"] == "Request body exceeds the configured size limit."
