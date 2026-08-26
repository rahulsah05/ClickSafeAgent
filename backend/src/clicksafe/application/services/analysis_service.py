import asyncio
from collections.abc import Iterable, Sequence
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from clicksafe.analyzers.base import Analyzer
from clicksafe.analyzers.dns import DnsAnalyzer
from clicksafe.analyzers.forms import FormsAnalyzer
from clicksafe.analyzers.html import HtmlAnalyzer
from clicksafe.analyzers.javascript import JavaScriptAnalyzer
from clicksafe.analyzers.metadata import MetadataAnalyzer
from clicksafe.analyzers.redirects import RedirectAnalyzer
from clicksafe.analyzers.reputation import ReputationAnalyzer
from clicksafe.analyzers.ssl import SslAnalyzer
from clicksafe.analyzers.whois import WhoisAnalyzer
from clicksafe.application.errors import AnalysisNotFoundError, UrlValidationError
from clicksafe.application.services.url_validation import UrlValidationService
from clicksafe.domain.analysis import AnalysisJob, UrlAnalysisContext
from clicksafe.domain.enums import AnalysisStatus, EvidenceSeverity, Verdict
from clicksafe.domain.evidence import EvidenceCategory, EvidenceItem
from clicksafe.infrastructure.ai.openai_responses_client import OpenAIResponsesClient
from clicksafe.infrastructure.browser.playwright_client import (
    BrowserCapture,
    BrowserCaptureError,
    PlaywrightClient,
)
from clicksafe.infrastructure.database.repositories import AnalysisJobRepository


class BrowserCaptureClient(Protocol):
    async def capture(self, url: str, *, analysis_id: str | None = None) -> BrowserCapture:
        ...


class AIVerdictClient(Protocol):
    async def assess(self, evidence: dict[str, Any]) -> dict[str, Any]:
        ...


def create_default_analyzers() -> list[Analyzer]:
    return [
        RedirectAnalyzer(),
        HtmlAnalyzer(),
        MetadataAnalyzer(),
        FormsAnalyzer(),
        JavaScriptAnalyzer(),
        DnsAnalyzer(),
        SslAnalyzer(),
        WhoisAnalyzer(),
        ReputationAnalyzer(),
    ]


class AnalysisService:
    def __init__(
        self,
        repository: AnalysisJobRepository,
        url_validation_service: UrlValidationService | None = None,
        browser_client: BrowserCaptureClient | None = None,
        analyzers: Sequence[Analyzer] | None = None,
        ai_client: AIVerdictClient | None = None,
    ) -> None:
        self._repository = repository
        self._url_validation_service = url_validation_service or UrlValidationService()
        self._browser_client = browser_client or PlaywrightClient()
        self._analyzers = list(analyzers) if analyzers is not None else create_default_analyzers()
        self._ai_client = ai_client or OpenAIResponsesClient()

    async def analyze(self, url: str) -> AnalysisJob:
        job = await self._repository.create(submitted_url=url)
        normalized_url_value: str | None = None

        try:
            normalized_url = self._url_validation_service.normalize(url)
            normalized_url_value = normalized_url.normalized
            running_job = await self._repository.update(
                job.id,
                normalized_url=normalized_url_value,
                status=AnalysisStatus.RUNNING,
                evidence=self._build_running_evidence(normalized_url_value),
            )
            if running_job is None:
                raise AnalysisNotFoundError(f"Analysis job {job.id} disappeared during processing.")

            browser_capture = await self._browser_client.capture(
                normalized_url_value,
                analysis_id=job.id,
            )
            html = self._read_html_artifact(browser_capture.html_path)
            analysis_context = UrlAnalysisContext(
                submitted_url=url,
                normalized_url=normalized_url_value,
                final_url=browser_capture.final_url,
                redirects=[redirect.url for redirect in browser_capture.redirects],
                html=html,
                screenshot_path=browser_capture.screenshot_path,
                metadata={
                    "browser_redirects": browser_capture.redirects,
                    "browser_status_code": browser_capture.status_code,
                    "html_path": browser_capture.html_path,
                    "html_size_bytes": browser_capture.html_size_bytes,
                    "html_truncated": browser_capture.html_truncated,
                },
            )
            analyzer_items = await self._run_analyzers(analysis_context)

            evidence = self._build_phase_six_evidence(
                submitted_url=url,
                normalized_url=normalized_url_value,
                scheme=normalized_url.scheme,
                hostname=normalized_url.hostname,
                port=normalized_url.port,
                browser_capture=browser_capture,
                analyzer_items=analyzer_items,
            )
            ai_assessment = await self._assess_evidence(evidence)
            evidence["ai"] = ai_assessment
            evidence["pending_capabilities"] = []
            verdict = Verdict(str(ai_assessment["verdict"]))
            risk_score = int(ai_assessment["risk_score"])
            completed_job = await self._repository.update(
                job.id,
                status=AnalysisStatus.COMPLETED,
                verdict=verdict,
                risk_score=risk_score,
                evidence=evidence,
                explanation=str(ai_assessment["explanation"]),
                completed_at=datetime.now(UTC),
            )
            if completed_job is None:
                raise AnalysisNotFoundError(f"Analysis job {job.id} disappeared during completion.")
            return completed_job
        except BrowserCaptureError as exc:
            failed_job = await self._repository.update(
                job.id,
                status=AnalysisStatus.FAILED,
                evidence={
                    "validation": {
                        "submitted_url": url,
                        "normalized_url": normalized_url_value,
                        "valid": True,
                    },
                    "browser": {
                        "captured": False,
                        "error_code": exc.error_code,
                        "reason": str(exc),
                    },
                    "lifecycle": {
                    "phase": 6,
                        "status": AnalysisStatus.FAILED.value,
                        "transitions": [
                            AnalysisStatus.REQUESTED.value,
                            AnalysisStatus.RUNNING.value,
                            AnalysisStatus.FAILED.value,
                        ],
                    },
                },
                error_message=str(exc),
                completed_at=datetime.now(UTC),
            )
            if failed_job is None:
                raise AnalysisNotFoundError(
                    f"Analysis job {job.id} disappeared during browser failure."
                ) from exc
            return failed_job
        except UrlValidationError as exc:
            failed_job = await self._repository.update(
                job.id,
                status=AnalysisStatus.FAILED,
                evidence={
                    "validation": {
                        "submitted_url": url,
                        "valid": False,
                        "reason": str(exc),
                    },
                    "lifecycle": {
                        "phase": 6,
                        "status": AnalysisStatus.FAILED.value,
                        "transitions": [
                            AnalysisStatus.REQUESTED.value,
                            AnalysisStatus.FAILED.value,
                        ],
                    },
                },
                error_message=str(exc),
                completed_at=datetime.now(UTC),
            )
            if failed_job is None:
                raise AnalysisNotFoundError(
                    f"Analysis job {job.id} disappeared during failure."
                ) from exc
            return failed_job

    async def get_analysis(self, analysis_id: str) -> AnalysisJob:
        job = await self._repository.get(analysis_id)
        if job is None:
            raise AnalysisNotFoundError(f"Analysis job {analysis_id} was not found.")
        return job

    async def list_recent(self, limit: int = 20) -> list[AnalysisJob]:
        return await self._repository.list_recent(limit=limit)

    def _build_running_evidence(self, normalized_url: str) -> dict[str, Any]:
        return {
            "lifecycle": {
                "phase": 6,
                "status": AnalysisStatus.RUNNING.value,
                "normalized_url": normalized_url,
            }
        }

    def _build_phase_six_evidence(
        self,
        *,
        submitted_url: str,
        normalized_url: str,
        scheme: str,
        hostname: str,
        port: int | None,
        browser_capture: BrowserCapture,
        analyzer_items: list[EvidenceItem],
    ) -> dict[str, Any]:
        return {
            "validation": {
                "submitted_url": submitted_url,
                "normalized_url": normalized_url,
                "valid": True,
                "scheme": scheme,
                "hostname": hostname,
                "port": port,
                "fragment_removed": "#" in submitted_url,
            },
            "browser": {
                "captured": True,
                "final_url": browser_capture.final_url,
                "status_code": browser_capture.status_code,
                "redirect_count": len(browser_capture.redirects),
                "redirects": [asdict(redirect) for redirect in browser_capture.redirects],
                "screenshot_path": browser_capture.screenshot_path,
                "html_path": browser_capture.html_path,
                "html_size_bytes": browser_capture.html_size_bytes,
                "html_truncated": browser_capture.html_truncated,
            },
            "lifecycle": {
                "phase": 6,
                "status": AnalysisStatus.COMPLETED.value,
                "transitions": [
                    AnalysisStatus.REQUESTED.value,
                    AnalysisStatus.RUNNING.value,
                    AnalysisStatus.COMPLETED.value,
                ],
            },
            "technical_analysis": self._serialize_evidence_items(
                item for item in analyzer_items if item.category == EvidenceCategory.TECHNICAL
            ),
            "reputation": self._serialize_evidence_items(
                item for item in analyzer_items if item.category == EvidenceCategory.REPUTATION
            ),
            "pending_capabilities": ["openai_responses_api_verdict"],
        }

    async def _assess_evidence(self, evidence: dict[str, Any]) -> dict[str, Any]:
        try:
            return await self._ai_client.assess(evidence)
        except Exception as exc:
            return {
                "provider": "openai_responses",
                "enabled": False,
                "status": "fallback",
                "fallback_used": True,
                "model": None,
                "response_id": None,
                "reason": type(exc).__name__,
                "verdict": Verdict.SUSPICIOUS.value,
                "risk_score": 55,
                "confidence": 0.35,
                "explanation": (
                    "AI verdict generation failed unexpectedly, so ClickSafe returned a "
                    "conservative suspicious verdict."
                ),
                "recommended_action": (
                    "Avoid entering credentials or sensitive data unless manually verified."
                ),
                "evidence_weights": [
                    {
                        "source": "ai_error",
                        "severity": EvidenceSeverity.MEDIUM.value,
                        "weight": 55,
                        "reason": "AI assessment failed during scan completion.",
                    }
                ],
            }

    async def _run_analyzers(self, context: UrlAnalysisContext) -> list[EvidenceItem]:
        results = await asyncio.gather(
            *(self._run_analyzer(analyzer, context) for analyzer in self._analyzers),
        )
        return [item for analyzer_items in results for item in analyzer_items]

    async def _run_analyzer(
        self,
        analyzer: Analyzer,
        context: UrlAnalysisContext,
    ) -> list[EvidenceItem]:
        try:
            return await analyzer.analyze(context)
        except Exception as exc:
            category = getattr(analyzer, "evidence_category", EvidenceCategory.TECHNICAL)
            if not isinstance(category, EvidenceCategory):
                category = EvidenceCategory.TECHNICAL
            return [
                EvidenceItem(
                    source=analyzer.name,
                    category=category,
                    severity=EvidenceSeverity.LOW,
                    title=f"{analyzer.name} analyzer failed",
                    description="Analyzer execution failed and was isolated from the scan.",
                    data={"error": type(exc).__name__},
                )
            ]

    def _serialize_evidence_items(self, items: Iterable[EvidenceItem]) -> list[dict[str, Any]]:
        return [
            {
                "source": item.source,
                "category": item.category.value,
                "severity": item.severity.value,
                "title": item.title,
                "description": item.description,
                "data": item.data,
            }
            for item in items
        ]

    def _read_html_artifact(self, html_path: str) -> str:
        try:
            return Path(html_path).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return ""
