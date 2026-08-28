from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from clicksafe.application.agent.agent_models import AgentStep, ToolExecutionOutcome
from clicksafe.domain.analysis import UrlAnalysisContext
from clicksafe.domain.enums import EvidenceCategory, EvidenceSeverity
from clicksafe.domain.evidence import EvidenceItem
from clicksafe.infrastructure.browser.playwright_client import BrowserCapture


@dataclass(slots=True)
class AgentInvestigationState:
    analysis_id: str
    submitted_url: str
    normalized_url: str
    browser_capture: BrowserCapture | None = None
    context: UrlAnalysisContext | None = None
    technical_evidence: list[EvidenceItem] = field(default_factory=list)
    reputation_evidence: list[EvidenceItem] = field(default_factory=list)
    tools_used: list[str] = field(default_factory=list)
    steps: list[AgentStep] = field(default_factory=list)
    risk_indicators: list[str] = field(default_factory=list)
    unresolved_questions: list[str] = field(default_factory=list)
    investigation_status: str = "running"
    planner_source: str = "local_heuristic"
    planner_fallback_used: bool = False
    planner_fallback_reason: str | None = None

    @property
    def final_url(self) -> str | None:
        return self.browser_capture.final_url if self.browser_capture is not None else None

    @property
    def tool_call_count(self) -> int:
        return len(self.tools_used)

    def set_browser_capture(self, capture: BrowserCapture) -> None:
        html = self._read_html(capture.html_path)
        self.browser_capture = capture
        self.context = UrlAnalysisContext(
            submitted_url=self.submitted_url,
            normalized_url=self.normalized_url,
            final_url=capture.final_url,
            redirects=[redirect.url for redirect in capture.redirects],
            html=html,
            screenshot_path=capture.screenshot_path,
            metadata={
                "browser_redirects": capture.redirects,
                "browser_status_code": capture.status_code,
                "html_path": capture.html_path,
                "html_size_bytes": capture.html_size_bytes,
                "html_truncated": capture.html_truncated,
                "blocked_request_count": capture.blocked_request_count,
                "page_title": capture.page_title,
                "body_text_sample": capture.body_text_sample,
            },
        )

    def record_outcomes(self, outcomes: list[ToolExecutionOutcome]) -> None:
        for outcome in outcomes:
            if outcome.status == "completed":
                self.tools_used.append(outcome.tool_name)
            for item in outcome.evidence_items:
                if item.category == EvidenceCategory.REPUTATION:
                    self.reputation_evidence.append(item)
                else:
                    self.technical_evidence.append(item)
                if item.severity in {
                    EvidenceSeverity.MEDIUM,
                    EvidenceSeverity.HIGH,
                    EvidenceSeverity.CRITICAL,
                }:
                    self._append_unique(self.risk_indicators, item.title)

    def record_step(self, step: AgentStep) -> None:
        self.steps.append(step)
        self.planner_source = step.planner_source
        for indicator in step.risk_indicators:
            self._append_unique(self.risk_indicators, indicator)
        self.unresolved_questions = step.unresolved_questions[:8]

    def mark_planner_fallback(self, reason: str) -> None:
        self.planner_source = "local_heuristic"
        self.planner_fallback_used = True
        self.planner_fallback_reason = reason

    def planning_snapshot(self, available_tools: list[dict[str, Any]]) -> dict[str, Any]:
        browser = self.browser_capture
        return {
            "submitted_url": self.submitted_url,
            "normalized_url": self.normalized_url,
            "browser": {
                "captured": browser is not None,
                "final_url": browser.final_url if browser else None,
                "status_code": browser.status_code if browser else None,
                "redirect_count": len(browser.redirects) if browser else 0,
                "blocked_request_count": browser.blocked_request_count if browser else 0,
                "page_title": browser.page_title if browser else None,
                "body_text_sample": browser.body_text_sample if browser else None,
            },
            "tools_used": self.tools_used,
            "technical_evidence": [self._compact_item(item) for item in self.technical_evidence],
            "reputation_evidence": [self._compact_item(item) for item in self.reputation_evidence],
            "risk_indicators": self.risk_indicators,
            "unresolved_questions": self.unresolved_questions,
            "available_tools": available_tools,
        }

    def to_evidence(self, *, max_steps: int, max_tool_calls: int) -> dict[str, Any]:
        important_findings = [
            {
                "source": item.source,
                "severity": item.severity.value,
                "title": item.title,
                "description": item.description,
            }
            for item in [*self.technical_evidence, *self.reputation_evidence]
            if item.severity in {EvidenceSeverity.MEDIUM, EvidenceSeverity.HIGH, EvidenceSeverity.CRITICAL}
        ][:8]
        return {
            "investigation_status": self.investigation_status,
            "planner": {
                "provider": self.planner_source,
                "fallback_used": self.planner_fallback_used,
                "fallback_reason": self.planner_fallback_reason,
            },
            "steps": [step.to_evidence() for step in self.steps],
            "tools_used": self.tools_used,
            "important_findings": important_findings,
            "risk_indicators": self.risk_indicators[:12],
            "unresolved_questions": self.unresolved_questions[:8],
            "limits": {
                "max_steps": max_steps,
                "max_tool_calls": max_tool_calls,
                "steps_used": len(self.steps),
                "tool_calls_used": self.tool_call_count,
            },
        }

    def _compact_item(self, item: EvidenceItem) -> dict[str, Any]:
        signal_keys = {
            "redirect_count",
            "final_url_changed",
            "suspicious_markers",
            "form_count",
            "suspicious_form_count",
            "matched_patterns",
            "payment_method",
            "identity_destination_match",
            "suspicious_indicators",
            "reputation_status",
            "resolved",
            "has_certificate",
            "domain_age_days",
            "listed",
            "malicious",
            "suspicious",
        }
        signals = {key: item.data[key] for key in signal_keys if key in item.data}
        return {
            "source": item.source,
            "severity": item.severity.value,
            "title": item.title,
            "description": item.description,
            "signals": signals,
        }

    def _read_html(self, html_path: str) -> str:
        try:
            return Path(html_path).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return ""

    def _append_unique(self, values: list[str], value: str) -> None:
        if value and value not in values:
            values.append(value)
