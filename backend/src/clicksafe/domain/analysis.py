from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from clicksafe.domain.enums import AnalysisStatus, Verdict


@dataclass(slots=True)
class UrlAnalysisContext:
    submitted_url: str
    normalized_url: str | None = None
    final_url: str | None = None
    redirects: list[str] = field(default_factory=list)
    html: str | None = None
    screenshot_path: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class AnalysisJob:
    id: str
    submitted_url: str
    normalized_url: str | None
    status: AnalysisStatus
    verdict: Verdict | None
    risk_score: int | None
    explanation: str | None
    evidence: dict[str, Any]
    error_message: str | None
    created_at: datetime
    updated_at: datetime
    completed_at: datetime | None
