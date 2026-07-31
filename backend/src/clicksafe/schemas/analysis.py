from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from clicksafe.domain.analysis import AnalysisJob
from clicksafe.domain.enums import AnalysisStatus, Verdict


class AnalyzeUrlRequest(BaseModel):
    url: str = Field(
        min_length=1,
        max_length=2048,
        description="URL to inspect. HTTP and HTTPS URLs are supported.",
    )


class AnalysisJobResponse(BaseModel):
    id: str
    submitted_url: str
    normalized_url: str | None
    status: AnalysisStatus
    verdict: Verdict | None
    risk_score: int | None = Field(default=None, ge=0, le=100)
    explanation: str | None
    evidence: dict[str, Any]
    error_message: str | None
    created_at: datetime
    updated_at: datetime
    completed_at: datetime | None

    model_config = ConfigDict(use_enum_values=True)

    @classmethod
    def from_domain(cls, job: AnalysisJob) -> "AnalysisJobResponse":
        return cls(
            id=job.id,
            submitted_url=job.submitted_url,
            normalized_url=job.normalized_url,
            status=job.status,
            verdict=job.verdict,
            risk_score=job.risk_score,
            explanation=job.explanation,
            evidence=job.evidence,
            error_message=job.error_message,
            created_at=job.created_at,
            updated_at=job.updated_at,
            completed_at=job.completed_at,
        )


class AnalysisVerdictResponse(BaseModel):
    verdict: Verdict
    risk_score: int = Field(ge=0, le=100)
    explanation: str
    evidence: dict[str, object]
