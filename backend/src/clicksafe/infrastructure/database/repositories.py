from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from clicksafe.domain.analysis import AnalysisJob
from clicksafe.domain.enums import AnalysisStatus, Verdict
from clicksafe.infrastructure.database.models import AnalysisJobModel


class AnalysisJobRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(self, submitted_url: str) -> AnalysisJob:
        now = datetime.now(UTC)
        model = AnalysisJobModel(
            id=str(uuid4()),
            submitted_url=submitted_url,
            normalized_url=None,
            status=AnalysisStatus.REQUESTED.value,
            verdict=None,
            risk_score=None,
            explanation=None,
            evidence={},
            error_message=None,
            created_at=now,
            updated_at=now,
            completed_at=None,
        )
        self._session.add(model)
        await self._session.commit()
        await self._session.refresh(model)
        return self._to_domain(model)

    async def get(self, analysis_id: str) -> AnalysisJob | None:
        model = await self._session.get(AnalysisJobModel, analysis_id)
        return self._to_domain(model) if model is not None else None

    async def list_recent(self, limit: int = 20) -> list[AnalysisJob]:
        statement = (
            select(AnalysisJobModel)
            .order_by(AnalysisJobModel.created_at.desc())
            .limit(limit)
        )
        result = await self._session.scalars(statement)
        return [self._to_domain(model) for model in result]

    async def update(
        self,
        analysis_id: str,
        *,
        normalized_url: str | None = None,
        status: AnalysisStatus | None = None,
        verdict: Verdict | None = None,
        risk_score: int | None = None,
        explanation: str | None = None,
        evidence: dict[str, Any] | None = None,
        error_message: str | None = None,
        completed_at: datetime | None = None,
    ) -> AnalysisJob | None:
        model = await self._session.get(AnalysisJobModel, analysis_id)
        if model is None:
            return None

        if normalized_url is not None:
            model.normalized_url = normalized_url
        if status is not None:
            model.status = status.value
        if verdict is not None:
            model.verdict = verdict.value
        if risk_score is not None:
            model.risk_score = risk_score
        if explanation is not None:
            model.explanation = explanation
        if evidence is not None:
            model.evidence = evidence
        if error_message is not None:
            model.error_message = error_message
        if completed_at is not None:
            model.completed_at = completed_at

        model.updated_at = datetime.now(UTC)
        await self._session.commit()
        await self._session.refresh(model)
        return self._to_domain(model)

    def _to_domain(self, model: AnalysisJobModel) -> AnalysisJob:
        return AnalysisJob(
            id=model.id,
            submitted_url=model.submitted_url,
            normalized_url=model.normalized_url,
            status=model.status_enum,
            verdict=model.verdict_enum,
            risk_score=model.risk_score,
            explanation=model.explanation,
            evidence=model.evidence,
            error_message=model.error_message,
            created_at=model.created_at,
            updated_at=model.updated_at,
            completed_at=model.completed_at,
        )
