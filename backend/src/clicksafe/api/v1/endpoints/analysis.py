from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status

from clicksafe.api.dependencies import AnalysisServiceDep
from clicksafe.application.errors import AnalysisNotFoundError
from clicksafe.schemas.analysis import AnalysisJobResponse, AnalyzeUrlRequest

router = APIRouter()


@router.post("/analyze", response_model=AnalysisJobResponse, status_code=status.HTTP_200_OK)
async def analyze_url(
    payload: AnalyzeUrlRequest,
    service: AnalysisServiceDep,
) -> AnalysisJobResponse:
    job = await service.analyze(payload.url)
    return AnalysisJobResponse.from_domain(job)


@router.get("/analyses", response_model=list[AnalysisJobResponse])
async def list_recent_analyses(
    service: AnalysisServiceDep,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
) -> list[AnalysisJobResponse]:
    jobs = await service.list_recent(limit=limit)
    return [AnalysisJobResponse.from_domain(job) for job in jobs]


@router.get("/analyses/{analysis_id}", response_model=AnalysisJobResponse)
async def get_analysis(
    analysis_id: str,
    service: AnalysisServiceDep,
) -> AnalysisJobResponse:
    try:
        job = await service.get_analysis(analysis_id)
    except AnalysisNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return AnalysisJobResponse.from_domain(job)
