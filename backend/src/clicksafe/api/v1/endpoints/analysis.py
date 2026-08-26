from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status
from fastapi.responses import FileResponse

from clicksafe.api.dependencies import AnalysisServiceDep
from clicksafe.application.errors import AnalysisNotFoundError
from clicksafe.core.config import get_settings
from clicksafe.domain.analysis import AnalysisJob
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


@router.get("/analyses/{analysis_id}/screenshot", response_class=FileResponse)
async def get_analysis_screenshot(
    analysis_id: str,
    service: AnalysisServiceDep,
) -> FileResponse:
    try:
        job = await service.get_analysis(analysis_id)
    except AnalysisNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    screenshot_path = _get_screenshot_path(job)
    if screenshot_path is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Screenshot is not available for this analysis.",
        )

    return FileResponse(screenshot_path, media_type="image/png")


def _get_screenshot_path(job: AnalysisJob) -> Path | None:
    browser_evidence = job.evidence.get("browser")
    if not isinstance(browser_evidence, dict) or browser_evidence.get("captured") is not True:
        return None

    stored_path = browser_evidence.get("screenshot_path")
    if not isinstance(stored_path, str) or not stored_path:
        return None

    try:
        screenshot_dir = Path(get_settings().screenshot_dir).resolve()
        expected_path = (screenshot_dir / f"{job.id}.png").resolve()
        artifact_path = Path(stored_path).resolve()
        if artifact_path != expected_path or not artifact_path.is_file():
            return None
    except (OSError, RuntimeError):
        return None

    return artifact_path
