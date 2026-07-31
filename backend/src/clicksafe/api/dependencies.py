from typing import Annotated

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from clicksafe.application.services.analysis_service import AnalysisService
from clicksafe.infrastructure.database.repositories import AnalysisJobRepository
from clicksafe.infrastructure.database.session import get_db_session

DatabaseSessionDep = Annotated[AsyncSession, Depends(get_db_session)]


async def get_analysis_service(session: DatabaseSessionDep) -> AnalysisService:
    return AnalysisService(AnalysisJobRepository(session))


AnalysisServiceDep = Annotated[AnalysisService, Depends(get_analysis_service)]
