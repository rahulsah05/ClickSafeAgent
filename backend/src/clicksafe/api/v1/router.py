from fastapi import APIRouter

from clicksafe.api.v1.endpoints import analysis, health

api_router = APIRouter()
api_router.include_router(health.router, tags=["health"])
api_router.include_router(analysis.router, tags=["analysis"])

