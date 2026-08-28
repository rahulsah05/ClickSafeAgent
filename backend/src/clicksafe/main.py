from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from clicksafe.api.middleware import RequestBodyLimitMiddleware, RequestContextMiddleware
from clicksafe.api.rate_limiting import InMemorySlidingWindowRateLimiter
from clicksafe.api.v1.router import api_router
from clicksafe.core.config import get_settings
from clicksafe.core.logging import configure_logging
from clicksafe.infrastructure.database.session import dispose_db, init_db


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    await init_db()
    try:
        yield
    finally:
        await dispose_db()


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level)

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        docs_url="/docs" if settings.app_env != "production" else None,
        redoc_url="/redoc" if settings.app_env != "production" else None,
        lifespan=lifespan,
    )
    app.state.analysis_rate_limiter = InMemorySlidingWindowRateLimiter(
        max_requests=settings.analysis_rate_limit_requests,
        window_seconds=settings.analysis_rate_limit_window_seconds,
        enabled=settings.analysis_rate_limit_enabled,
    )

    app.add_middleware(RequestBodyLimitMiddleware, max_body_bytes=settings.max_request_body_bytes)
    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(api_router, prefix=settings.api_v1_prefix)
    return app


app = create_app()
