import logging
import time
from uuid import uuid4

from fastapi import Request
from fastapi.responses import JSONResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from clicksafe.core.request_context import request_id_context

logger = logging.getLogger(__name__)


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request_id = uuid4().hex
        token = request_id_context.set(request_id)
        started_at = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            logger.exception(
                "http.request_failed",
                extra={
                    "event": "http.request_failed",
                    "http_method": request.method,
                    "http_path": request.url.path,
                },
            )
            raise
        finally:
            request_id_context.reset(token)

        duration_ms = round((time.perf_counter() - started_at) * 1_000, 2)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        logger.info(
            "http.request_completed",
            extra={
                "event": "http.request_completed",
                "http_method": request.method,
                "http_path": request.url.path,
                "http_status_code": response.status_code,
                "duration_ms": duration_ms,
                "request_id": request_id,
            },
        )
        return response


class RequestBodyLimitMiddleware:
    def __init__(self, app: ASGIApp, max_body_bytes: int) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        content_length = _get_content_length(scope)
        if content_length is not None and content_length > self.max_body_bytes:
            await self._send_too_large_response(scope, receive, send)
            return

        consumed_bytes = 0
        response_started = False

        async def limited_receive() -> Message:
            nonlocal consumed_bytes
            message = await receive()
            if message["type"] == "http.request":
                body = message.get("body", b"")
                if isinstance(body, bytes):
                    consumed_bytes += len(body)
                if consumed_bytes > self.max_body_bytes:
                    raise RequestBodyTooLargeError
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except RequestBodyTooLargeError:
            if not response_started:
                await self._send_too_large_response(scope, receive, send)

    async def _send_too_large_response(self, scope: Scope, receive: Receive, send: Send) -> None:
        response = JSONResponse(
            status_code=413,
            content={"detail": "Request body exceeds the configured size limit."},
        )
        await response(scope, receive, send)


class RequestBodyTooLargeError(Exception):
    pass


def _get_content_length(scope: Scope) -> int | None:
    for header_name, header_value in scope.get("headers", []):
        if header_name.lower() != b"content-length":
            continue
        try:
            return int(header_value)
        except ValueError:
            return None
    return None
