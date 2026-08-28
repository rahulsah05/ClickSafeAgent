import asyncio
import math
import time
from collections import defaultdict, deque
from collections.abc import Callable
from dataclasses import dataclass, field

from fastapi import HTTPException, Request, status


@dataclass(slots=True)
class InMemorySlidingWindowRateLimiter:
    """Per-process sliding-window limiter for expensive analysis requests."""

    max_requests: int
    window_seconds: float
    enabled: bool = True
    clock: Callable[[], float] = time.monotonic
    _requests: dict[str, deque[float]] = field(default_factory=lambda: defaultdict(deque))
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def retry_after(self, key: str) -> int | None:
        if not self.enabled:
            return None

        now = self.clock()
        async with self._lock:
            requests = self._requests[key]
            cutoff = now - self.window_seconds
            while requests and requests[0] <= cutoff:
                requests.popleft()

            if len(requests) >= self.max_requests:
                return max(1, math.ceil(self.window_seconds - (now - requests[0])))

            requests.append(now)
            return None


def get_client_key(request: Request) -> str:
    return request.client.host if request.client is not None else "unknown"


async def enforce_analysis_rate_limit(request: Request) -> None:
    limiter = request.app.state.analysis_rate_limiter
    retry_after = await limiter.retry_after(get_client_key(request))
    if retry_after is None:
        return

    raise HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="Scan rate limit exceeded. Please try again later.",
        headers={"Retry-After": str(retry_after)},
    )
