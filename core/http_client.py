"""HTTP client utilities with rate limiting and retry logic."""

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx

from core.config import get_settings
from core.logger import get_logger

logger = get_logger(__name__)


class RateLimiter:
    """Simple token bucket rate limiter."""

    def __init__(self, rate: float = 5.0):
        """Initialize rate limiter.

        Args:
            rate: Maximum requests per second
        """
        self.rate = rate
        self.tokens = rate
        self.last_update = asyncio.get_event_loop().time()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Acquire a token, waiting if necessary."""
        async with self._lock:
            now = asyncio.get_event_loop().time()
            elapsed = now - self.last_update
            self.tokens = min(self.rate, self.tokens + elapsed * self.rate)
            self.last_update = now

            if self.tokens < 1:
                wait_time = (1 - self.tokens) / self.rate
                await asyncio.sleep(wait_time)
                self.tokens = 0
            else:
                self.tokens -= 1


class HTTPClient:
    """Async HTTP client with rate limiting and common configurations."""

    def __init__(
        self,
        base_url: str | None = None,
        timeout: int | None = None,
        rate_limit: float | None = None,
        headers: dict[str, str] | None = None,
    ):
        settings = get_settings()
        self.timeout = timeout or settings.request_timeout
        self.rate_limiter = RateLimiter(rate_limit or settings.requests_per_second)

        default_headers = {
            "User-Agent": settings.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }
        if headers:
            default_headers.update(headers)

        self._client = httpx.AsyncClient(
            base_url=base_url or "",
            timeout=httpx.Timeout(self.timeout),
            headers=default_headers,
            follow_redirects=True,
        )

    async def get(
        self,
        url: str,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        """Perform rate-limited GET request."""
        await self.rate_limiter.acquire()
        return await self._client.get(url, params=params, headers=headers)

    async def post(
        self,
        url: str,
        data: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        """Perform rate-limited POST request."""
        await self.rate_limiter.acquire()
        return await self._client.post(url, data=data, json=json, headers=headers)

    async def head(
        self,
        url: str,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        """Perform rate-limited HEAD request."""
        await self.rate_limiter.acquire()
        return await self._client.head(url, headers=headers)

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()

    async def __aenter__(self) -> "HTTPClient":
        return self

    async def __aexit__(self, *args) -> None:
        await self.close()


@asynccontextmanager
async def create_client(
    base_url: str | None = None,
    **kwargs,
) -> AsyncIterator[HTTPClient]:
    """Create an HTTP client context manager."""
    client = HTTPClient(base_url=base_url, **kwargs)
    try:
        yield client
    finally:
        await client.close()
