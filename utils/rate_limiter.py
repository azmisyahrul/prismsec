"""Simple in-memory rate limiter for tool execution."""

import asyncio
import time
from collections import defaultdict
from typing import Optional


class RateLimiter:
    """Token bucket rate limiter.

    Prevents resource exhaustion by limiting how often tools can be called.

    Usage:
        limiter = RateLimiter(max_calls=5, period=60)
        async with limiter.acquire("nmap"):
            result = await run_nmap(...)
    """

    def __init__(self, max_calls: int = 10, period: float = 60.0):
        """
        Args:
            max_calls: Maximum calls allowed within the period.
            period: Time window in seconds.
        """
        self.max_calls = max_calls
        self.period = period
        self._calls: dict[str, list[float]] = defaultdict(list)
        self._locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    async def acquire(self, tool_name: str = "default") -> "RateLimitContext":
        """Acquire a rate limit slot for a tool.

        Returns a context manager that blocks until a slot is available.

        Raises:
            RateLimitExceeded: If too many calls are pending.
        """
        return RateLimitContext(self, tool_name)

    def _check_and_update(self, tool_name: str) -> bool:
        """Check if a call is allowed and update counters."""
        now = time.monotonic()
        window_start = now - self.period

        # Remove expired entries
        self._calls[tool_name] = [
            t for t in self._calls[tool_name] if t > window_start
        ]

        if len(self._calls[tool_name]) >= self.max_calls:
            return False

        self._calls[tool_name].append(now)
        return True

    def get_remaining(self, tool_name: str = "default") -> int:
        """Get remaining allowed calls for a tool."""
        now = time.monotonic()
        window_start = now - self.period
        active = sum(1 for t in self._calls[tool_name] if t > window_start)
        return max(0, self.max_calls - active)

    def get_wait_time(self, tool_name: str = "default") -> float:
        """Get seconds until the next call is allowed."""
        if self.get_remaining(tool_name) > 0:
            return 0.0
        if self._calls[tool_name]:
            oldest = min(self._calls[tool_name])
            return max(0.0, oldest + self.period - time.monotonic())
        return 0.0


class RateLimitContext:
    """Async context manager for rate limiting."""

    def __init__(self, limiter: RateLimiter, tool_name: str):
        self._limiter = limiter
        self._tool_name = tool_name

    async def __aenter__(self):
        # Wait if rate limited
        while True:
            async with self._limiter._locks[self._tool_name]:
                if self._limiter._check_and_update(self._tool_name):
                    return self
                wait_time = self._limiter.get_wait_time(self._tool_name)

            # Wait outside the lock
            if wait_time > 0:
                await asyncio.sleep(min(wait_time, 1.0))

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        return False


class RateLimitExceeded(Exception):
    """Raised when rate limit is exceeded."""
    pass
