"""
core/rate_limiter.py — In-Memory Sliding Window Rate Limiter

Enforces maximum request thresholds within a sliding time window.
Used to prevent brute-force attacks and abuse.
"""
import time
from collections import defaultdict
from typing import Dict, List, Tuple
from fastapi import Request, HTTPException, status


class SlidingWindowRateLimiter:
    """
    In-memory sliding window rate limiter.
    Tracks request timestamps per client IP and rejects requests
    exceeding `max_requests` within `window_seconds`.
    """

    def __init__(self, max_requests: int = 5, window_seconds: int = 60, name: str = "login"):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.name = name
        self._records: Dict[str, List[float]] = defaultdict(list)

    def _cleanup_old(self, key: str, now: float) -> None:
        threshold = now - self.window_seconds
        valid_ts = [ts for ts in self._records[key] if ts > threshold]
        if valid_ts:
            self._records[key] = valid_ts
        else:
            self._records.pop(key, None)

    def check(self, key: str) -> Tuple[bool, int, int]:
        """
        Check whether a request is allowed under the rate limit.

        Returns:
            (allowed: bool, retry_after_seconds: int, remaining_attempts: int)
        """
        now = time.time()
        self._cleanup_old(key, now)
        timestamps = self._records[key]

        if len(timestamps) >= self.max_requests:
            oldest = timestamps[0]
            retry_after = max(1, int(oldest + self.window_seconds - now))
            return False, retry_after, 0

        # Record this attempt
        timestamps.append(now)
        remaining = self.max_requests - len(timestamps)
        return True, 0, remaining

    def reset(self, key: str) -> None:
        """Clear rate limit record for a specific key (e.g. after successful login)."""
        self._records.pop(key, None)

    def get_client_ip(self, request: Request) -> str:
        """Extract the real client IP, respecting X-Forwarded-For if available."""
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        if request.client:
            return request.client.host
        return "unknown"

    async def __call__(self, request: Request):
        client_ip = self.get_client_ip(request)
        key = f"{self.name}:{client_ip}"
        allowed, retry_after, remaining = self.check(key)

        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=(
                    f"Rate limit exceeded: Maximum {self.max_requests} login attempts "
                    f"per {self.window_seconds // 60} minute allowed. "
                    f"Please try again after {retry_after} seconds."
                ),
                headers={"Retry-After": str(retry_after)},
            )


# Singleton instance for login rate limiting: 5 attempts per 60 seconds (1 minute)
login_rate_limiter = SlidingWindowRateLimiter(max_requests=5, window_seconds=60, name="login")
