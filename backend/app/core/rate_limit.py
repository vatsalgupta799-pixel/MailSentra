"""In-memory sliding window rate limiter for security-sensitive endpoints."""

import time
from collections import defaultdict
from typing import Dict, List, Tuple
from fastapi import HTTPException, Request, status


class SlidingWindowRateLimiter:
    """Thread-safe sliding-window rate limiter per client IP address."""

    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, List[float]] = defaultdict(list)

    def is_allowed(self, client_ip: str) -> Tuple[bool, int]:
        now = time.monotonic()
        timestamps = self.requests[client_ip]

        # Prune expired timestamps
        cutoff = now - self.window_seconds
        valid_timestamps = [ts for ts in timestamps if ts > cutoff]
        self.requests[client_ip] = valid_timestamps

        if len(valid_timestamps) >= self.max_requests:
            retry_after = int(self.window_seconds - (now - valid_timestamps[0])) + 1
            return False, max(retry_after, 1)

        valid_timestamps.append(now)
        return True, 0

    def check_rate_limit(self, request: Request) -> None:
        client_ip = request.client.host if request.client else "unknown"
        allowed, retry_after = self.is_allowed(client_ip)
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many authentication attempts. Please slow down and try again later.",
                headers={"Retry-After": str(retry_after)},
            )

    def reset(self) -> None:
        """Resets tracked requests (primarily for test execution)."""
        self.requests.clear()


# Global limiter for login endpoint: 10 attempts per minute per IP
login_rate_limiter = SlidingWindowRateLimiter(max_requests=10, window_seconds=60)
