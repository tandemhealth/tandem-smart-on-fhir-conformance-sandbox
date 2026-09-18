"""Minimal in-process fixed-window rate limiter.

The sandbox deliberately runs as a single replica (SQLite persistence), so an
in-memory limiter covers the whole deployment.
"""

import time

from fastapi import HTTPException, Request


class RateLimiter:
    def __init__(self, limit: int, window_seconds: float) -> None:
        self._limit = limit
        self._window = window_seconds
        self._windows: dict[str, tuple[float, int]] = {}

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        window_start, count = self._windows.get(key, (now, 0))
        if now - window_start >= self._window:
            window_start, count = now, 0
        if count >= self._limit:
            return False
        self._windows[key] = (window_start, count + 1)
        if len(self._windows) > 10_000:
            self._windows = {
                k: v for k, v in self._windows.items() if now - v[0] < self._window
            }
        return True

    def reset(self) -> None:
        self._windows.clear()


def client_ip(request: Request) -> str:
    # Behind the ingress the client address is the LB; the ingress controller
    # appends the real client to X-Forwarded-For. Spoofable in theory, but
    # only weakens rate limiting, which is best-effort abuse protection here.
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()[:64]
    return request.client.host if request.client else "unknown"


def enforce(limiter: RateLimiter, request: Request) -> None:
    if not limiter.allow(client_ip(request)):
        raise HTTPException(status_code=429, detail="Too many requests; slow down.")
