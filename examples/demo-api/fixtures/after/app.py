"""Hardened FastAPI fixture that resolves every finding in the before project."""

import os
import secrets
import sqlite3
import time

import requests
from core import build_user_search
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status

app = FastAPI()
database = sqlite3.connect(":memory:", check_same_thread=False)


class RateLimiter:
    """Token-bucket limiter so authenticated routes cannot be brute-forced."""

    def __init__(self, capacity: int = 30, refill_per_minute: float = 30.0) -> None:
        self.capacity = capacity
        self.refill_rate = refill_per_minute / 60.0
        self._buckets: dict[str, tuple[float, float]] = {}

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        tokens, last_seen = self._buckets.get(key, (float(self.capacity), now))
        tokens = min(float(self.capacity), tokens + (now - last_seen) * self.refill_rate)
        allowed = tokens >= 1.0
        self._buckets[key] = (tokens - 1.0 if allowed else tokens, now)
        return allowed


rate_limiter = RateLimiter()


async def enforce_rate_limit(request: Request) -> None:
    client_key = request.client.host if request.client else "unknown-client"
    if not rate_limiter.allow(f"{client_key}:{request.url.path}"):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Rate limit exceeded")


def require_admin(authorization: str = Header()) -> None:
    expected_token = os.environ.get("DEMO_ADMIN_TOKEN")
    supplied_token = authorization.removeprefix("Bearer ")
    if not expected_token:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Admin token is not configured")
    if not secrets.compare_digest(supplied_token, expected_token):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Admin access required")


@app.get(
    "/admin/users",
    dependencies=[Depends(require_admin), Depends(enforce_rate_limit)],
)
def list_users(term: str = "", limit: int = Query(50, ge=1, le=100)):
    directory_response = requests.get(
        "https://directory.invalid/users",
        timeout=(1.0, 3.0),
    )
    query, parameters = build_user_search(term, limit)
    rows = database.execute(query, parameters).fetchall()
    return {"directory_status": directory_response.status_code, "users": rows}
