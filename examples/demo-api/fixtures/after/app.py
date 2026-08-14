"""Hardened FastAPI fixture that resolves every finding in the before project."""

import os
import secrets
import sqlite3

import requests
from core import build_user_search
from fastapi import Depends, FastAPI, Header, HTTPException, Query, status

app = FastAPI()
database = sqlite3.connect(":memory:", check_same_thread=False)


def require_admin(authorization: str = Header()) -> None:
    expected_token = os.environ.get("DEMO_ADMIN_TOKEN")
    supplied_token = authorization.removeprefix("Bearer ")
    if not expected_token:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Admin token is not configured")
    if not secrets.compare_digest(supplied_token, expected_token):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Admin access required")


@app.get("/admin/users", dependencies=[Depends(require_admin)])
def list_users(term: str = "", limit: int = Query(50, ge=1, le=100)):
    directory_response = requests.get(
        "https://directory.invalid/users",
        timeout=(1.0, 3.0),
    )
    query, parameters = build_user_search(term, limit)
    rows = database.execute(query, parameters).fetchall()
    return {"directory_status": directory_response.status_code, "users": rows}
