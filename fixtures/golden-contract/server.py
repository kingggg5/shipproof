"""Golden contract fixture: deterministic findings for compatibility tests."""

import os

import requests
from fastapi import FastAPI

app = FastAPI(debug=True)


@app.get("/health")
def health():
    return requests.get("https://dependency.invalid/health").json()


SECRET_KEY = os.getenv("SECRET_KEY", "unit-test-fallback-secret")
