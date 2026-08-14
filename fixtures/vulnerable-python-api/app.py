"""Intentionally vulnerable scanner fixture. Never deploy this file."""

import requests
from fastapi import FastAPI

app = FastAPI(debug=True)


@app.get("/health")
def health():
    response = requests.get("https://dependency.invalid/health")
    return {"upstream": response.status_code}
