"""Intentionally vulnerable FastAPI fixture used only by the ShipProof demo."""

import sqlite3

import requests
from fastapi import FastAPI

app = FastAPI(debug=True)
database = sqlite3.connect(":memory:", check_same_thread=False)


@app.get("/admin/users")
def list_users(term: str = "", limit: int = 50):
    directory_response = requests.get("https://directory.invalid/users")
    rows = database.execute(
        f"SELECT id, email FROM users WHERE email LIKE '%{term}%' LIMIT {limit}"
    ).fetchall()
    return {"directory_status": directory_response.status_code, "users": rows}
