"""Local, read-only FastAPI app with a static SOC dashboard."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from backend.api import create_api_router

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_DIR = PROJECT_ROOT / "dashboard"


def create_app(database_path: str | Path | None = None) -> FastAPI:
    application = FastAPI(
        title="Adaptive SSH Honeypot SOC API",
        description="Read-only investigation API over stored honeypot events and analysis.",
        version="0.9.0",
    )
    application.include_router(create_api_router(database_path))
    application.mount("/assets", StaticFiles(directory=DASHBOARD_DIR), name="dashboard-assets")

    @application.get("/", include_in_schema=False)
    def dashboard_index():
        return FileResponse(DASHBOARD_DIR / "index.html")

    @application.get("/health", tags=["health"])
    def health():
        return {"status": "ok"}

    return application


app = create_app()
