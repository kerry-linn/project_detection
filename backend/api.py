from __future__ import annotations

from fastapi import FastAPI

from backend.config import Settings, load_settings
from backend.routes import ingestion, security


def create_app(settings: Settings | None = None) -> FastAPI:
    """Run with: uvicorn backend.api:create_app --factory"""
    app = FastAPI(title="Security Monitoring Lab API", version="0.1.0")
    app.state.settings = settings or load_settings()
    app.include_router(ingestion.router)
    app.include_router(security.router)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    return app
