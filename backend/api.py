from __future__ import annotations

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from backend.http_safety import RequestSafety

from backend.config import Settings, load_settings
from backend.routes import auth, documents, exports, ingestion, security


def create_app(settings: Settings | None = None) -> FastAPI:
    """Run with: uvicorn backend.api:create_app --factory"""
    app = FastAPI(title="Security Monitoring Lab API", version="0.1.0")
    app.add_middleware(RequestSafety)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request, error):
        return JSONResponse(status_code=422, content={"detail": "invalid request"})

    app.state.settings = settings or load_settings()
    app.include_router(auth.router)
    app.include_router(documents.router)
    app.include_router(ingestion.router)
    app.include_router(exports.router)
    app.include_router(security.router)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    return app
