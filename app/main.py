from __future__ import annotations

from fastapi import FastAPI

from app.api.v1.rate_limit import router as rate_limit_router
from app.core.settings import settings


def create_app() -> FastAPI:
    app = FastAPI(title=settings.app_name)
    app.include_router(rate_limit_router, prefix="/v1")

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()

